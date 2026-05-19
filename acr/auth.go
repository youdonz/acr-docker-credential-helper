package acr

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/golang-jwt/jwt/v5"
)

const (
	// Azure Container Registry resource scope
	ACRScope = "https://containerregistry.azure.net/.default"

	// ACR token exchange endpoint path
	ACRTokenExchangePath = "/oauth2/exchange" // #nosec G101

	// Request timeout for token operations
	TokenRequestTimeout = 30 * time.Second
)

// AzureAuthenticator handles Azure and ACR authentication
type AzureAuthenticator struct {
	httpClient *http.Client
}

// NewAzureAuthenticator creates a new authenticator
func NewAzureAuthenticator() *AzureAuthenticator {
	return &AzureAuthenticator{
		httpClient: &http.Client{
			Timeout: TokenRequestTimeout,
		},
	}
}

// GetAzureAccessToken obtains an Azure access token using DefaultAzureCredential
func (a *AzureAuthenticator) GetAzureAccessToken() (string, error) {
	// Create credential using Azure Identity SDK
	// This will try: environment variables, managed identity, Azure CLI, etc.
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return "", fmt.Errorf("failed to create Azure credential: %w", err)
	}

	// Get access token for ACR scope
	ctx, cancel := context.WithTimeout(context.Background(), TokenRequestTimeout)
	defer cancel()

	token, err := cred.GetToken(ctx, policy.TokenRequestOptions{
		Scopes: []string{ACRScope},
	})
	if err != nil {
		return "", fmt.Errorf("failed to get Azure access token: %w", err)
	}

	return token.Token, nil
}

// ExtractTenantIDFromToken extracts the tenant ID from an Azure access token JWT
// Returns the tenant ID from the 'tid' claim, or an error if not found
func (a *AzureAuthenticator) ExtractTenantIDFromToken(azureToken string) (string, error) {
	claims := jwt.MapClaims{}
	_, _, err := jwt.NewParser().ParseUnverified(azureToken, claims)
	if err != nil {
		return "", fmt.Errorf("failed to parse JWT: %w", err)
	}

	tidClaim, ok := claims["tid"]
	if !ok {
		return "", fmt.Errorf("tid claim not found in token")
	}

	tenantID, ok := tidClaim.(string)
	if !ok {
		return "", fmt.Errorf("tid claim is not a string")
	}

	if tenantID == "" {
		return "", fmt.Errorf("tid claim is empty")
	}

	return tenantID, nil
}

// ACRTokenResponse represents the JSON response from ACR token exchange
type ACRTokenResponse struct {
	RefreshToken string `json:"refresh_token"`
}

// ExchangeForACRToken exchanges an Azure token for an ACR refresh token
func (a *AzureAuthenticator) ExchangeForACRToken(
	registryHost string,
	tenantID string,
	azureToken string,
) (string, error) {
	// Construct the token exchange URL
	exchangeURL := fmt.Sprintf("https://%s%s", registryHost, ACRTokenExchangePath)

	// Prepare form data
	formData := url.Values{
		"grant_type":   []string{"access_token"},
		"service":      []string{registryHost},
		"tenant":       []string{tenantID},
		"access_token": []string{azureToken},
	}

	// Create HTTP request
	ctx, cancel := context.WithTimeout(context.Background(), TokenRequestTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(
		ctx,
		"POST",
		exchangeURL,
		strings.NewReader(formData.Encode()),
	)
	if err != nil {
		return "", fmt.Errorf("failed to create token exchange request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Execute request
	resp, err := a.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("token exchange request failed: %w", err)
	}

	defer func() { _ = resp.Body.Close() }()

	// Check response status
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf(
			"ACR token exchange failed with status %d: %s",
			resp.StatusCode,
			string(body),
		)
	}

	// Parse response
	var tokenResp ACRTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return "", fmt.Errorf("failed to parse ACR token response: %w", err)
	}

	if tokenResp.RefreshToken == "" {
		return "", fmt.Errorf("ACR token exchange returned empty refresh_token")
	}

	return tokenResp.RefreshToken, nil
}
