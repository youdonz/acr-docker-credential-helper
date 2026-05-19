package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

var binaryPath string

func TestMain(m *testing.M) {
	tmpDir, err := os.MkdirTemp("", "credential-helper-test")
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create temp dir: %v\n", err)
		os.Exit(1)
	}

	binaryPath = filepath.Join(tmpDir, "docker-credential-acr")
	cmd := exec.Command("go", "build", "-o", binaryPath, ".")
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "failed to build binary: %v\n", err)
		_ = os.RemoveAll(tmpDir)
		os.Exit(1)
	}

	exitCode := m.Run()
	_ = os.RemoveAll(tmpDir)
	os.Exit(exitCode)
}

// runHelper invokes the binary with the given action and stdin, returning stdout, stderr, and exit code.
func runHelper(t *testing.T, action string, stdin string) (stdout, stderr string, exitCode int) {
	t.Helper()

	var args []string
	if action != "" {
		args = append(args, action)
	}

	cmd := exec.Command(binaryPath, args...)
	cmd.Stdin = strings.NewReader(stdin)
	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf

	err := cmd.Run()
	exitCode = 0
	if exitErr, ok := err.(*exec.ExitError); ok {
		exitCode = exitErr.ExitCode()
	} else if err != nil {
		t.Fatalf("failed to run binary: %v", err)
	}

	return outBuf.String(), errBuf.String(), exitCode
}

func TestBinary_NoArgs(t *testing.T) {
	cmd := exec.Command(binaryPath)
	var outBuf bytes.Buffer
	cmd.Stdout = &outBuf

	err := cmd.Run()
	if err == nil {
		t.Fatal("expected non-zero exit code when no args provided")
	}

	exitErr, ok := err.(*exec.ExitError)
	if !ok {
		t.Fatalf("unexpected error type: %v", err)
	}
	if exitErr.ExitCode() != 1 {
		t.Errorf("expected exit code 1, got %d", exitErr.ExitCode())
	}
	if !strings.Contains(outBuf.String(), "Usage:") {
		t.Errorf("expected usage message on stdout, got: %s", outBuf.String())
	}
}

func TestBinary_InvalidAction(t *testing.T) {
	stdout, _, exitCode := runHelper(t, "foobar", "")
	if exitCode != 1 {
		t.Errorf("expected exit code 1, got %d", exitCode)
	}
	if !strings.Contains(stdout, "unknown action") {
		t.Errorf("expected 'unknown action' in stdout, got: %s", stdout)
	}
}

func TestBinary_List_ReturnsValidJSON(t *testing.T) {
	stdout, _, exitCode := runHelper(t, "list", "")
	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d; stdout: %s", exitCode, stdout)
	}

	var result map[string]string
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		t.Fatalf("stdout is not valid JSON map: %v\nstdout was: %s", err, stdout)
	}
	if len(result) != 0 {
		t.Errorf("expected empty map, got: %v", result)
	}
}

func TestBinary_Store_ExitsNonZero(t *testing.T) {
	input := `{"ServerURL":"myregistry.azurecr.io","Username":"user","Secret":"pass"}`
	stdout, _, exitCode := runHelper(t, "store", input)
	if exitCode != 1 {
		t.Errorf("expected exit code 1, got %d", exitCode)
	}
	if !strings.Contains(stdout, "not implemented") {
		t.Errorf("expected 'not implemented' in stdout, got: %s", stdout)
	}
}

func TestBinary_Erase_ExitsNonZero(t *testing.T) {
	stdout, _, exitCode := runHelper(t, "erase", "myregistry.azurecr.io")
	if exitCode != 1 {
		t.Errorf("expected exit code 1, got %d", exitCode)
	}
	if !strings.Contains(stdout, "not implemented") {
		t.Errorf("expected 'not implemented' in stdout, got: %s", stdout)
	}
}

func TestBinary_Get_NonACR_ExitsNonZero(t *testing.T) {
	stdout, _, exitCode := runHelper(t, "get", "registry-1.docker.io")
	if exitCode != 1 {
		t.Errorf("expected exit code 1, got %d", exitCode)
	}
	if !strings.Contains(stdout, "not an ACR registry") {
		t.Errorf("expected 'not an ACR registry' in stdout, got: %s", stdout)
	}
}

func TestBinary_Get_ValidACR_NoCredentials(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping: requires Azure credentials (slow DefaultAzureCredential timeout in CI)")
	}

	// Clear Azure credential env vars to ensure auth fails
	t.Setenv("AZURE_CLIENT_ID", "")
	t.Setenv("AZURE_CLIENT_SECRET", "")
	t.Setenv("AZURE_TENANT_ID", "")
	t.Setenv("AZURE_AUTHORITY_HOST", "")

	stdout, _, exitCode := runHelper(t, "get", "myregistry.azurecr.io")
	if exitCode != 1 {
		t.Errorf("expected exit code 1, got %d", exitCode)
	}
	if stdout == "" {
		t.Error("expected error message on stdout, got empty string")
	}
}

func TestBinary_ErrorsOnStdout(t *testing.T) {
	_, stderr, exitCode := runHelper(t, "get", "example.com")
	if exitCode != 1 {
		t.Errorf("expected exit code 1, got %d", exitCode)
	}
	if stderr != "" {
		t.Errorf("expected stderr to be empty (protocol requires errors on stdout), got: %s", stderr)
	}
}

func TestBinary_Version(t *testing.T) {
	stdout, _, exitCode := runHelper(t, "version", "")
	if exitCode != 0 {
		t.Errorf("expected exit code 0, got %d", exitCode)
	}
	if stdout == "" {
		t.Error("expected version output, got empty string")
	}
}

func TestBinary_Get_URLVariants(t *testing.T) {
	tests := []struct {
		name             string
		input            string
		expectAnyOf      []string // stdout must contain at least one of these
		expectRegistryOK bool     // true = URL passes registry validation (fails at auth/exchange)
	}{
		{
			name:             "bare hostname",
			input:            "myregistry.azurecr.io",
			expectRegistryOK: true,
		},
		{
			name:             "with https prefix",
			input:            "https://myregistry.azurecr.io",
			expectRegistryOK: true,
		},
		{
			name:             "with trailing slash",
			input:            "https://myregistry.azurecr.io/",
			expectRegistryOK: true,
		},
		{
			name:             "with http prefix",
			input:            "http://myregistry.azurecr.io",
			expectRegistryOK: true,
		},
		{
			name:        "non-ACR registry",
			input:       "gcr.io",
			expectAnyOf: []string{"not an ACR registry"},
		},
		{
			name:        "short registry name",
			input:       "ab.azurecr.io",
			expectAnyOf: []string{"invalid ACR registry name"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if testing.Short() && tt.expectRegistryOK {
				t.Skip("skipping: requires Azure credentials (slow DefaultAzureCredential timeout in CI)")
			}

			stdout, _, exitCode := runHelper(t, "get", tt.input)
			if exitCode != 1 {
				t.Errorf("expected exit code 1 (no real ACR credentials), got %d", exitCode)
			}

			if tt.expectRegistryOK {
				// URL is a valid ACR format, so it should fail at auth or exchange, not registry validation
				if strings.Contains(stdout, "not an ACR registry") || strings.Contains(stdout, "invalid ACR registry name") {
					t.Errorf("expected URL to pass registry validation, but got: %s", stdout)
				}
			}

			if len(tt.expectAnyOf) > 0 {
				found := false
				for _, substr := range tt.expectAnyOf {
					if strings.Contains(stdout, substr) {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("expected stdout to contain one of %v, got: %s", tt.expectAnyOf, stdout)
				}
			}
		})
	}
}
