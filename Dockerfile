# Stage 1: Build
FROM docker.io/library/golang:1.26-alpine AS builder

RUN apk add --no-cache upx

WORKDIR /build

COPY go.mod go.sum ./
RUN go mod download && go mod verify

COPY . .

RUN CGO_ENABLED=0 go build \
    -ldflags="-s -w" \
    -trimpath \
    -o docker-credential-acr \
    . \
    && upx --best --lzma docker-credential-acr

# Stage 2: Runtime
FROM scratch

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /build/docker-credential-acr /docker-credential-acr

USER 65534:65534

ENTRYPOINT ["/docker-credential-acr"]
