# Multi-stage Dockerfile for suppline
# Stage 1: Build the web UI
FROM node:26-alpine3.24 AS ui

WORKDIR /ui
COPY ui/package.json ui/package-lock.json ./
RUN --mount=type=cache,target=/root/.npm \
    npm ci
COPY ui/ ./
RUN npm run build

# Stage 2: Build the Go binary with the UI embedded
FROM golang:1.27.4-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git ca-certificates

WORKDIR /build

# Copy go mod files first for better caching
COPY go.mod go.sum ./

# Download dependencies with cache mount
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

# Install swag for generating API documentation with cache mount
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go install github.com/swaggo/swag/cmd/swag@latest

# Copy source code
COPY cmd/ ./cmd/
COPY internal/ ./internal/
COPY ui/*.go ./ui/
COPY ui/notbuilt/ ./ui/notbuilt/
COPY --from=ui /ui/dist/ ./ui/dist/

# Generate Swagger documentation
RUN mkdir -p build/swagger && \
    swag init -g internal/api/api.go -o build/swagger --parseDependency --parseInternal

# Build a static binary (pure Go, no CGO)
ARG VERSION=dev
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=linux go build -tags embedui \
    -ldflags="-w -s -X github.com/daimoniac/suppline/internal/version.Version=${VERSION}" \
    -o suppline \
    ./cmd/suppline

# Create directories that will be needed in the runtime image
RUN mkdir -p /build/data /build/config

# Stage 3: Create minimal runtime image
FROM alpine:3.24.4

# Install runtime dependencies including trivy and cosign clients.
# cosign is pinned rather than installed from apk: its CLI contract changes between patch
# releases, and an unpinned upgrade silently breaks the attestation pipeline.
RUN apk add --no-cache ca-certificates git wget && \
    wget https://github.com/aquasecurity/trivy/releases/download/v0.76.2/trivy_0.76.2_Linux-64bit.tar.gz && \
    tar zxvf trivy_0.76.2_Linux-64bit.tar.gz trivy && \
    mv trivy /usr/local/bin/ && \
    rm trivy_0.76.2_Linux-64bit.tar.gz && \
    wget -O /usr/local/bin/cosign https://github.com/sigstore/cosign/releases/download/v3.1.4/cosign-linux-amd64 && \
    chmod 0755 /usr/local/bin/cosign

# Create non-root user
RUN addgroup -g 1000 suppline && \
    adduser -D -u 1000 -G suppline suppline

# Create directories for data and config
RUN mkdir -p /data /config && \
    chown -R suppline:suppline /data /config

WORKDIR /app

# Copy binary from builder
COPY --from=builder /build/suppline /app/suppline

# Switch to non-root user
USER suppline

# Expose ports (defaults; set in suppline.yml)
# 8080: web UI, API and Swagger (server.port)
# 9090: metrics and health (observability.port)
EXPOSE 8080 9090

# Runtime settings live in suppline.yml; only secrets come from the environment.
ENV SUPPLINE_CONFIG=/config/suppline.yml

# Relative paths (checkouts, caches) resolve inside the writable data directory.
WORKDIR /data

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:9090/health || exit 1

ENTRYPOINT ["/app/suppline"]
