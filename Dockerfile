# Multi-stage Dockerfile for daimoniac/suppline
# Stage 1: Build the Go binary
FROM golang:1.25.4-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git ca-certificates gcc musl-dev sqlite-dev

WORKDIR /build

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Install swag for generating API documentation
RUN go install github.com/swaggo/swag/cmd/swag@latest

# Copy source code
COPY . .

# Generate Swagger documentation
RUN mkdir -p build/swagger && \
    swag init -g internal/api/api.go -o build/swagger --parseDependency --parseInternal

# Build the binary with CGO enabled for SQLite
RUN CGO_ENABLED=1 GOOS=linux go build -a -installsuffix cgo \
    -ldflags="-w -s" \
    -o daimoniac/suppline \
    ./cmd/daimoniac/suppline

# Stage 2: Create minimal runtime image
FROM alpine:3.21

# Install runtime dependencies including trivy client
RUN apk add --no-cache ca-certificates sqlite-libs wget cosign && \
    wget https://github.com/aquasecurity/trivy/releases/download/v0.58.1/trivy_0.58.1_Linux-64bit.tar.gz && \
    tar zxvf trivy_0.58.1_Linux-64bit.tar.gz && \
    mv trivy /usr/local/bin/ && \
    rm trivy_0.58.1_Linux-64bit.tar.gz

# Create non-root user
RUN addgroup -g 1000 daimoniac/suppline && \
    adduser -D -u 1000 -G daimoniac/suppline daimoniac/suppline

# Create directories for data and config
RUN mkdir -p /data /config && \
    chown -R daimoniac/suppline:daimoniac/suppline /data /config

WORKDIR /app

# Copy binary from builder
COPY --from=builder /build/daimoniac/suppline /app/daimoniac/suppline

# Switch to non-root user
USER daimoniac/suppline

# Expose ports
# 8080: API server
# 9090: Metrics
# 8081: Health checks
EXPOSE 8080 9090 8081

# Set default environment variables
ENV SUPPLINE_CONFIG=/config/daimoniac/suppline.yml \
    SQLITE_PATH=/data/daimoniac/suppline.db \
    LOG_LEVEL=info \
    METRICS_PORT=9090 \
    HEALTH_PORT=8081 \
    API_PORT=8080 \
    API_ENABLED=true

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:8081/health || exit 1

ENTRYPOINT ["/app/daimoniac/suppline"]
