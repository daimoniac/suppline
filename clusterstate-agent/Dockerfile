# ---- Builder ----
FROM golang:1.24-alpine AS builder

WORKDIR /build

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build \
    -trimpath \
    -ldflags="-s -w" \
    -o /clusterstate-agent \
    .

# ---- Runtime ----
FROM alpine:3.21

# ca-certificates required for TLS connections to the suppline webhook
RUN apk add --no-cache ca-certificates

COPY --from=builder /clusterstate-agent /usr/local/bin/clusterstate-agent

# Run as non-root (nobody)
USER 65534:65534

ENTRYPOINT ["/usr/local/bin/clusterstate-agent"]
