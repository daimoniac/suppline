# suppline

A cloud-native supply chain security solution for Kubernetes container images. Continuously monitors a private Docker registry, scans images for vulnerabilities using Trivy, generates SBOMs, creates attestations using Sigstore, and signs images that meet security policies.

## Features

- **Continuous Image Discovery**: Automatically discovers new and updated container images in your private registry
- **Vulnerability Scanning**: Scans images using Trivy to identify security vulnerabilities
- **SBOM Generation**: Creates Software Bill of Materials in CycloneDX format
- **Attestation & Signing**: Uses Sigstore to attest and sign secure images
- **Policy Engine**: Evaluates images against security policies with CVE toleration support
- **State Tracking**: Maintains scan history and vulnerability records
- **HTTP API**: Query scan results and trigger operations via REST API
- **Observability**: Prometheus metrics, health checks, and structured logging

## Architecture

suppline is implemented as a single Go binary with the following components:

- **Registry Watcher**: Continuously monitors the container registry for new images
- **Task Queue**: In-memory queue for managing scanning tasks
- **Worker**: Processes images through scanning, attestation, and signing workflows
- **State Store**: Persistent storage for scan results and vulnerability data
- **Policy Engine**: Evaluates security policies with CVE toleration support
- **HTTP API**: REST API for querying and triggering operations

## Configuration

Configuration is loaded from environment variables. All settings have sensible defaults for quick start.

### Complete Environment Variables Reference

#### Regsync Configuration
```bash
# Path to regsync.yml configuration file
REGSYNC_PATH=regsync.yml                    # Default: regsync.yml
```

#### Task Queue Configuration
```bash
# In-memory queue buffer size
QUEUE_BUFFER_SIZE=1000                      # Default: 1000
```

#### Worker Configuration
```bash
# How often the worker polls for new tasks
WORKER_POLL_INTERVAL=5s                     # Default: 5s

# Maximum retry attempts for transient failures
WORKER_RETRY_ATTEMPTS=3                     # Default: 3

# Initial backoff duration for retries (exponential)
WORKER_RETRY_BACKOFF=10s                    # Default: 10s
```

#### Trivy Scanner Configuration
```bash
# Trivy server address (host:port)
TRIVY_SERVER_ADDR=localhost:4954            # Default: localhost:4954

# Optional authentication token for Trivy server
TRIVY_TOKEN=                                # Default: empty

# Timeout for Trivy scan operations
TRIVY_TIMEOUT=5m                            # Default: 5m

# Skip TLS verification (not recommended for production)
TRIVY_INSECURE=false                        # Default: false
```

#### Attestation Configuration (Key-Based Mode)
```bash
# Path to Cosign private key for signing
ATTESTATION_KEY_PATH=/path/to/cosign.key    # Required if not using keyless

# Password for encrypted private key
ATTESTATION_KEY_PASSWORD=secret             # Default: empty

# Rekor transparency log URL
REKOR_URL=https://rekor.sigstore.dev        # Default: https://rekor.sigstore.dev

# Fulcio certificate authority URL
FULCIO_URL=https://fulcio.sigstore.dev      # Default: https://fulcio.sigstore.dev
```

#### Attestation Configuration (Keyless Mode)
```bash
# Enable keyless signing with OIDC
ATTESTATION_USE_KEYLESS=true                # Default: false

# OIDC issuer URL (e.g., https://accounts.google.com)
OIDC_ISSUER=https://accounts.google.com     # Required if keyless

# OIDC client ID
OIDC_CLIENT_ID=your-client-id               # Required if keyless
```

#### State Store Configuration
```bash
# State store type: sqlite, postgres, or memory
STATE_STORE_TYPE=sqlite                     # Default: sqlite

# PostgreSQL connection URL (if using postgres)
POSTGRES_URL=postgresql://user:pass@host/db # Required if type=postgres

# SQLite database file path (if using sqlite)
SQLITE_PATH=suppline.db          # Default: suppline.db

# How often to rescan existing images
RESCAN_INTERVAL=24h                         # Default: 24h
```

#### HTTP API Configuration
```bash
# Enable HTTP API server
API_ENABLED=true                            # Default: true

# API server port
API_PORT=8080                               # Default: 8080

# Optional API key for authentication
API_KEY=your-secret-api-key                 # Default: empty (no auth)

# Disable write operations (POST endpoints)
API_READ_ONLY=false                         # Default: false
```

#### Observability Configuration
```bash
# Log level: debug, info, warn, error
LOG_LEVEL=info                              # Default: info

# Prometheus metrics port
METRICS_PORT=9090                           # Default: 9090

# Health check endpoint port
HEALTH_CHECK_PORT=8081                      # Default: 8081
```

### Minimal Configuration Example

For a quick start, you only need to set:

```bash
# Required
REGSYNC_PATH=regsync.yml
ATTESTATION_KEY_PATH=/path/to/cosign.key

# Optional but recommended
LOG_LEVEL=info
API_KEY=your-secret-key
```

All other settings use sensible defaults.

**For complete configuration reference, see [docs/CONFIGURATION.md](docs/CONFIGURATION.md)**

## Regsync Configuration

suppline reads the `regsync.yml` configuration file to determine which repositories to monitor and which CVEs to tolerate. See `regsync.yml.example` for a complete example.

### CVE Toleration Format

You can tolerate specific CVEs using the `x-tolerate` extension in your sync entries:

```yaml
sync:
  - source: nginx
    target: hostingmaloonde/nginx
    type: repository
    x-tolerate:
      # Temporary toleration with expiry date
      - id: CVE-2024-56171
        statement: initial toleration when introducing supplychain
        expires_at: 2025-12-31T23:59:59Z
      
      # Permanent toleration (no expiry)
      - id: CVE-2025-0838
        statement: no fix available, accepted risk
```

**Toleration Fields:**
- `id` (required): CVE identifier (e.g., CVE-2024-56171)
- `statement` (required): Reason for toleration (for audit purposes)
- `expires_at` (optional): RFC3339 timestamp when toleration expires

**Behavior:**
- Tolerated CVEs are excluded from critical vulnerability count during policy evaluation
- Expired tolerations are treated as if they don't exist (CVE counts as critical)
- System logs warnings for tolerations expiring within 7 days
- Tolerations without `expires_at` are permanent

**For complete regsync.yml format documentation, see [deploy/DEPLOYMENT.md](deploy/DEPLOYMENT.md#regsync-configuration-format)**

## Quick Start

### Docker Compose (Recommended for Local Development)

```bash
# 1. Create your regsync.yml configuration
cp regsync.yml.example regsync.yml
# Edit regsync.yml with your registry credentials and sync entries

# 2. Generate signing keys (optional, for key-based signing)
mkdir -p keys
cosign generate-key-pair
mv cosign.key keys/

# 3. Start services
docker compose up -d

# 4. Check status
docker compose ps
docker compose logs -f
```

### Kubernetes (Production)

```bash
# 1. Update configuration
# Edit deploy/kubernetes/secret.yaml with your regsync.yml

# 2. Generate signing keys
cosign generate-key-pair
kubectl create secret generic suppline-signing-key \
  --namespace=suppline \
  --from-file=cosign.key=cosign.key

# 3. Deploy
kubectl apply -k deploy/kubernetes/

# 4. Check status
kubectl get pods -n suppline
kubectl logs -n suppline -l app=suppline -f
```

See [deploy/DEPLOYMENT.md](deploy/DEPLOYMENT.md) for comprehensive deployment guide.

## Building

### From Source

```bash
# Build binary
make build

# Or manually
go build -o suppline ./cmd/suppline
```

### Docker Images

```bash
# Build main application image
make docker-build

# Build Trivy server image (optional)
make docker-build-trivy

# Or manually
docker build -t suppline:latest -f Dockerfile .
docker build -t trivy-server:latest -f Dockerfile.trivy .
```

## Running Locally

### Option 1: Docker Compose (Recommended)

```bash
docker compose up -d
```

### Option 2: Manual

1. Start Trivy server:
```bash
trivy server --listen localhost:4954
```

2. Create your `regsync.yml` configuration file

3. Run suppline:
```bash
./suppline
```

## API Endpoints

suppline provides a comprehensive REST API for querying scan results and triggering operations.

### Query Endpoints

- `GET /api/v1/scans/{digest}` - Get scan record with vulnerabilities
- `GET /api/v1/scans` - List scans with filters
- `GET /api/v1/vulnerabilities` - Search vulnerabilities across all images
- `GET /api/v1/tolerations` - List tolerated CVEs with expiry information
- `GET /api/v1/images/failed` - List policy-failed images

### Action Endpoints

- `POST /api/v1/scans/trigger` - Trigger rescan of specific digest or repository
- `POST /api/v1/policy/reevaluate` - Reload config and re-evaluate policy

### Observability

- `GET /health` - Health check endpoint with component status
- `GET /metrics` - Prometheus metrics

**For complete API documentation with examples, see [docs/API.md](docs/API.md)**

## Monitoring

### Prometheus Metrics

```bash
# Port forward to access metrics
kubectl port-forward -n suppline svc/suppline 9090:9090
curl http://localhost:9090/metrics
```

Key metrics:
- `suppline_scans_total` - Total scans
- `suppline_policy_passed_total` - Images passing policy
- `suppline_queue_depth` - Current queue depth
- `suppline_vulnerabilities_total` - Total vulnerabilities

### Health Checks

```bash
curl http://localhost:8081/health
```

Returns status of all components: config, queue, worker, trivy, database, watcher.

## Development

### Prerequisites

- Go 1.25.4+
- Docker and Docker Compose
- kubectl (for Kubernetes deployment)
- cosign (for signing key generation)

### Setup

```bash
# Install dependencies
make deps

# Set up development environment
make dev-setup

# Run tests
make test

# Run integration tests
make test-integration

# Run linters
make lint
```

### Project Structure

```
.
├── cmd/
│   └── suppline/    # Main application entry point
├── internal/
│   ├── api/                    # HTTP API server
│   ├── attestation/            # Sigstore attestation
│   ├── config/                 # Configuration loading
│   ├── observability/          # Metrics, logging, health
│   ├── policy/                 # Policy engine
│   ├── queue/                  # Task queue
│   ├── registry/               # Registry client
│   ├── regsync/                # Regsync parser
│   ├── scanner/                # Trivy scanner
│   ├── statestore/             # State persistence
│   ├── watcher/                # Registry watcher
│   └── worker/                 # Worker processing
├── deploy/
│   ├── kubernetes/             # Kubernetes manifests
│   └── DEPLOYMENT.md           # Deployment guide
├── test/
│   └── integration/            # Integration tests
├── Dockerfile                  # Main application image
├── Dockerfile.trivy            # Trivy server image
├── docker-compose.yml          # Local development
├── Makefile                    # Build automation
├── go.mod
└── README.md
```

### Make Targets

```bash
make help                 # Show all available targets
make build                # Build binary
make test                 # Run tests
make docker-build         # Build Docker images
make docker-run           # Run with Docker Compose
make k8s-deploy           # Deploy to Kubernetes
make k8s-logs             # View Kubernetes logs
```

## Documentation

### Core Documentation

- **[README.md](README.md)** - This file: Overview, quick start, and basic configuration
- **[QUICKSTART.md](QUICKSTART.md)** - Step-by-step quick start guide for local and production deployments
- **[deploy/DEPLOYMENT.md](deploy/DEPLOYMENT.md)** - Comprehensive deployment guide with troubleshooting

### API and Configuration

- **[docs/API.md](docs/API.md)** - Complete API reference with examples
- **[docs/CONFIGURATION.md](docs/CONFIGURATION.md)** - Complete configuration reference for all environment variables
- **[regsync.yml.example](regsync.yml.example)** - Example regsync configuration with CVE tolerations

### Operations

- **[docs/STATE_STORE_REBUILD.md](docs/STATE_STORE_REBUILD.md)** - State store rebuild and recovery procedures
- **[deploy/README.md](deploy/README.md)** - Deployment configurations overview

### Additional Resources

- **[Makefile](Makefile)** - Build and deployment automation targets
- **[deploy/kubernetes/](deploy/kubernetes/)** - Kubernetes manifests and kustomization
- **[internal/observability/README.md](internal/observability/README.md)** - Observability implementation details

## License

See LICENSE file for details.
