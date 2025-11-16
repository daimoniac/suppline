# Configuration Reference

Complete reference for all configuration options in suppline.

## Table of Contents

- [Configuration Sources](#configuration-sources)
- [Environment Variables](#environment-variables)
- [Regsync Configuration](#regsync-configuration)
- [Examples](#examples)

## Configuration Sources

Configuration is loaded from multiple sources in this priority order:

1. **Default values** - Built-in defaults in the application
2. **Regsync file** - Registry and toleration configuration from `suppline.yml`
3. **Environment variables** - Runtime configuration overrides

## Environment Variables

### Core Configuration

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `SUPPLINE_CONFIG` | string | `suppline.yml` | Path to regsync configuration file |
| `LOG_LEVEL` | string | `info` | Log level: `debug`, `info`, `warn`, `error` |

### Queue & Worker

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `QUEUE_BUFFER_SIZE` | int | `1000` | In-memory queue buffer size (number of tasks) |
| `WORKER_POLL_INTERVAL` | duration | `5s` | How often worker polls for new tasks |
| `WORKER_RETRY_ATTEMPTS` | int | `3` | Maximum retry attempts for transient failures |
| `WORKER_RETRY_BACKOFF` | duration | `10s` | Initial backoff duration for retries (exponential) |

### Scanner (Trivy)

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `TRIVY_SERVER_ADDR` | string | `localhost:4954` | Trivy server address (host:port) |
| `TRIVY_TOKEN` | string | `` | Optional authentication token for Trivy server |
| `TRIVY_TIMEOUT` | duration | `5m` | Timeout for Trivy scan operations |
| `TRIVY_INSECURE` | bool | `false` | Skip TLS verification (not recommended for production) |

### State Store

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `STATE_STORE_TYPE` | string | `sqlite` | State store type: `sqlite`, `postgres`, or `memory` |
| `SQLITE_PATH` | string | `suppline.db` | SQLite database file path |
| `POSTGRES_URL` | string | `` | PostgreSQL connection URL (if type=postgres) |
| `RESCAN_INTERVAL` | duration | `24h` | Default rescan interval for unchanged images |

### Attestation & Signing

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `ATTESTATION_KEY_PATH` | string | `` | Path to Cosign private key (required if not keyless) |
| `ATTESTATION_KEY_PASSWORD` | string | `` | Password for encrypted private key |
| `REKOR_URL` | string | `https://rekor.sigstore.dev` | Rekor transparency log URL |
| `FULCIO_URL` | string | `https://fulcio.sigstore.dev` | Fulcio certificate authority URL |

### API Server

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `API_ENABLED` | bool | `true` | Enable HTTP API server |
| `API_PORT` | int | `8080` | API server port |
| `API_KEY` | string | `` | Optional API key for authentication |
| `API_READ_ONLY` | bool | `false` | Disable write operations (POST endpoints) |

### Observability

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `METRICS_PORT` | int | `9090` | Prometheus metrics port |
| `HEALTH_CHECK_PORT` | int | `8081` | Health check endpoint port |

## Regsync Configuration

The `suppline.yml` file defines registry credentials, sync entries, and CVE tolerations.

### File Structure

```yaml
version: 1

# Registry credentials
creds:
  - registry: string          # Registry hostname
    user: string              # Username or token name
    pass: string              # Password or token value
    repoAuth: bool            # Use repository-scoped authentication
    reqPerSec: int            # Rate limit (requests per second)
    reqConcurrent: int        # Concurrent request limit

# Default settings
defaults:
  parallel: int               # Parallel sync operations
  x-rescanInterval: string    # Default rescan interval (e.g., "7d", "24h")
  x-policy:                   # Default policy
    expression: string        # CEL expression
    failureMessage: string    # Custom failure message

# Sync entries
sync:
  - source: string            # Source repository
    target: string            # Target repository
    type: string              # Type: "image" or "repository"
    schedule: string          # Cron schedule (optional)
    x-rescanInterval: string  # Rescan interval override (optional)
    x-policy:                 # Policy override (optional)
      expression: string
      failureMessage: string
    x-tolerate:               # CVE tolerations (optional)
      - id: string            # CVE identifier
        statement: string     # Reason for toleration
        expires_at: string    # RFC3339 timestamp (optional)
```

### Credentials Section

```yaml
creds:
  # Docker Hub with personal access token
  - registry: docker.io
    user: myusername
    pass: dckr_pat_xxxxxxxxxxxxx
    repoAuth: true
    reqPerSec: 100
    reqConcurrent: 5
  
  # Private registry with basic auth
  - registry: registry.example.com
    user: admin
    pass: secretpassword
    repoAuth: false
```

### Sync Entries

```yaml
sync:
  # Sync entire repository
  - source: nginx
    target: myregistry.example.com/nginx
    type: repository
  
  # Sync with tag filters
  - source: alpine
    target: myregistry.example.com/alpine
    type: repository
    tags:
      semverRange:
        - ">=3.18.0"
      deny:
        - "latest"
```

### Rescan Interval Configuration

The `x-rescanInterval` field controls how often images are rescanned even if their digest hasn't changed.

**Interval Notation:**
- `m` - minutes (e.g., `30m`, `90m`)
- `h` - hours (e.g., `2h`, `12h`, `24h`)
- `d` - days (e.g., `1d`, `3d`, `7d`)

**Configuration Levels:**

1. **Sync Entry Level** - Highest priority, applies to specific repository
2. **Defaults Level** - Applies to all sync entries without explicit interval
3. **Hardcoded Default** - Falls back to `7d` if not configured

**Examples:**

```yaml
defaults:
  x-rescanInterval: 7d        # Default: rescan every 7 days

sync:
  # Uses default interval (7d)
  - source: nginx
    target: myregistry.example.com/nginx
    type: repository
  
  # Override with shorter interval for critical images
  - source: postgres
    target: myregistry.example.com/postgres
    type: repository
    x-rescanInterval: 3d      # Rescan every 3 days
  
  # Short interval for development images
  - source: myapp-dev
    target: myregistry.example.com/myapp-dev
    type: repository
    x-rescanInterval: 12h     # Rescan every 12 hours
```

### Policy Configuration

Policies use CEL (Common Expression Language) to evaluate security posture.

**Available Variables:**
- `criticalCount` - Number of critical vulnerabilities (excluding tolerated)
- `highCount` - Number of high vulnerabilities (excluding tolerated)
- `mediumCount` - Number of medium vulnerabilities (excluding tolerated)
- `lowCount` - Number of low vulnerabilities (excluding tolerated)
- `toleratedCount` - Number of tolerated vulnerabilities
- `vulnerabilities` - List of all vulnerabilities with details
- `imageRef` - Image reference being evaluated

**Examples:**

```yaml
defaults:
  x-policy:
    expression: "criticalCount == 0"
    failureMessage: "critical vulnerabilities found"

sync:
  # Strict policy for production
  - source: myapp-prod
    target: myregistry.example.com/myapp-prod
    type: repository
    x-policy:
      expression: "criticalCount == 0 && highCount == 0"
      failureMessage: "critical or high vulnerabilities found"
  
  # Lenient policy for development
  - source: myapp-dev
    target: myregistry.example.com/myapp-dev
    type: repository
    x-policy:
      expression: "criticalCount <= 5"
      failureMessage: "too many critical vulnerabilities"
```

### CVE Tolerations

```yaml
sync:
  - source: nginx
    target: myregistry.example.com/nginx
    type: repository
    x-tolerate:
      # Temporary toleration with expiry
      - id: CVE-2024-56171
        statement: "Initial toleration when introducing supplychain"
        expires_at: 2025-12-31T23:59:59Z
      
      # Permanent toleration
      - id: CVE-2025-0838
        statement: "No fix available, accepted risk after security review"
      
      # False positive
      - id: CVE-2024-12345
        statement: "False positive, not applicable to our use case"
        expires_at: 2025-06-30T23:59:59Z
```

**Fields:**
- `id` (required): CVE identifier (e.g., `CVE-2024-56171`)
- `statement` (required): Reason for toleration (for audit and compliance)
- `expires_at` (optional): RFC3339 timestamp when toleration expires

**Behavior:**
- Tolerated CVEs are excluded from policy evaluation
- Expired tolerations are ignored (CVE counts as critical)
- Warnings logged for tolerations expiring within 7 days
- Tolerations without `expires_at` never expire

## Examples

### Minimal Configuration

```bash
# .env file
SUPPLINE_CONFIG=suppline.yml
ATTESTATION_KEY_PATH=/keys/cosign.key
```

### Development Configuration

```bash
# .env file
SUPPLINE_CONFIG=suppline.yml
ATTESTATION_KEY_PATH=./keys/cosign.key
LOG_LEVEL=debug
TRIVY_SERVER_ADDR=localhost:4954
STATE_STORE_TYPE=sqlite
SQLITE_PATH=./suppline.db
API_KEY=dev-secret-key
RESCAN_INTERVAL=1h
```

### Production Configuration

```bash
# Kubernetes ConfigMap
WORKER_POLL_INTERVAL=5s
WORKER_RETRY_ATTEMPTS=3
RESCAN_INTERVAL=24h
QUEUE_BUFFER_SIZE=2000
TRIVY_SERVER_ADDR=trivy:4954
TRIVY_TIMEOUT=10m
STATE_STORE_TYPE=sqlite
SQLITE_PATH=/data/suppline.db
LOG_LEVEL=info
METRICS_PORT=9090
HEALTH_CHECK_PORT=8081
API_ENABLED=true
API_PORT=8080

# Kubernetes Secret
SUPPLINE_CONFIG=/config/suppline.yml
ATTESTATION_KEY_PATH=/keys/cosign.key
ATTESTATION_KEY_PASSWORD=<from-secret>
API_KEY=<from-secret>
```

## Duration Format

Duration values use Go's duration format:

- `s` - seconds (e.g., `30s`)
- `m` - minutes (e.g., `5m`)
- `h` - hours (e.g., `24h`)
- Combined (e.g., `1h30m`, `2h45m30s`)

**Examples:**
```bash
WORKER_POLL_INTERVAL=5s
TRIVY_TIMEOUT=5m
RESCAN_INTERVAL=24h
WORKER_RETRY_BACKOFF=30s
```

## Boolean Format

Boolean values accept multiple formats:

**True values:** `true`, `1`, `yes`
**False values:** `false`, `0`, `no`, `` (empty)

**Examples:**
```bash
API_ENABLED=true
TRIVY_INSECURE=false
API_READ_ONLY=1
```

## Configuration Best Practices

### Security

1. **Never commit secrets** to version control
2. **Use strong API keys** (minimum 32 characters)
3. **Rotate credentials regularly** (every 90 days)
4. **Use repository-scoped tokens** instead of user passwords
5. **Enable TLS** for Trivy server in production
6. **Restrict API access** with network policies

### Performance

1. **Adjust queue buffer size** based on registry size
2. **Tune rescan interval** to balance freshness and load
3. **Increase Trivy timeout** for large images
4. **Monitor queue depth** and adjust worker settings

### Reliability

1. **Set appropriate retry attempts** (3-5 recommended)
2. **Use exponential backoff** for retries
3. **Enable health checks** in orchestrator
4. **Configure resource limits** appropriately
5. **Use persistent storage** for state store

### Observability

1. **Use structured logging** (JSON format)
2. **Set appropriate log level** (info for production)
3. **Enable Prometheus metrics** for monitoring
4. **Configure alerting** on key metrics
5. **Integrate with log aggregation** systems
