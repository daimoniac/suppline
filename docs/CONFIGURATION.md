# Configuration Reference

Complete reference for all configuration options in suppline.

## Table of Contents

- [Configuration Sources](#configuration-sources)
- [Environment Variables](#environment-variables)
- [Regsync Configuration](#regsync-configuration)
- [Examples](#examples)
- [Triage (`x-triage`)](#triage-x-triage)

## Configuration Sources

Configuration is loaded from multiple sources in this priority order:

1. **Default values** - Built-in defaults in the application
2. **Regsync file** - Registry and VEX configuration from `suppline.yml`
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
| `TRIVY_INSECURE` | bool | `false` | Skip TLS verification / allow insecure registry access (eval/HTTP registries) |

### State Store

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `STATE_STORE_TYPE` | string | `sqlite` | State store type: `sqlite`, `postgres`, or `memory` |
| `SQLITE_PATH` | string | `suppline.db` | SQLite database file path (when `STATE_STORE_TYPE=sqlite`) |
| `POSTGRES_URL` | string | `` | PostgreSQL connection URL (required when `STATE_STORE_TYPE=postgres`) |
| `RESCAN_INTERVAL` | duration | `24h` | Default rescan interval for unchanged images |

### SQLite schema reset

The normalized vulnerability schema stores CVE descriptions once in `cve_catalog`
and package occurrences in `scan_findings`. It intentionally does not migrate the
legacy `vulnerabilities` table. When upgrading from a version that used that table,
stop all Suppline writers, remove the SQLite database plus its `-wal` and `-shm`
files, and restart Suppline. Registry discovery and cluster inventory will refill
the empty database. Suppline refuses to start if it detects the legacy table.

### PostgreSQL

Set `STATE_STORE_TYPE=postgres` and `POSTGRES_URL` (for example
`postgres://user:pass@host:5432/suppline?sslmode=disable`). Compose and the Helm
chart default to a bundled PostgreSQL 18 instance. Official 18 images store data
under `/var/lib/postgresql/18/docker`; Compose and the chart mount
`/var/lib/postgresql`. Existing PostgreSQL 16 volumes cannot be reused.

To copy an existing catalog-schema SQLite database into an empty Postgres
database without starting the full worker pipeline:

```bash
SQLITE_PATH=/data/suppline.db POSTGRES_URL=postgres://... /app/suppline copy-sqlite
```

The command preserves row IDs and refuses to run if the destination already has
repositories. Do not switch a live backend to `postgres` until this copy
succeeds.

### Attestation

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `ATTESTATION_KEY` | string | `` | Base64-encoded Cosign private key (required for signing) |
| `ATTESTATION_KEY_PASSWORD` | string | `` | Password for encrypted private key |
| `ATTESTATION_ALLOW_HTTP_REGISTRY` | bool | `false` | Pass `--allow-http-registry` to cosign (Compose eval / HTTP registries only) |
| `ATTESTATION_NEW_BUNDLE_FORMAT` | bool | `false` | Pass `--new-bundle-format` to cosign. Default `false` writes classic `sha256-<digest>.att` tags; `true` uses Cosign v3 protobuf bundles / OCI referrers |
| `FULCIO_URL` | string | `https://fulcio.sigstore.dev` | Fulcio certificate authority URL |
| `ATTESTATION_COMMAND_TIMEOUT` | duration | `2m` | Timeout per Cosign attestation command |

### API Server

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `API_ENABLED` | bool | `true` | Enable HTTP API server |
| `API_PORT` | int | `8080` | API server port |
| `SUPPLINE_API_KEY` | string | `` | Required when the API is enabled. The cluster-inventory webhook and cluster list stay unauthenticated |
| `SUPPLINE_LLM_API_KEY` | string | `` | Bearer token for the Triage OpenAI-compatible endpoint. If `x-triage.enabled` is true and this is empty, Triage stays off |
| `SUPPLINE_ALLOW_NO_AUTH` | bool | `false` | Explicit opt-in to start the API with authentication disabled. Isolated evaluation only |
| `API_READ_ONLY` | bool | `false` | Disable write operations, including repository and tag rescan |

### Observability

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `METRICS_PORT` | int | `9090` | Prometheus metrics port |
| `HEALTH_CHECK_PORT` | int | `8081` | Health check endpoint port |

## Regsync Configuration

The `suppline.yml` file defines registry credentials, sync entries, and VEX (Vulnerability Exploitability Exchange) statements.

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
    tls: string               # optional: enabled (default), insecure, or disabled (HTTP)

# Default settings
defaults:
  parallel: int               # Parallel sync operations
  x-rescanInterval: string    # Default rescan interval (e.g., "7d", "24h")
  x-policy:                   # Default policy
    expression: string        # CEL expression
    failureMessage: string    # Custom failure message
  x-vex:                     # Default VEX statements (optional)
    - id: string              # CVE identifier
      state: string           # Analysis state (not_affected, affected, in_triage, false_positive, resolved, resolved_with_pedigree)
      justification: string   # Justification (required when state is not_affected)
      detail: string          # Explanation / reason
      expires_at: string      # RFC3339 timestamp or date (YYYY-MM-DD) (optional)

# Sync entries
sync:
  - source: string            # Source repository
    target: string            # Target repository
    type: string              # Type: "image" or "repository"
    schedule: string          # Cron schedule (optional)
    x-suppline-ignore: bool   # If true, suppline skips this entry entirely (default: false)
    x-rescanInterval: string  # Rescan interval override (optional)
    x-policy:                 # Policy override (optional)
      expression: string
      failureMessage: string
    x-vex:                    # VEX statements (optional)
      - id: string            # CVE identifier
        state: string         # Analysis state
        justification: string # Justification (for not_affected state)
        detail: string        # Explanation / reason
        expires_at: string    # RFC3339 timestamp or date (YYYY-MM-DD) (optional)
```

### Credentials Section

Credentials support Go template syntax for environment variable expansion, allowing you to keep secrets out of configuration files.

**Template Syntax:**
- Use `{{ env "VAR_NAME" }}` to expand environment variables
- Quotes are required around the template expression in YAML
- If no template syntax is present, values are used as-is

**Examples:**

```yaml
creds:
  # Using environment variables (recommended for secrets)
  - registry: registry-1.docker.io
    user: '{{ env "DOCKER_USERNAME" }}'
    pass: '{{ env "DOCKER_PASSWORD" }}'
    repoAuth: false
    reqPerSec: 10
    reqConcurrent: 10
  
  - registry: docker.io
    user: '{{ env "DOCKER_USERNAME" }}'
    pass: '{{ env "DOCKER_PASSWORD" }}'
    repoAuth: false
    reqPerSec: 10
    reqConcurrent: 10

  # Local HTTP registry (Compose eval / lab only)
  - registry: registry:5000
    tls: disabled
  
  # Plain text credentials (not recommended for production)
  - registry: registry.example.com
    user: admin
    pass: secretpassword
    repoAuth: false
```

**Environment Variables:**
```bash
export DOCKER_USERNAME=myusername
export DOCKER_PASSWORD=dckr_pat_xxxxxxxxxxxxx
```

**Security Best Practices:**
- Always use environment variables for credentials in production
- Never commit credentials to version control
- Use Kubernetes Secrets or similar secret management systems
- Rotate credentials regularly

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
  
  # Temporarily skip an entry without removing it
  - source: legacy-app
    target: myregistry.example.com/legacy-app
    type: repository
    x-suppline-ignore: true
```

### Ignoring Sync Entries

The `x-suppline-ignore` field lets you temporarily disable a sync entry without deleting it from `suppline.yml`.

**Behaviour:**
- When `true`, the entry is discarded while reading `suppline.yml`, so it is excluded from all downstream processing.
- When `false` (default), the entry is processed normally.
- The field is per-entry only; there is no defaults-level equivalent.

**Examples:**

```yaml
sync:
  # Active entry — processed normally
  - source: nginx
    target: myregistry.example.com/nginx
    type: repository

  # Temporarily ignored — kept for reference, not processed
  - source: legacy-app
    target: myregistry.example.com/legacy-app
    type: repository
    x-suppline-ignore: true

  # Explicit false — same as omitting the field
  - source: alpine
    target: myregistry.example.com/alpine
    type: repository
    x-suppline-ignore: false
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
- `criticalCount` - Number of critical vulnerabilities (excluding VEX-exempted)
- `highCount` - Number of high vulnerabilities (excluding VEX-exempted)
- `mediumCount` - Number of medium vulnerabilities (excluding VEX-exempted)
- `lowCount` - Number of low vulnerabilities (excluding VEX-exempted)
- `exemptedCount` - Number of VEX-exempted vulnerabilities
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

### VEX Statements

VEX (Vulnerability Exploitability Exchange) statements follow the CycloneDX VEX standard and can be defined at two levels:

1. **Default Level** - Applied to all sync targets
2. **Sync Entry Level** - Applied to specific repositories

VEX statements from both levels are **merged together**, with sync-specific statements added to the default ones.

**Default VEX Example:**

```yaml
defaults:
  x-vex:
    # These VEX statements apply to ALL sync targets
    - id: CVE-2024-00001
      state: false_positive
      detail: "Known false positive across all images"
      expires_at: 2025-12-31T23:59:59Z
    
    - id: CVE-2024-00002
      state: not_affected
      justification: vulnerable_code_not_present
      detail: "Accepted risk - no fix available in base images"

sync:
  - source: nginx
    target: myregistry.example.com/nginx
    type: repository
    # This target gets both default VEX statements PLUS the one below
    x-vex:
      - id: CVE-2024-56171
        state: not_affected
        justification: vulnerable_code_not_in_execute_path
        detail: "Nginx-specific exemption"
        expires_at: 2025-12-31T23:59:59Z
  
  - source: alpine
    target: myregistry.example.com/alpine
    type: repository
    # This target gets only the default VEX statements
```

**Sync-Specific VEX Example:**

```yaml
sync:
  - source: nginx
    target: myregistry.example.com/nginx
    type: repository
    x-vex:
      # Temporary exemption with expiry
      - id: CVE-2024-56171
        state: not_affected
        justification: vulnerable_code_not_present
        detail: "Initial VEX statement when introducing supplychain"
        expires_at: 2025-12-31T23:59:59Z
      
      # Permanent exemption
      - id: CVE-2025-0838
        state: not_affected
        justification: vulnerable_code_not_in_execute_path
        detail: "No fix available, accepted risk after security review"
      
      # False positive
      - id: CVE-2024-12345
        state: false_positive
        detail: "Not applicable to our use case"
        expires_at: 2025-06-30T23:59:59Z
```

**Fields:**
- `id` (required): CVE identifier (e.g., `CVE-2024-56171`)
- `state` (required): VEX analysis state. One of:
  - `not_affected` - The vulnerability does not affect this component (exempts from policy counts)
  - `affected` - The vulnerability affects this component
  - `in_triage` - Under investigation
  - `false_positive` - Incorrectly identified as vulnerable
  - `resolved` - The vulnerability has been remediated
  - `resolved_with_pedigree` - Resolved and provenance is tracked
- `justification` (required when state is `not_affected`): Canonical values:
  - `code_not_present`
  - `code_not_reachable`
  - `requires_configuration`
  - `requires_dependency`
  - `requires_environment`
  - `protected_by_compiler`
  - `protected_at_runtime`
  - `protected_at_perimeter`
  - `protected_by_mitigations`
  - Legacy aliases are still accepted and normalized internally:
  - `component_not_present` -> `code_not_present`
  - `vulnerable_code_not_present` -> `code_not_present`
  - `vulnerable_code_cannot_be_controlled_by_adversary` -> `code_not_reachable`
  - `vulnerable_code_not_in_execute_path` -> `code_not_reachable`
  - `inline_mitigations_already_exist` -> `protected_by_mitigations`
  - `protected_by_mitigating_control` -> `protected_by_mitigations`
- `detail` (optional): Human-readable explanation for audit and compliance
- `expires_at` (optional): When the statement expires. Supports:
  - RFC3339 timestamp: `2026-02-28T23:59:59Z`
  - Date only (sets to 23:59:59 UTC): `2026-02-28`
  - Date validation ensures valid dates (e.g., Feb 29 only in leap years)

**Behavior:**
- Only VEX statements with state `not_affected` and that are not expired exempt CVEs from policy evaluation
- Default VEX statements are merged with sync-specific statements
- Expired statements are ignored (CVE counts normally)
- Warnings logged for statements expiring within 7 days
- Statements without `expires_at` never expire

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
SUPPLINE_API_KEY=dev-secret-key
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
STATE_STORE_TYPE=postgres
POSTGRES_URL=postgres://suppline:suppline@postgres:5432/suppline?sslmode=disable
LOG_LEVEL=info
METRICS_PORT=9090
HEALTH_CHECK_PORT=8081
API_ENABLED=true
API_PORT=8080

# Kubernetes Secret
SUPPLINE_CONFIG=/config/suppline.yml
ATTESTATION_KEY_PATH=/keys/cosign.key
ATTESTATION_KEY_PASSWORD=<from-secret>
SUPPLINE_API_KEY=<from-secret>
```

## Triage (`x-triage`)

Triage runs after a CEL failure on an image that is currently running in a cluster (`only_in_use`, default true; the same runtime window as `source="runtime"` alerts). Set `only_in_use: false` to triage every failure. When triage is enabled, the policy views show **Triage now** and **Fix using coding agent** together. **Triage now** queues the failures in the current image-usage view. The coding-agent button copies a prompt for those same failures. The Triage view, and the Tasks triage card, list current automated runs that were rejected or left unresolved. Each row can be requeued or copied as **Fix this using coding assistant**, and **Fix all open using coding assistant** copies that whole set. Triage checks out the gitops repositories in `context_repos`, asks an OpenAI-compatible chat model whether the CVE affects this deployment, and may write `x-vex-auto` on the matching sync entry. The model can also read the latest image snapshots reported by the cluster agents, fetch the public CVE or GHSA advisory, and check out one directory of the image's source commit. That commit comes from the OCI labels `org.opencontainers.image.source` and `org.opencontainers.image.revision` when they are present. Otherwise triage reads the upstream tag's SLSA provenance (`configSource.uri` on the attestation attached to the catalog source image). A `-sha-` tag is searched on GitHub only when that attestation is missing, and only a single matching repository is used. The checkout is searched with the same grep and read_file tools as the gitops repos. `dependency_sources` then checks out at most five direct npm or pnpm dependents of the vulnerable package. `requires_configuration` and `requires_environment` may cite a gitops line or a line from one of those checkouts. `code_not_reachable` may cite a public line, an empty grep by the `grep_id` of a directory that was fully fetched (a parent that was not fetched is not absence), an empty grep of the scanned image when that search reports absence, or, for `linux`, `linux-libc-dev`, `linux-headers`, and `kernel`, a gitops line that names the image when the workload does not set `hostNetwork`, `privileged`, or a host device. The image checkout is named `image` and is used when the image has no source commit. It searches scripts, source files, and Go binaries. A skipped stripped native library that belongs to the package is not absence. A `grep_id` whose search returned rows is those lines. An empty grep does not satisfy `requires_configuration` or `requires_environment`. An empty grep of the gitops tree stays uncertain. `SUPPLINE_GITHUB_TOKEN` is used for GitHub code search and for the commit-search fallback. Hand-written `x-vex` is never modified and wins when both lists contain the same id. The workflow, dedupe rules, and guardrails are in [STATE_MACHINE.md](STATE_MACHINE.md).

```yaml
x-triage:
  enabled: true
  only_in_use: true      # default; false triages images that are not running
  mode: dry-run          # dry-run (default) | enforce
  llm:
    base_url: https://llm.internal/v1
    model: anthropic/claude-sonnet-5.5
    max_steps: 20
    daily_token_budget: 2000000
  min_confidence: 0.8
  expiry: 30d
  renew_before: 7d
  retriage_interval: 24h
  allowed_justifications:
    - requires_configuration
    - requires_environment
    - protected_at_perimeter
    - protected_at_runtime
    - protected_by_mitigations
    - code_not_reachable
  block_kev: true
  checkout_dir: /data/gitops
  backup_retention: 10
  context_repos:
    - name: infra
      url: https://git.example/infra/gitops.git
      auth: { type: https-token, env: GITOPS_INFRA_TOKEN }
      include: ["**/*.yaml"]
  config_repo:            # omit to edit the local suppline.yml instead
    url: ssh://git@git.example/infra/suppline-config.git
    path: suppline.yml
    auth:
      type: ssh
      key_env: SUPPLINE_CONFIG_REPO_KEY
      known_hosts_env: SUPPLINE_KNOWN_HOSTS
    author: { name: suppline-triage, email: triage@suppline.local }
```

`prompt` replaces the built-in decision policy. Leave it unset to accept a low residual risk with `requires_configuration` or `requires_environment`, and to rate a finding that is not exposed to the public down one severity step (`critical -> high`, `high -> medium`, `medium -> low`). The tool workflow and the JSON output contract stay in place either way.

Git credentials and `SUPPLINE_LLM_API_KEY` come from the environment, not from this file. SSH auth requires both a private key and `known_hosts`. An empty `branch` follows the remote HEAD. `config_repo.path` is a plain file inside that repository. In enforce mode without `config_repo`, the local file must be writable; a read-only ConfigMap mount refuses to start. Local writes keep `suppline.yml.bak.1` (newest) through `.bak.N`. The Tasks view uses the same writer for semver range updates, removing unused sync entries, and removing unused VEX statements: a configured `config_repo` is committed and pushed, otherwise the local file is updated. Those actions stay available when the LLM loop is off, as long as the file or config repository can be written.

Per-sync auto statements:

```yaml
sync:
  - source: nginx
    target: registry.example/nginx
    type: repository
    x-vex: []        # people
    x-vex-auto: []   # Triage
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
