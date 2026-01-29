<p align="center">
  <img src="docs/suppline-fullsize.png" alt="suppline logo" width="300"/>
</p>


*“Self-hosted image intake gateway for Kubernetes.”*


Continuously mirrors remote registries, scans, policy-gates, and attests images before they reach your cluster.

suppline mirrors images from public registries into your local registry, continuously scans them with Trivy, evaluates CEL-based security policies, and publishes Sigstore attestations. Clusters then pull only from the local mirror and can enforce “verified-only” deployments via Kyverno/OPA.

Mirror → Scan → Gate → Attest → Run.
cloud native, one service, no SaaS dependency — air-gap compatible by design. Increase availability, decrease vendor dependency, improve supply chain security, all in one go. 

## Overview

suppline automates the complete container supply chain workflow for third party images:

1. **Mirror** - Continuously syncs images from remote registries to your local registry using regsync
2. **Scan** - Runs Trivy to identify vulnerabilities and generate SBOMs
3. **Evaluate** - Applies CEL-based policies with CVE toleration support per repository
4. **Attest** - Creates signed attestations (SBOM, vulnerabilities, SCAI) via Sigstore

Runs as a single Go binary with built-in state persistence, REST API, and observability. Clusters pull only from your local mirror — no external registry dependencies. Integrates with Kyverno/OPA policies to enforce only scanned, compliant images in your cluster.

## Features

- **Continuous Registry Mirroring** - Syncs images from public registries to your local mirror using regsync, keeping your supply chain local and available
- **Bring Your Own Registry** - Mirror to any private registry or use built-in local storage
- **Registry Monitoring** - Watches for new/updated images in your local mirror
- **Smart Rescanning** - Conditional logic based on digest changes and time intervals
- **CVE Tolerations** - Accept specific vulnerabilities with expiry dates and audit trails
- **Policy Engine** - CEL-based policies with per-repository overrides
- **Sigstore Attestations** - SBOM, vulnerability, and SCAI attestations with cosign
- **State Persistence** - SQLite-based scan history and vulnerability tracking
- **REST API** - Query results, trigger rescans, manage policies
- **Observability** - Prometheus metrics, structured JSON logs, health checks
- **Air-Gap Compatible** - No external registry dependencies, works in isolated environments

## Why Mirror?

Continuous registry mirroring with suppline provides critical benefits:

- **Increased Availability** - Clusters pull from your local registry, not external vendors. No more image pull failures due to upstream outages.
- **Decreased Vendor Dependency** - Your supply chain is no longer tied to the availability of Docker Hub, Quay, or other public registries.
- **Improved Supply Chain Security** - All images pass through your security pipeline before reaching clusters. Enforce policies, scan for vulnerabilities, and attest every image.
- **Air-Gap Deployments** - Mirror images once, deploy to isolated networks without external registry access.
- **Compliance & Audit** - Complete audit trail of every image, scan result, and policy decision in your local database.
- **Cost Optimization** - Reduce egress bandwidth by pulling from local registry instead of remote sources.

## How It Works

```
Remote Registries → Mirroring (regsync) → Local Registry
                                              ↓
                                          Watcher → Queue → Worker → Scanner (Trivy)
                                                                          ↓
                                                                  Policy Engine
                                                                          ↓
                                                                  Attestor (Cosign)
                                                                          ↓
                                                                  State Store (SQLite)
                                                                          ↓
                                                                  REST API / Metrics
```

**Mirroring** continuously syncs images from remote registries to your local registry using regsync configuration. **Watcher** polls your local registry for new/updated images and enqueues scan tasks. **Worker** processes tasks through the pipeline: scan with Trivy, evaluate policy, create attestations, persist results. **API** exposes scan data and metrics for integration with Kyverno/OPA policies. Kubernetes clusters pull only from your local mirror, eliminating external registry dependencies.

## Getting Started

### Prerequisites

- Container registry credentials
- Cosign key pair for attestations

### 1. Configure

```bash
cp suppline.yml.example suppline.yml
```

Edit `suppline.yml` with your registry credentials and mirroring rules:

```yaml
version: 1

creds:
  - registry: docker.io
    user: [username]
    pass: [password]
  - registry: myregistry.com
    user: [username]
    pass: [password]

defaults:
  parallel: 2
  x-rescanInterval: 7d
  x-policy:
    expression: "criticalCount == 0"
    failureMessage: "critical vulnerabilities found"

sync:
  - source: nginx
    target: myregistry.com/nginx
    type: repository
    x-tolerate:
      - id: CVE-2024-56171
        statement: "Accepted risk"
        expires_at: 2025-12-31T23:59:59Z
  - source: kubernetes/pause
    target: myregistry.com/kubernetes/pause
    type: repository
```

The `sync` section defines what images to mirror from remote registries to your local registry. Images are continuously kept in sync, scanned, and evaluated against your policies.

### 2. Generate Keys

```bash
mkdir -p keys
cosign generate-key-pair
mv cosign.key keys/
```

### 3. Start

```bash
docker compose up -d
```

### 4. Verify

```bash
curl http://localhost:8081/health
curl http://localhost:8080/api/v1/scans
```

## Configuration

### Environment Variables

| Variable | Default | Purpose |
|----------|---------|---------|
| `SUPPLINE_CONFIG` | `suppline.yml` | Config file path |
| `LOG_LEVEL` | `info` | Log level (debug, info, warn, error) |
| `QUEUE_BUFFER_SIZE` | `1000` | Task queue capacity |
| `WORKER_POLL_INTERVAL` | `5s` | Worker poll frequency |
| `WORKER_RETRY_ATTEMPTS` | `3` | Max retries for transient failures |
| `TRIVY_SERVER_ADDR` | `localhost:4954` | Trivy server address |
| `TRIVY_TIMEOUT` | `5m` | Scan timeout |
| `SQLITE_PATH` | `suppline.db` | Database file path |
| `ATTESTATION_KEY_PATH` | `/keys/cosign.key` | Cosign private key |
| `API_PORT` | `8080` | API server port |
| `SUPPLINE_API_KEY` | - | Optional API authentication |
| `METRICS_PORT` | `9090` | Prometheus metrics port |
| `HEALTH_CHECK_PORT` | `8081` | Health check port |

### Configuration Format

`suppline.yml` uses regsync format with suppline extensions for mirroring and security policies. You can use golang templating expansion, useful for e.g. secrets:

```yaml
version: 1

creds:
  - registry: docker.io
    user: '{{ env "DOCKER_USERNAME" }}'
    pass: '{{ env "DOCKER_PASSWORD" }}'
  - registry: myregistry.com
    user: '{{ env "MYREGISTRY_USERNAME" }}'
    pass: '{{ env "MYREGISTRY_PASSWORD" }}'

defaults:
  parallel: 2
  x-rescanInterval: 7d
  x-policy:
    expression: "criticalCount == 0"
    failureMessage: "critical vulnerabilities found"
  x-tolerate:                         # Default tolerations for all targets
    - id: CVE-2024-00001
      statement: "Known false positive"
      expires_at: 2025-12-31T23:59:59Z

sync:
  - source: nginx
    target: myregistry.com/nginx
    type: repository
    x-rescanInterval: 3d              # Override default
    x-policy:                         # Override default
      expression: "criticalCount == 0 && highCount <= 5"
    x-tolerate:                       # Merged with default tolerations
      - id: CVE-2024-56171
        statement: "Accepted risk"
        expires_at: 2025-12-31T23:59:59Z
```

**Key Fields:**
- `source` - Source image/repository (from remote registry)
- `target` - Target location in your local registry
- `type` - `repository` (all tags) or `image` (specific tag)
- `x-rescanInterval` - How often to rescan unchanged images (default: 24h)
- `x-policy` - CEL-based security policy for this mirror
- `x-tolerate` - CVE tolerations with expiry dates (merged with defaults)

Images are continuously mirrored from source to target, then scanned and evaluated against policies. Kubernetes clusters pull only from the target registry.

### Policies

Policies use CEL (Common Expression Language). Available variables:

- `criticalCount`, `highCount`, `mediumCount`, `lowCount` - Vulnerability counts (excluding tolerated)
- `toleratedCount` - Number of tolerated CVEs
- `vulnerabilities` - Full vulnerability list with details
- `imageRef` - Image reference

**Common Policies:**

```yaml
# No critical vulnerabilities
expression: "criticalCount == 0"

# No critical or high
expression: "criticalCount == 0 && highCount == 0"

# Allow up to 5 high
expression: "criticalCount == 0 && highCount <= 5"

# Only block fixable critical vulnerabilities
expression: |
  vulnerabilities.filter(v,
    v.severity == "CRITICAL" &&
    v.fixedVersion != "" &&
    !v.tolerated
  ).size() == 0
```

See [Policy Guide](docs/POLICY.md) for more examples and CEL reference.

## API

The API is mainly used for the UI. For details, see the swagger documentation included in the binary at http://localhost:8080/swagger.

### Query Endpoints

```bash
# Get scan record
GET /api/v1/scans/{digest}

# List scans
GET /api/v1/scans?repository=nginx&limit=10

# Search vulnerabilities
GET /api/v1/vulnerabilities?cve_id=CVE-2024-56171&severity=CRITICAL

# List tolerations
GET /api/v1/tolerations

# List failed images
GET /api/v1/images/failed
```

### Action Endpoints

```bash
# Trigger rescan
POST /api/v1/scans/trigger
{ "digest": "sha256:abc123...", "repository": "nginx" }

# Re-evaluate all policies
POST /api/v1/policy/reevaluate
```

### Observability

```bash
# Health check
GET /health

# Prometheus metrics
GET /metrics
```

**Key Metrics:**
- `suppline_scans_total` - Total scans by status
- `suppline_policy_passed_total` - Images passing policy
- `suppline_policy_failed_total` - Images failing policy
- `suppline_vulnerabilities_total` - Vulnerabilities by severity
- `suppline_queue_depth` - Current queue depth

## Deployment

### Docker Compose
This will spin up trivy, regsync, suppline, suppline-ui and registry containers comprising the solution.

```bash
docker compose up -d
docker compose logs -f suppline
docker compose down
```

### Kubernetes

edit the `values.yaml` and `values-secrets.yaml` (or use env variables) in `charts/suppline` and substitute your configuration.

Install the solution using helm into your namespace:

```bash
helm install --upgrade -f charts/suppline/values.yaml -f charts/suppline/values-secrets.yaml suppline charts/suppline
```

### Standalone

```bash
make build
trivy server --listen localhost:4954 &
export SUPPLINE_CONFIG=suppline.yml
export ATTESTATION_KEY=<base64-encoded cosign private key>
export ATTESTATION_KEY_PASSWORD=<cosign password>
./suppline
```

## Development

### Setup

```bash
make deps
make dev-setup
make build
make test
```

### Project Structure

```
cmd/suppline/              # Entry point
internal/
  ├── api/                 # HTTP API
  ├── attestation/         # Sigstore integration
  ├── config/              # Config parsing
  ├── policy/              # CEL policy engine
  ├── queue/               # Task queue
  ├── registry/            # OCI registry client
  ├── scanner/             # Trivy integration
  ├── statestore/          # SQLite persistence
  ├── watcher/             # Registry monitoring
  └── worker/              # Pipeline orchestration
test/integration/          # Integration tests
ui/                        # web frontend
```

### Testing

```bash
make test                  # Unit tests
make test-integration      # Integration tests
make test-all              # All tests with coverage
```

## Monitoring

### Metrics

Prometheus metrics on `:9090/metrics`:

- `suppline_scans_total` - Total scans by status
- `suppline_policy_passed_total` - Images passing policy
- `suppline_policy_failed_total` - Images failing policy
- `suppline_queue_depth` - Current queue depth
- `suppline_vulnerabilities_total` - Vulnerabilities by severity
- `suppline_scan_duration_seconds` - Scan duration histogram

### Logging

JSON-formatted structured logs with fields: `time`, `level`, `msg`, `digest`, `repository`, `critical`, `high`, `tolerated`, etc.

### Health

```bash
curl http://localhost:8081/health
```

Returns status of: config, queue, worker, trivy, database, watcher

## Troubleshooting

**Trivy connection failed**

```bash
curl http://localhost:4954/healthz
docker compose logs trivy
```

**Authentication errors**

```bash
# Verify credentials in suppline.yml
cosign login docker.io -u [username] -p [password]
```

```bash
# Verify attestations generated by suppline
cosign verify-attestation --type https://in-toto.io/attestation/scai/attribute-report/v0.3 --key keys/cosign.pub --insecure-ignore-tlog myprivateregistry/alpine:3.22 | jq -r .payload | base64 -d | jq -r
Verification for myprivateregistry/beats_filebeat-oss@sha256:1d2de3fdbbf6494560a65a8d07961082b8b1652732fef839005f3e945f7a01d0 --
The following checks were performed on each of these signatures:
  - The cosign claims were validated
  - The signatures were verified against the specified public key
{
  "_type": "https://in-toto.io/Statement/v0.1",
  "predicateType": "https://in-toto.io/attestation/scai/attribute-report/v0.3",
  "subject": [
    {
      "name": "index.docker.io/myprivateregistry/beats_filebeat-oss",
      "digest": {
        "sha256": "1d2de3fdbbf6494560a65a8d07961082b8b1652732fef839005f3e945f7a01d0"
      }
    }
  ],
  "predicate": {
    "attribute": "container-security-assessment",
    "attributes": [
      {
        "attribute": "tolerated-vulnerability",
        "evidence": {
          "cveId": "CVE-2021-43527",
          "description": "NSS (Network Security Services) versions prior to 3.73 or 3.68.1 ESR are vulnerable to a heap overflow when handling DER-encoded DSA or RSA-PSS signatures. Applications using NSS for handling signatures encoded within CMS, S/MIME, PKCS \\#7, or PKCS \\#12 are likely to be impacted. Applications using NSS for certificate validation or other TLS, X.509, OCSP or CRL functionality may be impacted, depending on how they configure NSS. *Note: This vulnerability does NOT impact Mozilla Firefox.* However, email clients and PDF viewers that use NSS for signature verification, such as Thunderbird, LibreOffice, Evolution and Evince are believed to be impacted. This vulnerability affects NSS < 3.73 and NSS < 3.68.1.",
          "fixedVersion": "3.67.0-4.el7_9",
          "packageName": "nss",
          "severity": "CRITICAL",
          "statement": "DSA/RSA not used",
          "version": "3.53.1-7.el7_9"
        }
      }
    ],
    "evidence": {
      "lastScanned": "2025-11-22T14:49:02.617663494Z",
      "scanStatus": "passed-with-exceptions",
      "validUntil": "2025-11-30T14:49:02.617663494Z"
    },
    "target": {
      "uri": "pkg:docker/myprivateregistry/beats_filebeat-oss@sha256:1d2de3fdbbf6494560a65a8d07961082b8b1652732fef839005f3e945f7a01d0"
    }
  }
}
```
You can also check the attestations of type `cyclonedx` and `vuln` that suppline also generates for each digest.

**Database locked**

SQLite has limited concurrent write support
Use PostgreSQL for high-throughput or multiple instances

**Queue filling up**
```bash
curl http://localhost:8081/health
export WORKER_POLL_INTERVAL=10s
export QUEUE_BUFFER_SIZE=2000
```

**Debug mode**
```bash
export LOG_LEVEL=debug
./suppline
```

## Security

- Store Cosign keys in Kubernetes secrets or vault
- Use `SUPPLINE_API_KEY` for API authentication in production
- Never commit registry credentials to version control
- Enable TLS for Trivy server (`TRIVY_INSECURE=false`)
- Use network policies to restrict access in Kubernetes
- Apply minimal RBAC permissions to service accounts

## Integration



## Documentation

- **[API Reference](http://localhost:8080/swagger)** - Live Swagger docs
- **[Configuration Guide](docs/CONFIGURATION.md)** - Environment variables and regsync format
- **[Policy Guide](docs/POLICY.md)** - CEL policy examples and reference

## Support

- **Issues**: https://github.com/daimoniac/suppline/issues
- **Examples**: `suppline.yml.example` and `deploy/` directory
