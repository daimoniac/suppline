# AGENTS.md — suppline

> Quick-reference for AI coding agents. Read this before starting any task.

## What suppline does

Self-hosted container image intake gateway for Kubernetes: **Mirror → Scan → Gate → Attest → Run.**

Automates the container supply chain security workflow:
1. **Mirror** — syncs images from remote registries (Docker Hub, Quay, etc.) to a private registry via `regsync`
2. **Scan** — runs Trivy in client-server mode; produces CycloneDX SBOMs and CVE reports
3. **Gate** — evaluates CEL-based policies (default: `criticalCount == 0`) with per-repo VEX (Vulnerability Exploitability Exchange) support
4. **Attest** — signs SBOM, vulnerability report, VEX, and SCAI attestations with Sigstore/cosign
5. **Serve** — REST API + Prometheus metrics; Kyverno/OPA enforce attestation-verified-only image deployments

Single Go binary. Air-gap compatible. No SaaS dependency.

## Go module

```
module github.com/daimoniac/suppline
go 1.24.0
```

CGO is required (`mattn/go-sqlite3`). The build needs `gcc`, `musl-dev`, and `sqlite-dev`.

## Essential commands

```bash
make build              # go build + swagger regen → ./suppline binary
make run                # build + run locally
make test               # unit tests only (alias: make test-unit)
make test-unit          # ./scripts/test.sh unit
make test-integration   # requires Docker Compose; guards on INTEGRATION_TEST=true
make test-all           # unit + integration + auth
make lint               # golangci-lint run ./...
make fmt                # gofmt -s -w + go fmt
make vet                # go vet ./...
make deps               # go mod download && go mod tidy
make dev-setup          # deps + install golangci-lint
make clean              # remove binary, *.db, coverage.txt, build/
```

Direct Go test (unit only, no Docker required):
```bash
go test ./internal/...
```

## Project layout

```
cmd/suppline/main.go        Entry point; wires all components via constructors
internal/
  api/                      HTTP REST server (stdlib net/http, no external router)
  attestation/              cosign/Sigstore attestation; SBOM + vuln + SCAI
  config/                   All config types, env var loading, YAML + Go template expansion
  errors/                   Domain error types: TransientError, PermanentError, ManifestNotFoundError
  integration/              Kyverno ClusterPolicy YAML generation; public key retrieval
  observability/            Prometheus metrics, health check, slog logger, metrics+health server
  policy/                   CEL policy engine; VEX-based exemption filtering; expiry warnings
  queue/                    In-memory priority queue; digest-based deduplication; two priority channels
  registry/                 go-containerregistry client: lists repos/tags, get digests/manifests
  scanner/                  Trivy CLI wrapper (client-server mode); local fallback; SBOM generation
  statestore/               SQLite persistence (WAL mode); StateStore / StateStoreQuery / StateStoreCleanup interfaces
  types/                    Domain types: Vulnerability, VEXStatement, VulnerabilityRecord
  watcher/                  Registry poller; enqueues ScanTask to queue on new/updated images
  worker/                   Concurrent processors; Pipeline: Scan → Policy → Attest → Persist
build/swagger/              Generated Swagger docs (do not edit manually)
charts/suppline/            Helm chart
test/integration/           Integration tests (need live Trivy + registry)
test/worker_integration/    Worker-level integration tests
ui/                         Nginx-based web frontend
```

## Architecture: request / task flow

```
Watcher (polls registry)
  └─► Queue (InMemoryQueue, two priority channels, digest-dedup)
        └─► ImageWorker (N goroutines, default 3)
              └─► Pipeline.Execute()
                    1. Scanner   → SBOM + CVE list
                    2. Policy    → CEL evaluation + VEX exemption filtering
                    3. Attestor  → cosign sign SBOM / vuln / VEX / SCAI
                    4. StateStore → write to SQLite

API (port 8080) ──────────────────────────────────► StateStore (read)
Metrics (port 9090) Prometheus
Health  (port 8081) JSON per-component status
```

## Configuration

Two-layer system:

**`suppline.yml`** (regsync format with `x-` extensions):
```yaml
version: 1
creds:
  - registry: docker.io
    user: '{{ env "DOCKER_USERNAME" }}'   # Go template expansion
    pass: '{{ env "DOCKER_PASSWORD" }}'
defaults:
  parallel: 4
  x-rescanInterval: 1d
  x-worker-concurrency: 3
  x-policy:
    expression: "criticalCount == 0"
sync:
  - source: nginx
    target: myprivateregistry/nginx
    type: repository
    x-vex:
      - id: CVE-2024-56171
        state: not_affected
        justification: vulnerable_code_not_present
        detail: "accepted risk"
        expires_at: 2025-12-31T23:59:59Z
```

**Key environment variables** (see `env.example` for full list):

| Variable | Default | Purpose |
|---|---|---|
| `SUPPLINE_CONFIG` | `suppline.yml` | Config file path |
| `LOG_LEVEL` | `info` | debug/info/warn/error |
| `TRIVY_SERVER_ADDR` | `localhost:4954` | Trivy server |
| `TRIVY_LOCAL_FALLBACK` | `true` | Fall back to local scan |
| `SUPPLINE_API_KEY` | — | Bearer key for REST API |
| `ATTESTATION_KEY` | — | Base64-encoded cosign private key |
| `STATE_STORE_TYPE` | `sqlite` | Only sqlite implemented |
| `SQLITE_PATH` | `./data/suppline.db` | SQLite DB file |
| `API_PORT` | `8080` | REST API |
| `METRICS_PORT` | `9090` | Prometheus |
| `HEALTH_PORT` | `8081` | Health endpoint |
| `WORKER_CONCURRENCY` | `3` | Parallel scan workers |
| `RESCAN_INTERVAL` | `24h` | How often to rescan |

## Web UI

The frontend is a **SPA built with a modern framework (Vite/React)** served by `nginx:alpine`. Full details in [ui/AGENTS.md](ui/AGENTS.md). Key facts:

- **Entry point**: `ui/index.html` — single shell; all navigation is client-side via History API
- **API client**: `ui/js/api.js` — all `fetch()` calls; reads backend URL from `/config.json` (runtime-generated from `$API_BASE_URL`)
- **Auth**: API key stored in `localStorage` (`stk_api_key`); validated against the backend at login
- **XSS guard**: `ui/js/utils/security.js:escapeHtml()` — must be used whenever API data is interpolated into HTML strings
- **Build**: `make build-ui` (docker build). Built artifacts are served as static files.
- **Local dev**: `docker run -p 3000:80 -e API_BASE_URL=http://localhost:8080 suppline-ui`
- **Tests**: `node ui/test.js` (hand-rolled, no framework)

## REST API

- Base path: `/api/v1`
- Auth: `Authorization: Bearer <SUPPLINE_API_KEY>`
- Swagger UI: `http://localhost:8080/swagger/index.html`
- Key endpoints: `GET /scans`, `GET /scans/{digest}`, `GET /failed`, `POST /rescan`, `GET /vulnerabilities`, policy management, Kyverno policy generation
- Swagger annotations use `swaggo` format; run `make build` to regenerate docs after changing annotations

## Code conventions

**Error handling**
- Wrap with `fmt.Errorf("context: %w", err)`
- Use `internal/errors` domain types for retry semantics:
  - `errors.NewTransient(err)` → worker will retry (up to `RetryAttempts`)
  - `errors.NewPermanentf(...)` → fail immediately, no retry
  - `errors.IsTransient(err)` / `errors.IsManifestNotFound(err)` for checks
- Sentinel store errors (e.g. `statestore.ErrScanNotFound`) checked with `errors.Is()`

**Logging**
- Stdlib `log/slog` only — no third-party logger
- Structured key-value pairs: `logger.Info("message", "key", value)`
- Logger injected via constructor, not global
- UTC timestamps

**Interfaces**
- Defined in the **consumer** package, not the provider
- All major components expose Go interfaces: `Scanner`, `Attestor`, `PolicyEngine`, `TaskQueue`, `Worker`, `Watcher`, `Client`
- Enables inline mock structs in tests — no mock generation framework used

**Testing**
- Unit tests co-located with source (`*_test.go` beside `.go`)
- Property-based tests use `github.com/leanovate/gopter`
- Integration tests guard on `INTEGRATION_TEST=true` env var
- API tests use `httptest.NewRecorder()` / `httptest.NewServer()`
- No mock framework — mocks are plain structs implementing the interface

## Database (SQLite)

WAL mode, foreign keys enabled, 5-connection pool. Schema:
- `repositories` — registry + name
- `artifacts` — per-digest record with scan schedule
- `scans` — vuln counts, policy pass/fail, attest flags, duration, error
- `vulnerabilities` — individual CVEs linked to scans
- `vex_statements_json` — applied VEX exemptions per scan

Postgres is planned but not implemented. Do not add a second store backend without discussion.

## Common pitfalls

- **CGO required**: `go build` without a C compiler will fail. In Docker the builder uses `golang:*-alpine` with explicit `apk add gcc musl-dev sqlite-dev`.
- **Swagger docs**: `build/swagger/` is generated. Edit annotations in handler files, then `make build` to regenerate. Never hand-edit the generated files.
- **Config templates**: `suppline.yml` is processed as a Go text/template before YAML parsing. Double-braces `{{ }}` are intentional.
- **Integration test guard**: integration tests will silently skip unless `INTEGRATION_TEST=true` is set and Docker Compose services are running.
- **`values-secrets.yaml`**: never commit this file — it is gitignored. Use `values-secrets.yaml.example` as the template.
