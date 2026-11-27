# AGENTS.md — suppline

Agent-focused working notes for this repository.

## Canonical docs

Use these as the source of truth instead of duplicating details here:

- Product overview and how to start: [README.md](README.md)
- Development commands: [Development](#development) below
- Zero-cred Compose eval path: [docs/EVAL.md](docs/EVAL.md)
- Release / semver images + Helm OCI: [docs/RELEASE.md](docs/RELEASE.md)
- UI-specific implementation guidance: [ui/AGENTS.md](ui/AGENTS.md)
- Policy details and CEL examples: [docs/POLICY.md](docs/POLICY.md)
- Registry and config details: [docs/REGISTRY.md](docs/REGISTRY.md), [docs/CONFIGURATION.md](docs/CONFIGURATION.md)

## Agent workflow

1. Read the relevant canonical docs above before editing.
2. Make the smallest safe change set; do not refactor unrelated code.
3. Run focused validation for touched areas first, then broader checks if needed.
4. If API annotations changed, regenerate swagger with `make build` (see [Development](#development)).

## Repository-specific guardrails

- Do not hand-edit generated swagger files in `build/swagger/`.
- Keep logging on stdlib `log/slog` with structured key-value fields.
- Use wrapped errors (`fmt.Errorf("...: %w", err)`) and existing domain error semantics in `internal/errors`.
- Keep interfaces in consumer packages; avoid introducing mock-generation tooling.
- Avoid adding a second state store backend unless explicitly requested.

## Validation guidance

- Prefer targeted tests for changed packages, then run broader test/lint commands as needed.
- Unit tests run against PostgreSQL: wrap `go test` in `./scripts/with-test-postgres.sh` (or use `make test`), which starts a throwaway server in Docker unless `SUPPLINE_TEST_POSTGRES_URL` is set. Use `storetest.New(t)` (or `newTestStore(t)` inside package statestore) for a fresh database per test.
- Integration tests need a Trivy server (`make test-integration`); do not assume they run in CI or locally by default.

## High-signal pitfalls

- `suppline.yml` is template-expanded before YAML parsing; preserve intentional `{{ ... }}` expressions.

## Development

```bash
make dev-setup          # deps + tooling
make build              # regenerates swagger, then builds (embeds the UI)
make test               # unit tests; throwaway PostgreSQL in Docker, or SUPPLINE_TEST_POSTGRES_URL
make test-integration   # needs a Trivy server
make lint fmt vet
```

```
cmd/suppline/          Service entry point
internal/
  watcher/             Registry polling and scan decisions
  queue/               Task queue with digest dedup
  worker/              Pipeline: scan → policy → attest → persist
  scanner/             Trivy integration
  policy/              CEL engine and VEX handling
  attestation/         cosign / Sigstore
  statestore/          PostgreSQL persistence
  api/                 REST API and Swagger
clusterstate-agent/    Kubernetes inventory reporter
charts/suppline/       Helm chart
ui/                    React + Vite frontend, embedded into the binary
```

Swagger files under `build/swagger/` are generated. UI notes are in [ui/AGENTS.md](ui/AGENTS.md).
