# AGENTS.md — suppline

Agent-focused working notes for this repository.

## Canonical docs

Use these as the source of truth instead of duplicating details here:

- Product overview, setup, architecture, config, API, deployment, and development commands: [README.md](README.md)
- UI-specific implementation guidance: [ui/AGENTS.md](ui/AGENTS.md)
- Policy details and CEL examples: [docs/POLICY.md](docs/POLICY.md)
- Registry and config details: [docs/REGISTRY.md](docs/REGISTRY.md), [docs/CONFIGURATION.md](docs/CONFIGURATION.md)

## Agent workflow

1. Read the relevant canonical docs above before editing.
2. Make the smallest safe change set; do not refactor unrelated code.
3. Run focused validation for touched areas first, then broader checks if needed.
4. If API annotations changed, regenerate swagger via the documented build command in [README.md](README.md).

## Repository-specific guardrails

- Do not hand-edit generated swagger files in `build/swagger/`.
- Keep logging on stdlib `log/slog` with structured key-value fields.
- Use wrapped errors (`fmt.Errorf("...: %w", err)`) and existing domain error semantics in `internal/errors`.
- Keep interfaces in consumer packages; avoid introducing mock-generation tooling.
- Avoid adding a second state store backend unless explicitly requested.

## Validation guidance

- Prefer targeted tests for changed packages, then run broader test/lint commands as needed.
- Integration tests require the environment documented in [README.md](README.md); do not assume they run in CI/local by default.

## High-signal pitfalls

- CGO is required for sqlite (`mattn/go-sqlite3`), so local builds need a C toolchain.
- `suppline.yml` is template-expanded before YAML parsing; preserve intentional `{{ ... }}` expressions.
