---
status: accepted
---

# PostgreSQL is the only state store; SQLite support is removed

suppline could persist to SQLite or PostgreSQL. Every deployment now runs PostgreSQL, the Compose eval included, and no SQLite installation is left. SQLite still shaped the code: CGO and a C toolchain in every build, `sqlite-libs` in the image, a dialect layer with branches per database, a `copy-sqlite` subcommand, and a `store.sqlitePath` setting. Worse, the unit tests ran against in-memory SQLite, while the only PostgreSQL test (`TestPostgresStoreRoundTrip`) is skipped unless `SUPPLINE_TEST_POSTGRES_URL` is set, and CI doesn't set it. CI tested the database nobody runs. Leader election ([ADR 0004](0004-warm-standby-with-postgres-leader-election.md)) builds on PostgreSQL advisory locks and would have needed a single-instance exception for SQLite.

We decided:

- **PostgreSQL is required.** suppline refuses to start without `POSTGRES_URL`. The `store` config section, `copy-sqlite` and the SQLite driver are removed. Strict config decoding rejects a leftover `store:` block, with an error that says SQLite support was removed.
- **Builds are pure Go.** `CGO_ENABLED=0`; the image drops `gcc`, `musl-dev`, `sqlite-dev` and `sqlite-libs`.
- **Tests run against PostgreSQL.** They need `SUPPLINE_TEST_POSTGRES_URL` and fail, not skip, when it is unset. `make test` starts a throwaway PostgreSQL container, and CI uses a `services: postgres` container. Each test gets its own database, cloned with `CREATE DATABASE … TEMPLATE` from one migrated per run.
- **The SQL stays as written.** `SQLiteStore` and the `sqlite_*.go` files are renamed, the per-database branches go, and the `DB` wrapper keeps rewriting `?` placeholders to `$n`. Rewriting every query buys nothing.
- **The chart keeps its bundled PostgreSQL as the default** when no external URL is given, and drops the SQLite data volume.

## Considered Options

- **Keep SQLite for single-node and eval installs**: no one runs it, the eval already uses PostgreSQL, and every feature would keep paying for two dialects and for tests against the wrong one.
- **testcontainers-go for tests**: a new dependency tree in a supply-chain tool, and it needs Docker from inside the test process. A URL plus `make test` does the same with no new code.
- **Embedded PostgreSQL binaries for tests**: downloads binaries at test time.
- **Rewrite queries to native `$n` placeholders**: a large diff with no behaviour change. Possible later, file by file.

## Consequences

- Running unit tests needs Docker (via `make test`) or a reachable PostgreSQL. `go test ./...` alone fails with a message naming the variable.
- Local builds no longer need a C toolchain, and the binary cross-compiles.
- Any config still carrying `store.sqlitePath` must drop it before upgrading.
