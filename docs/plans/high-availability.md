# Plan: warm-standby high availability

Design and rationale:
- [ADR 0005](../adr/0005-postgres-is-the-only-state-store.md): PostgreSQL only (phase 0)
- [ADR 0004](../adr/0004-warm-standby-with-postgres-leader-election.md): leader election and proxying (phase 1)

Every PR can ship on its own and leaves `main` working. Deployments stay at one replica until PR 9 is released, which needs PRs 5–8 in place.

Out of scope: PostgreSQL HA (CNPG instances, backups), active/active scanning, and UI changes.

## Facts from the code that shape the plan

**Database and state**
- **The store goes through `database/sql` with the pgx stdlib driver** ([postgres.go:9-21](../../internal/statestore/postgres.go)). The pool allows 25 connections, with no idle timeout and no keepalive settings. `DB` embeds `*sql.DB` and rewrites `?` to `$n` ([dialect.go:36-48](../../internal/statestore/dialect.go)), so a raw `*sql.Conn` does not get the rewrite. A `*sql.Conn` stays pinned to its session and never reconnects behind the caller's back, which is what the lock needs. PR 5 asserts this in a test.
- **Every start runs schema migrations without a lock** (`initPostgresSchema`, [postgres.go:36-293](../../internal/statestore/postgres.go)). There is no version table; everything is `IF NOT EXISTS`.
- **Unit tests use in-memory SQLite.** 23 test files do. The only PostgreSQL test skips without `SUPPLINE_TEST_POSTGRES_URL` ([postgres_test.go:10-13](../../internal/statestore/postgres_test.go)), and CI runs `go test -race ./internal/...` with no database ([test.yml:45](../../.github/workflows/test.yml)).
- **Config decoding is strict** ([regsync.go:75](../../internal/config/regsync.go)). `store.sqlitePath` appears in [suppline.yml](../../suppline.yml), [suppline.yml.example](../../suppline.yml.example) and [CONFIGURATION.md](../CONFIGURATION.md).
- **State that already survives a failover**:
  - triage spend, in the `triage_budget` table
  - cooldown holds, kept in the registry ([ADR 0001](../adr/0001-cooldown-holds-imports-in-the-tag-runway.md))
  - scans, VEX and inventory, all in PostgreSQL

**Startup and running components**
- **What runs at startup** ([main.go](../../cmd/suppline/main.go)):
  - The observability server starts first (:90). That lets a standby serve `/health` while it waits.
  - Before any component starts, these have side effects:
    - the store and its migrations (:115)
    - the Trivy health check, which is fatal (:151)
    - the attestor key file (:174)
    - `cosign login`, which is fatal (:185)
    - `enqueueFailedArtifacts` and `enqueueDueArtifacts` (:263, :271)
  - Components start from :381 to :488.
- **Lost on failover, by design**:
  - the in-memory queue ([queue.go:64](../../internal/queue/queue.go))
  - the scan-request waiter ([scan_waiter.go](../../internal/api/scan_waiter.go))
  - runway candidates ([runway.go:113](../../internal/runway/runway.go))
  - mirror activity

  A new leader rebuilds the queue the same way a restart does: initial discovery plus the failed and due enqueues.
- **What each start sends to registries today**:
  - The watcher discovers at once, then every `worker-poll-interval` (5m in production): it lists tags and sends a HEAD per tag against the target registry ([watcher.go:121-155](../../internal/watcher/watcher.go), [main.go:241](../../cmd/suppline/main.go)).
  - The mirror runs a "missing" pass over **every** sync entry against every upstream source ([run.go:252-268](../../internal/mirror/run.go)), then startup cleanup over all `cleanupTags` targets ([cleanup.go:227](../../internal/mirror/cleanup.go)). It then starts each entry's `@every <interval>` cron from the process start.
  - Cleanup already follows every copy pass ([process.go:143](../../internal/mirror/process.go)).
  - `mirror_syncs` already stores `status` and `finished_at` for each entry ([postgres.go:189](../../internal/statestore/postgres.go)).
  - `enqueueFailedArtifacts` ([failed_rescan.go](../../cmd/suppline/failed_rescan.go)) already re-queues only in-use policy-failed artifacts, as urgent, but regardless of how recently they were scanned.
- **The malicious feed and triage checkouts live on the container filesystem** (`/data/...`). A new leader clones them again, as it does after any restart today.

**Health and metrics**
- **Health statuses** are only `healthy`, `unhealthy` and `unknown`, and anything other than healthy makes `/health` return 503 ([health.go:17-102](../../internal/observability/health.go)). Liveness and readiness both use `/health`, in the chart and in the infra repo.
- **Metrics**:
  - Business metrics register on the default registry through promauto ([metrics.go](../../internal/observability/metrics.go)).
  - The DB and config collectors are registered in `worker.Start` ([worker.go:254-255](../../internal/worker/worker.go)).
  - Unlabelled gauges export 0 until they are set, which matters for `suppline_malicious_db_last_sync_success_timestamp_seconds`: an unset value would trip the staleness alert.

**HTTP and scan requests**
- **The HTTP server** has `WriteTimeout: 15s` and shuts down with a 10 s timeout ([api.go:139-141, 319-324](../../internal/api/api.go)). Scan-request long-polls extend their own write deadline and wait up to 10 minutes (`maxScanRequestWait`, [handlers_scan_requests.go:25, 279](../../internal/api/handlers_scan_requests.go)).
- **Scan-request behaviour when the request is unknown**:
  - `GET /api/v1/scan-requests/{digest}` answers 404 when neither the waiter nor the queue knows the request and no newer scan exists (:245).
  - `POST` always queues a new urgent scan; it is deduplicated only while a scan of the same digest is pending.

**Chart and deployment**
- **The chart** ([charts/suppline](../../charts/suppline)):
  - The StatefulSet hardcodes `replicas: 1`, and `backend.replicaCount` is unused.
  - There is no PDB and no downward-API env.
  - The Role (`configmaps get/list`) is used by no code. go.mod has no client-go.
- **The infra deployment** uses `standard-bundle` 0.73.0 with `bundles: backend: statefulset`. That chart supports:
  - `bundles: backend: deployment`
  - `replicas`
  - per-bundle `podDisruptionBudgets` (with explicit `matchLabels`)
  - `affinity`
  - downward-API env through `containers.<name>.environment` or `additionalContainerSpec.env`. Use only one of them per container.

---

## Phase 0: PostgreSQL only (ADR 0005)

### PR 1: Run the tests against PostgreSQL

- `internal/statestore/storetest` (new, test helper): `New(t) *PostgresStore`.
  - Reads `SUPPLINE_TEST_POSTGRES_URL`. If it is unset, calls `t.Fatal` with a message that names the variable and `make test`.
  - Once per test binary: creates `suppline_tmpl_<random>`, runs migrations in it, and marks it as a template.
  - Per test: `CREATE DATABASE t_<random> TEMPLATE suppline_tmpl_<random>`, plus `t.Cleanup` that drops it.
- Switch all 23 test files from SQLite to `storetest.New`. Tests that depended on SQLite behaviour get fixed, not skipped. PostgreSQL's stricter typing, ordering and timestamp handling may expose real bugs; fix each in this PR or file it.
- `Makefile`:
  - `test-unit` starts `postgres:18-alpine` on a random port (`docker run --rm -d`), exports the URL, runs the tests, and stops the container.
  - `SUPPLINE_TEST_POSTGRES_URL` set in the environment overrides this.
- `.github/workflows/test.yml`: add a `services: postgres` container and set `SUPPLINE_TEST_POSTGRES_URL`.

### PR 2: Remove SQLite

- **Config**:
  - Delete `StateStore.Type`, `store.sqlitePath` and its defaults ([types.go](../../internal/config/types.go), [loader.go](../../internal/config/loader.go), [runtime.go](../../internal/config/runtime.go)).
  - Validation fails without `POSTGRES_URL`.
  - Strict decoding rejects `store:`. Wrap that error so it says SQLite support was removed.
- **Code**:
  - Delete `NewSQLiteStore`, the SQLite schema and `ensureSchemaColumns`, the SQLite branches in [dialect.go](../../internal/statestore/dialect.go) and its callers, [copy.go](../../internal/statestore/copy.go), and [copy_sqlite.go](../../cmd/suppline/copy_sqlite.go) with its subcommand in `main.go`.
  - `go mod tidy` drops `mattn/go-sqlite3`.
- **Build**:
  - [Dockerfile](../../Dockerfile): `CGO_ENABLED=0`; drop `gcc musl-dev sqlite-dev` from the builder and `sqlite-libs` from the runtime stage.
  - Check that `make build` and the release workflow don't set CGO.
- **Chart**: remove `persistence.data` and the SQLite comment at [values.yaml:139](../../charts/suppline/values.yaml). Bundled PostgreSQL stays the default.
- **Docs**:
  - README: the "SQLite or PostgreSQL" line, the architecture diagram alt text, the standalone build note and the `statestore/` line.
  - [docs/index.md](../index.md)
  - CONFIGURATION.md: the state-store section, the SQLite schema reset, `copy-sqlite`, and the `POSTGRES_URL` row, which becomes required.
  - STATE_MACHINE.md: "SQLite scan record".
  - AGENTS.md: the CGO pitfall.
  - `suppline.yml` and `suppline.yml.example`.

### PR 3: Rename (no behaviour change)

- Rename `SQLiteStore` to `Store`, `sqlite_*.go` to drop the prefix, and the `sqlite_*_test.go` files to match. The rename is mechanical, so review the diff with `git diff -M`.

---

## Phase 1: Leader election (ADR 0004)

### PR 4: Migration lock

- `initPostgresSchema` takes `pg_advisory_lock(<migration key>)` on a dedicated `*sql.Conn`, runs, then unlocks and closes the connection. The keys are constants in `statestore`, and two int32 keys keep them clear of the leader lock.
- Test: two stores migrate the same fresh database concurrently and both succeed.

### PR 5: Leader election, standby startup, health and metrics

Two or more replicas still must not run until PR 6, because a standby would answer API requests itself.

**`internal/leader` (new)**
- Consumer interface `Locker`:
  - `TryAcquire(ctx) (bool, error)`
  - `Check(ctx) error`
  - `Advertise(ctx, holder, address string) error`
  - `Release(ctx) error`
  - `Current(ctx) (Leader, bool, error)`
- `Elector.Run(ctx, onElected func(ctx))`:
  - As a standby it retries `TryAcquire` every 5 s.
  - After winning, it calls `Advertise`, sets `suppline_leader 1`, and runs `onElected`. Then it calls `Check` every 5 s with a 3 s timeout.
  - When a check fails, it logs at error level and calls the injected `exit` (default `os.Exit(1)`) after a 5 s best-effort cancel of the leader context.
- `holder` is a random instance ID plus the hostname, also used for `X-Suppline-Served-By`.

**`statestore` implementation**
- Takes a dedicated `*sql.Conn` from the store's pool (one of the 25). On that connection it runs `SET tcp_keepalives_idle = 10; SET tcp_keepalives_interval = 5; SET tcp_keepalives_count = 3`, then `SELECT pg_try_advisory_lock(<k1>, <k2>)`.
- `Check`: `SELECT EXISTS (SELECT 1 FROM pg_locks WHERE locktype = 'advisory' AND classid = <k1> AND objid = <k2> AND pid = pg_backend_pid() AND granted)`. It runs on the lock connection, so a broken connection also fails it.
- `Advertise` writes `leader(id = 1, holder, address, backend_pid, acquired_at)` with an upsert. This PR adds the table to `initPostgresSchema`, which runs under the PR 4 lock.
- `Current` runs one query: the `leader` row joined with `pg_locks` on `backend_pid` and `granted`. It returns no leader if the row's backend doesn't hold the lock.
- `Release`: `pg_advisory_unlock`, then close the connection.

**`main.go`**
- Split startup. Everything up to and including `cosign login` and component construction runs on every pod. The `enqueue*` calls and every `Start`/`Run` move into `onElected`. That includes registering the DB and config collectors, which already live in `worker.Start`.
- The API server starts on every pod. PR 6 makes the standby proxy.

**Health**
- Add `StatusStandby`, which counts as healthy in `GetHealth` and `/ready`.
- Until election, the queue, worker, watcher, mirror and malicious components report `standby`. `onElected` sets them as the code does today.
- `/health` JSON gains `"role": "leader" | "standby"`.

**Metrics**
- New gauge `suppline_leader`.
- The observability server's `/metrics` handler serves a standby registry (Go and process collectors plus `suppline_leader`) until election, then the default registry. Leadership only ever goes from standby to leader, because a loss exits the process, so this is a one-way switch.

**Tests**
- Against `storetest`:
  - Two lockers: only one acquires.
  - `pg_terminate_backend` of the holder's PID makes its `Check` fail and lets the other acquire.
  - `Current` ignores a row whose backend lost the lock.
  - A `*sql.Conn` whose backend was terminated fails `PingContext`/queries and does not reconnect.
- `Elector` with a fake `Locker` and an injected `exit`.
- Health: `standby` counts as healthy.

### PR 6: Standbys proxy the API port

**Config**: `server.advertiseAddress`, a URL such as `http://10.0.3.7:8080`. If it is empty, the default is the first non-loopback IPv4 of the host plus `server.port`. Document it in CONFIGURATION.md.

**`internal/api`**
- A wrapping handler in front of the router.
  - On the leader it adds `X-Suppline-Served-By` and passes the request through.
  - On a standby:
    - If `X-Suppline-Proxied` is present, answer 503 (loop guard).
    - Otherwise resolve the leader through `Current`, cached for 2 s and refreshed early after a proxy error. If there is no leader, poll every 500 ms for up to 10 s, then answer 503 with `Retry-After: 5`.
    - Proxy with `httputil.ReverseProxy` (`Rewrite`, `SetXForwarded`, `X-Suppline-Proxied: 1`, path and basePath unchanged).
    - Clear the write deadline for proxied requests through `http.NewResponseController(w).SetWriteDeadline(time.Time{})`.
    - On a dial error the `ErrorHandler` invalidates the cache and answers 502.
- Where the leader logs the client IP or OIDC context, it must use `X-Forwarded-For` only when `X-Suppline-Proxied` is set. Check `scanRequestAuth` and the webhook handlers.
- Tests: proxying, loop guard, waiting for a leader, a long response past 15 s, and basePath.

### PR 7: Graceful shutdown with drain

- On SIGTERM:
  1. Mark the process as draining, so `/ready` on the observability port returns 503 and the Service stops sending new requests.
  2. Close the open scan-request waits so they answer 202 with their poll path. Add a `draining` channel to `ScanRequestWaiter` that `awaitScan` selects on, next to the existing `closed`.
  3. `server.Shutdown` with the remaining budget.
  4. Cancel the components, wait, release the lock, close the store.

  The whole sequence is bounded by 60 s, which replaces today's 30 s and 10 s timeouts.
- A standby only drains its proxied requests, which carry no waits of their own. A long-poll it proxies is cut when the drain ends, and the client polls again.
- **Lock loss** skips all of this (PR 5).
- **Docs** (CONFIGURATION.md, scan requests from CI): the job re-POSTs when the connection drops, a request answers 5xx, or a poll answers 404, with up to 3 attempts. Update the ready-to-use job snippet.

### PR 8: Continue schedules from stored state

This also makes plain restarts cheaper. It must land before PR 9 allows two replicas.

**Mirror** ([run.go](../../internal/mirror/run.go), [journal.go](../../internal/mirror/journal.go))
- After `journal.Bind`, read each entry's `mirror_syncs` row and decide whether its startup "missing" pass runs. It runs when any of these hold:
  - the status is `never` or failed
  - there is no row, because the key is new or the config changed
  - an `interval` entry finished longer ago than its interval
  - a `schedule` (cron) entry finished before the most recent time its schedule fired
- For `interval` entries, replace `@every <interval>` with a first run at `finished_at + interval` (or now, if that is in the past), then `@every <interval>`. Cron `schedule` entries keep their wall-clock schedule.
- `runCleanupForAllTargets` covers only the targets whose entry ran its startup pass. If none ran, skip it.
- Journal bookkeeping for skipped entries: don't `Begin`/`Finish`, and keep the stored row. The mirror's health still becomes ready through `WithReady`.

**Failed artifacts** ([failed_rescan.go](../../cmd/suppline/failed_rescan.go))
- Keep the in-use and unused split, and still skip unused ones.
- Also skip in-use artifacts whose last scan (`ScanRecord.CreatedAt`) is newer than `now - worker-poll-interval`.

**Watcher**: unchanged.

**Tests**
- Journal rows for: fresh success (skipped, next run at `finished_at + interval`), stale success (runs), failed (runs), never (runs), new key (runs), and a cron entry before and after its fire time.
- Cleanup runs only for targets that ran.
- Failed-artifact filter: in-use and old (queued), in-use and recent (skipped), unused (skipped).

### PR 9: Chart: Deployment, replicas, PDB, anti-affinity

- Turn `templates/statefulset.yaml` into `templates/deployment.yaml`:
  - `replicas: {{ .Values.backend.replicaCount }}`
  - `strategy: RollingUpdate`, `maxSurge: 1`, `maxUnavailable: 0`
  - `terminationGracePeriodSeconds: 90`
  - `POD_IP` from `status.podIP`, plus a default `server.advertiseAddress: 'http://{{ env "POD_IP" }}:<port>'` in the rendered `suppline.yml`
  - The Trivy cache as an `emptyDir` with `sizeLimit` (`trivy.cache.sizeLimit`, default 15Gi)
- If `replicaCount > 1`: a `PodDisruptionBudget` with `minAvailable: 1`, and default required pod anti-affinity on `kubernetes.io/hostname`. `.Values.affinity` overrides the default.
- Document in NOTES.txt and the chart README that required anti-affinity with `maxSurge: 1` needs `replicaCount + 1` schedulable nodes; otherwise set `maxSurge: 0, maxUnavailable: 1`.
- Point the liveness and readiness probes at `/health` and `/ready` respectively. `/ready` is 503 while draining.
- Release notes (RELEASE.md / CHANGELOG): `helm upgrade` replaces the StatefulSet with a Deployment, which brings a short outage. Delete the orphaned `cache-*` PVCs.

### PR 10: Remove the unused Role

- Delete [rbac.yaml](../../charts/suppline/templates/rbac.yaml) and the `rbac.create` value. The ServiceAccount stays.

---

## Infrastructure repo (after PR 9 is released; not done here)

In `infrastructure/apps/suppline/values/values.yaml`:
- **Workload**:
  - `bundles: backend: deployment`, `backend.replicas: 2`
  - `strategy` set to RollingUpdate. Check how `standard-bundle` maps `strategy` for Deployments.
  - Pod anti-affinity on `kubernetes.io/hostname` in `affinity`.
  - `podDisruptionBudgets: [{name: suppline, minAvailable: 1, matchLabels: <bundle matchLabels>}]`
- **Container settings**:
  - Pin `tag` to a release.
  - Move the Trivy `cache` from `volumes` (longhorn-noreplica) to `additionalVolumes` as `emptyDir` with `sizeLimit: 15Gi`.
  - Add `POD_IP` through `additionalContainerSpec.env`, which already carries `TMPDIR` and `POSTGRES_URL`.
  - `terminationGracePeriodSeconds: 90` through `additionalTemplateSpec`.
  - Readiness probe to `/ready`.
- **Config**: in `catalog/suppline.yml`, `server.advertiseAddress: 'http://{{ env "POD_IP" }}:8080'`.
- **Alerts**:
  - Wrap the suppline expressions in `max(...)`, or `max by (repository)` where they are already grouped. Standbys don't export the business metrics, so this is only a guard.
  - Add `SupplineLeaderCount`: `sum(suppline_leader) != 1 for 2m`, warning.
- **Cleanup**: after the sync, delete PVC `cache-suppline-backend-0` (check the exact name) in namespace `suppline`.
- **Network**: if a NetworkPolicy covers `suppline`, allow pod-to-pod traffic on 8080.
- **kured**: no change, because the PDB covers drains.
- **Prerequisite tracked separately**: CNPG `instances: 3`, `enablePDB: true`, HA alerts back on, backups enabled.

## Verification after rollout

- `kubectl delete pod <leader>`: the API answers again within 30 s, `sum(suppline_leader) == 1`, and the new leader logs initial discovery.
- Drain the leader's node: the same, and the PDB keeps one pod.
- A CI job during a leader kill completes after re-POSTing.
- `pg_terminate_backend` of the leader's lock backend: the leader exits, and the standby leads within 10 s.
- `curl` against the standby pod IP returns the leader's data with `X-Suppline-Served-By` naming the leader.
