# Plan: in-process malicious-package detection

Design and rationale: [ADR 0001](../adr/0001-in-process-malicious-package-detection.md). Terms: [GLOSSARY.md](../../GLOSSARY.md).

The work is split into four PRs. Each one is shippable alone, and each leaves `main` working.

## Facts from the code that shape the plan

- **The SBOM is never parsed today.** `GenerateSBOM` runs on every scan ([pipeline.go:152](../../internal/worker/pipeline.go)), but its raw CycloneDX output is passed only to `attestationPhase`. `ScanResult.SBOM` is declared but never set. go.mod has no CycloneDX, purl or osv-scalibr dependency.
- **go-git can't do this yet.** `gitops.Manager` only makes non-bare checkouts with a hard reset, `Auth.transport` is unexported, and `validateGitAuth` rejects an empty auth type, so anonymous cloning isn't possible.
- **Health has no "degraded" state.** Any non-healthy component makes `/health` return 503, and the Helm liveness and readiness probes both hit `/health`.
- **There are three engine construction sites:** per repository (`pipeline.go:850`), the default (`main.go:192`), and the vexaudit factory (`main.go:311`). vexaudit replays policy from the database (`vexaudit/audit.go:441`) to judge VEX statements; see PR 2 for why MAL findings stay out of that replay.
- **A digest has no single parent row.** Artifacts are unique on (repo, digest, tag), so a per-digest table can't cascade from one parent and needs explicit cleanup.
- **There's a periodic-job pattern to copy:** `vexaudit.Run` refreshes once, then runs on a ticker, and keeps an RWMutex snapshot.
- **`x-triage` sets the config precedent:** a top-level `x-` block, read once at startup and not hot-reloaded.

---

## PR 1: Matcher, feed sync, config and service (no effect on scans)

**`internal/malicious/` (new package)**
- `osv.go`: a minimal OSV record struct with `id`, `summary`, `withdrawn`, `affected[].package{ecosystem,name,purl}`, `affected[].versions` and `affected[].ranges[].{type,events}`.
- `ecosystem.go`: maps purl types to OSV ecosystems (`npm`→npm, `pypi`→PyPI, `gem`→RubyGems, `nuget`→NuGet, `cargo`→crates.io, `golang`→Go, `maven`→Maven, `composer`→Packagist), with name normalisation:
  - npm: `@scope/name`
  - PyPI: PEP 503 lowercase, `-` and `_` and `.` all become `-`
  - Maven: `group:artifact`
  - Go: module path
  - Packagist: `vendor/name`
- `index.go`: an immutable `Index` mapping ecosystem → normalised name → []entry. `Match(pkgs []Package) []Finding` checks the explicit `versions` first, then range events (`introduced`/`fixed`/`last_affected`; `introduced: "0"` with no fix means every version), comparing versions with `github.com/google/osv-scalibr/semantic`. Withdrawn entries are skipped.
- `sbom.go`: pulls `components[].purl` out of CycloneDX JSON, recursing into nested components, deduplicating, and keeping only mapped purl types. It parses with `github.com/package-url/packageurl-go` and a minimal struct, not cyclonedx-go.
- `source.go`: a shallow (depth 1), single-branch **bare** clone through go-git. `Fetch` returns `(oldCommit, newCommit)`, and `Diff(old, new)` returns the changed blob paths under `osv/malicious/**` and `osv/withdrawn/**` by tree diff, with no worktree. If a fetch fails because of the shallow clone, it deletes the clone and clones again. A full index is built by walking the tree at HEAD.
- `service.go`: `Service.Run(ctx)` follows the vexaudit pattern:
  - The initial clone and index build run in the background, and scanning does not wait for them.
  - A sync runs every `sync_interval`.
  - `Snapshot()` returns `{Index, Commit, SyncedAt, Status}`. Status is `unavailable` before the first load, and `stale` when `now - lastSuccess > stale_after`.
  - It exposes `OnUpdate(func(ctx, Update))`, where `Update` holds either the changed entries or `Full: true` for the first load or recovery from stale. Wiring this up happens in PR 3.

**Config: `x-malicious-packages`** (top level in `RegsyncConfig`, read at startup only, like `x-triage`)

```yaml
x-malicious-packages:
  enabled: true            # default true
  block: true              # default true: built-in policy gate
  repo:
    url: https://github.com/ossf/malicious-packages.git
    ref: main
    auth: {}               # optional; same shape as x-triage repos
  checkout_dir: /data/malicious-packages
  sync_interval: 1h
  stale_after: 6h
  ecosystems: [npm, PyPI, RubyGems, NuGet, crates.io, Go, Maven, Packagist]
```

- Validation that allows an empty auth (anonymous) but otherwise reuses the `GitAuthConfig` rules.
- Export the auth → transport path, either `gitops.Auth.Transport()` or by moving `triage.resolveAuth` into `gitops`, so both callers share it.

**Health and metrics**
- A `malicious_packages` health component that **always reports healthy** and gives the status, commit and age in its message (see facts above).
- Metrics (age is `time() - suppline_malicious_db_last_sync_success_timestamp_seconds`):
  - `suppline_malicious_db_last_sync_success_timestamp_seconds`
  - `suppline_malicious_db_sync_errors_total`
  - `suppline_malicious_db_packages{ecosystem}`

**Wiring:** start the service goroutine in `main.go` with the other background services (it stops on ctx cancel). Do nothing else with it yet.

**Tests**
- Table tests for ecosystem mapping and normalisation, and for version and range matching, including withdrawn entries and `introduced: 0`.
- SBOM extraction from a Trivy-shaped fixture with nested components and OS packages, where the OS packages must be ignored.
- `source` tests against a local `file://` repo built with go-git in a temp dir: first clone, a fetch with additions and withdrawals, and recovery by re-cloning.
- Config validation tests.

---

## PR 2: Persistence, pipeline, policy gate, SCAI, triage exclusion

**Types:** `types.MaliciousFinding{ID, Ecosystem, PackageName, Version, PURL, Summary, URL}` and `types.MaliciousCheck{Status, Commit, SnapshotAt, Findings}`. `ScanResult` and `ScanRecord` gain `Malicious *types.MaliciousCheck` (nil when the check is disabled).

**State store** (SQLite in `ensureSchemaColumns` plus inline DDL, Postgres in `ADD COLUMN IF NOT EXISTS` plus its statement list, and the `copy.go` lists for both)
- `scan_records`: add `malicious_status` (queryable for the PR 3 catch-up) and `malicious_check_json` (the whole check, findings included), following the existing `policy_failure_findings_json` pattern instead of a separate findings table. They are read by `GetLastScan` and `ListScans`; `copy.go` reads them only when the source SQLite has them.
- `package_inventory`: `(digest, ecosystem, name, version, purl)`, PK `(digest, purl)`, index `(ecosystem, name)`. It is replaced per digest at scan time. Cleanup:
  - delete by digest in `CleanupArtifactScans`
  - an orphan sweep, `DELETE … WHERE digest NOT IN (SELECT digest FROM artifacts)`, inside the existing cleanup paths (`CleanupRepository`, `CleanupOrphanedRepositories`, and the artifact-delete helper)
- New methods:
  - `ReplacePackageInventory`
  - `ListInventoryByPackage(ecosystem, name)`
  - `ListLatestScansWithMALStatus(statuses)`
  - `UpdateMALCheck(scanID, check)`
  - load MAL findings into `ScanRecord`

**Pipeline** ([pipeline.go](../../internal/worker/pipeline.go)): a new `maliciousPhase` between `scanPhase` and `policyPhase`.
- It extracts packages from the SBOM, writes the inventory, runs `Snapshot().Index.Match`, and sets `scanResult.Malicious` and `scanResult.MALCheck`.
- If the service is disabled, `MALCheck` is nil and nothing changes.
- If the SBOM fails to parse, the status is `unavailable` and a warning is logged.
- `converter.go` persists the status and the findings.

**Policy** ([policy.go](../../internal/policy/policy.go))
- Declare the CEL variables `malicious` (a list of maps) and `maliciousCount` in `NewEngine`, and fill them in both `Evaluate` and `evaluateSubset`.
- **The gate:** a `policy.WithMaliciousGate(bool)` option, passed at all three construction sites. After CEL runs in `Engine.Evaluate`, if the gate is on and `len(Malicious) > 0`, the result is failed and one `PolicyFailureFinding` is added per MAL finding.
- Add `Kind` (`vulnerability` | `malicious`) to `PolicyFailureFinding`. Existing JSON without it reads as `vulnerability`.
- The cooldown (`x-cooldown`, which replaced `minimumReleaseAge`) runs after the gate: a malicious match fails the scan during the cooldown, and the cooldown only holds a passing scan back. See [ADR 0001](../adr/0001-cooldown-holds-imports-in-the-tag-runway.md).
- `describe.go` is unchanged: its combined-clause wording ("No critical or malicious vulnerabilities") would be wrong, and the gate makes `maliciousCount` in expressions rare.
- vexaudit's `scanResult()` deliberately leaves MAL findings out. The audit asks whether a VEX statement changes the outcome; with the gate in the replay, every statement on an image with malware would look unused.

**SCAI** ([scai.go](../../internal/attestation/scai.go))
- Change `SCAIAttributeItem.Evidence` to `any`. The JSON for existing exempted-vulnerability attributes stays the same.
- Always add an attribute `malicious-package-check` whose evidence is `{status, snapshotCommit, snapshotAt, findings[]}`, but only when `MALCheck != nil`, i.e. when the feature is enabled.

**Triage exclusion**
- Skip `Kind == malicious` in `queuePolicyFailure` ([triage/service.go:350](../../internal/triage/service.go)), `noticeFromScan` ([api/handlers_triage.go:529](../../internal/api/handlers_triage.go)), [triage/resolve.go:128](../../internal/triage/resolve.go) and [api/triage_repositories.go:199](../../internal/api/triage_repositories.go).
- A test asserts that a scan whose only failure is MAL queues no triage jobs.

**Tests**
- Policy: gate on and off; CEL can read `malicious`; VEX can't exempt; describe output.
- Statestore: migrations on a fresh and an existing database for both dialects; inventory cleanup; copy.
- Pipeline with a fake snapshot.
- SCAI JSON golden test.
- (vexaudit: covered by the comment on `scanResult()`; no behaviour change.)

---

## PR 3: Re-matching and catching up after an outage

`malicious.Rematcher`, registered through `Service.OnUpdate`. It runs on its own goroutine: `Notify` never blocks the sync, queued updates are merged, and a full or dropped update makes the next run full.
- **Inventory names are stored normalised** (the index key), so an advisory finds images with one `(ecosystem, name)` lookup, e.g. `amzn_client` in the image vs `amzn-client` in the advisory.
- **Rescan rule:** a digest is rescanned (urgent, per repository holding it) only when an advisory now matches that its latest scan did not record. Withdrawn entries never trigger a rescan; the next normal rescan clears them.
- **Incremental update** (new or changed entries): for each entry's packages, `ListInventoryByPackage`, then match those digests against the changed entries only.
- **Full update** (first load, re-clone, or recovery from stale): match every digest with an inventory against the whole index. This also catches advisories published while suppline was down. A latest scan recorded as `unavailable` or `stale` with nothing new gets `UpdateMaliciousCheck` (status ok, current snapshot); its SCAI is not touched (ADR).
- **Store:** `ListInventoryDigests`, `ListInventoryByPackage`, `ListLatestDigestScans` (latest scan and one tag per repository), `UpdateMaliciousCheck`.
- **Metrics:** `suppline_malicious_rematch_rescans_total`. The `suppline_malicious_findings{repository,in_use}` gauge moves to PR 4, where the scan data it needs gets a count column.

**Tests:** real SQLite store with a fake feed: full catch-up (hit queues a rescan, clean late check is confirmed, known findings are not rescanned again), incremental hits including crates.io name normalisation, nothing done while unavailable, and update coalescing.

---

## PR 4: API, UI and docs

- **API:**
  - the new `ScanRecord` fields show up in `GET /scans/{digest}` (PascalCase, like today).
  - `GET /api/v1/malicious`: the feed's state (enabled, block, status ok/unavailable/stale, commit, last successful sync, last attempt and its error, sync interval, stale_after, repository and ref, active entries per ecosystem), how many current images were checked ok, unavailable, stale or not at all, and every current image with a malicious finding (repository, digest, tags, scanned at, whether it runs in a cluster, policy result, findings).
  - `/health` gains `maliciousEnabled`, like `mirrorEnabled`, so the sidebar shows the view only when the feature is on.
  - Update the swagger annotations, then run `make swagger`; never edit `build/swagger/` by hand.
- **Metrics:** `suppline_malicious_images_current{repository,in_use}` from the database collector (cached for a minute, like the CVE counts).
- **UI** (read [ui/AGENTS.md](../../ui/AGENTS.md) first):
  - add the types in `ui/src/lib/api.ts`
  - **a "Malicious packages" sidebar view** (`/malicious`, shown when enabled): feed sync state with a stale/unavailable warning, check coverage of current images, active entries per ecosystem, and the affected images grouped by package and by image, in-use first, linking to scan detail and osv.dev
  - in `ScanDetailPage.tsx`, show the MAL check status next to the attestation badges, plus a "Malicious packages" section listing the findings with links to osv.dev
  - give policy-failure rows with `Kind == malicious` their own label
- **Docs:**
  - `docs/CONFIGURATION.md`: the `x-malicious-packages` section
  - `docs/POLICY.md`: the `malicious` and `maliciousCount` variables and the gate
  - `README.md`: the health component, the metrics table, and the scan step in the pipeline description
  - `docs/STATE_MACHINE.md`: the re-match flow
- **Eval:** set `x-malicious-packages: { enabled: false }` in `suppline.demo.yml`.
- **Helm:** document that `/data` is an emptyDir when the bundled Postgres is enabled, so the feed is cloned again on restart.

---

## Open points (not blocking PR 1)

1. **Persisting the clone in Helm.** I recommend accepting a re-clone on each restart for now. A PVC just for the feed can come later if restarts are frequent.
2. **Check the upstream layout** (`osv/malicious/<ecosystem>/<name>/MAL-*.json`, `osv/withdrawn/...`) against the live repo before writing `source.go`.
3. **Run a purl spot-check on real images:** Trivy's SBOM for one npm-heavy and one Python image, to confirm the name normalisation.

## Validation

Run focused tests per PR (CGO is required for sqlite):

```bash
go test ./internal/malicious/... ./internal/config/... ./internal/gitops/...
```

```bash
go test ./internal/policy/... ./internal/statestore/... ./internal/worker/... ./internal/attestation/... ./internal/triage/... ./internal/vexaudit/...
```

Then `make test` and `make lint` before each PR. Run `make swagger` for PR 4.
