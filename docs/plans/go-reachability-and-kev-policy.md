# Plan: Go symbol reachability in triage, and KEV in CEL policy

Two independent tracks. Each PR can ship on its own and leaves `main` working.

## Priority (decided 2026-11-26)

**Track B goes first. Track A is parked** (spike done, not scheduled). The decision rests on data from the internal-1 deployment (read-only queries, 2026-11-26):

- **KEV (Track B):** 131 of 2,329 currently passing scans contain a KEV-listed CVE with no VEX exemption. Examples: libxslt CVE-2026-125350 (66 scans), brotli CVE-2026-111497 at HIGH (25), git CVE-2025-48384 (16), glibc CVE-2023-4911 (1). Effort ~4–5 days including the UI (B4), low risk (it can only make a gate stricter), opt-in.
- **Go (Track A):** Go findings are 13 of 347 triage runs (about 3% of LLM tokens), and only 7 of 618 failing scans fail solely because of Go critical findings. With a ~23% decision rate, the rule would replace ~2 LLM jobs and almost never change a gate. Effort ~4–5 days (A1+A2), and a mistake writes a wrong `not_affected`.

Pick Track A back up if a deployment with mostly Go images asks for it, or as the LLM-free, scan-time follow-up, where it would apply to every Go finding instead of the few that reach triage. This is one deployment, mostly OS-package-heavy images; the KEV result likely holds elsewhere, the Go result depends on what people mirror.

- **Track A: Go reachability.** When no Go binary in the image contains code from the vulnerable package, triage writes a `not_affected` VEX statement without the model. The data comes from the Go vulnerability database (OSV format), which lists the affected packages and functions for each advisory. The spike (PR A0) narrowed this from function level to package level; see its results.
- **Track B: KEV in policy.** CEL policy can see whether a finding is on the CISA Known Exploited Vulnerabilities (KEV) list, so a policy can block a known-exploited finding whatever its severity.

## Facts from the code that shape the plan

- **Triage already has a rule path that skips the model.** `triageHeaders` ([kernel.go](../../internal/triage/kernel.go)) splits off header-only kernel findings before any model session, applies the KEV rule through `decideHeader`, and writes `vex-auto` statements with `rule:kernel-headers` provenance. Track A copies this shape as `rule:go-symbols`.
- **Images can already be unpacked.** `imageFS` / `UnpackImage` ([image_grep.go](../../internal/triage/image_grep.go), [registry/unpack.go](../../internal/registry/unpack.go)) unpacks one digest to a temp dir. Files over the per-file limit are left out and listed in `.suppline-skipped`. `isGoBinary` and `elfFile` exist. `imageFS` handles one digest, while `Job.InUse` can hold several.
- **Findings don't record their file path.** `types.Vulnerability` has no binary path or Trivy package type, so we can't tell which binary a Go finding came from. The rule has to check every Go binary in the image that embeds the affected module.
- **IDs differ.** Trivy reports Go findings as `CVE-*` or `GHSA-*`. The Go database keys records by `GO-*` and lists the others in `aliases`. Track A needs an alias index for Go records only. Full alias-aware VEX is a follow-up (see the end of this plan).
- **KEV lives only in triage.** `triage.KEVCache` ([kev.go](../../internal/triage/kev.go)) is a lazy, TTL-based set of CVE IDs, configured through `x-triage.kev_feed_url` / `kev_cache_ttl` and used only when `block_kev` is on. Policy can't see it.
- **CEL inputs are built in one place.** `Engine.Evaluate` ([policy.go](../../internal/policy/policy.go)) builds the `vulnerabilities` maps and counts. The CEL environment is declared in `NewEngine`. Engines are built in three places: per repository (worker pipeline), the default (`main.go`), and the vexaudit factory. vexaudit replays policy from the database.
- **There's a "feed changed, re-check images" precedent.** `malicious.Rematcher` ([rematch.go](../../internal/malicious/rematch.go)) diffs feed updates and queues urgent work for the affected digests.

---

## Track A: Go reachability (parked; see Priority)

### PR A0: Spike results (2026-11-26)

Run with govulncheck v1.10.0 (the latest), Go 1.27, fixture modules served from a local file `GOPROXY` with a hand-written vuln DB, plus the Go binaries from 12 older public images (coredns, cert-manager, external-dns, traefik, loki, kube-state-metrics, ingress-nginx, flux source-controller, prometheus, argocd, vault, metrics-server): 18 Go binaries in all.

**The plan as first written doesn't hold. govulncheck's symbol level can't be the basis of the rule:**

1. **Most real binaries are stripped, and govulncheck gives up on them.** 13 of the 18 binaries have no `.symtab` (`-s -w`; ko and goreleaser builds). govulncheck finds inlined functions through the symbol table, so for a stripped binary it reports *every* vulnerable symbol in the module as called ([golang/go#57764](https://github.com/golang/go/issues/57764), `internal/vulncheck/binary.go`). Nothing in the JSON says it fell back. A rule built on govulncheck symbols would decide nothing for 9 of the 12 images.
2. **Generics are missed. This is a false negative.** `parseName` keeps the instantiation suffix (`GenBig[go.shape.string]`), so it never equals the advisory's `GenBig`. A called, non-inlined generic function is reported as "not called". Still unfixed on x/vuln master. No real hit in the 5 unstripped binaries, but it's a correctness bug in exactly the direction that matters.
3. **Inlining works otherwise** (unstripped only): inlined functions and methods are found through the inline tree. An inlined call that constant-folds to nothing leaves no trace. That's arguably true "code not present", and it's the same for any approach based on the binary.
4. **Records without symbols:** any linked code from the package counts as present. As expected.
5. **Offline DB:** `https://vuln.go.dev/vulndb.zip` (3.7 MB) unzips to exactly the `-db file://` layout. No index generation needed.
6. **In-process:** `scan.Command` works (prometheus: 0.54 s, same output as the CLI). It adds ~13 MB of binary and `golang.org/x/{vuln,tools,telemetry}`. Telemetry counters are no-ops unless the host opens telemetry.

**What does work: package presence from the pclntab file table.** Stripping removes `.symtab` but not `.gopclntab`. Its file table lists the source file of every function compiled in, *including inlined ones*. Stdlib `debug/elf` + `debug/gosym` reads it in a few lines. "No file from the vulnerable package's directory" means "no code from that package in the binary".
- On fixtures it gives the same answer as govulncheck's unstripped analysis for default, stripped and `-trimpath` builds, inlining included.
- On the 5 unstripped real binaries: **zero cases** where govulncheck saw a package the file table called absent. This only held after decoding the module cache's case escaping (`!azure` → `Azure`). Without that, vault produced two false "absent" results. That is the main thing to get right in the implementation.
- **Yield:** of 2,410 applicable (binary, advisory) pairs, **619 (26%)** have no code from the vulnerable package in the binary. With the anti-obfuscation guard below, **549 (23%)**. Per binary: 9–39%, lowest on flux source-controller (6/202) and vault (9/173).

**Decision:** Track A uses the file table, not govulncheck. No x/vuln dependency, stripped binaries are covered, and the generics bug doesn't apply. Symbol-level precision (govulncheck) becomes a follow-up, gated on the generics fix and only useful for unstripped binaries (about +10–20% decisions on those).

### PR A1: Go vuln DB sync (no effect on triage)

- New `internal/govulndb`: download `vulndb.zip` on an interval, unpack into a fresh dir, swap the snapshot atomically, and keep the last good copy if a sync fails. Copy `malicious.Service` for `Run`, `Snapshot`, and the `unavailable`/`stale` statuses.
- An in-memory index:
  - `CVE-*`/`GHSA-*` → `[]GO-*` (from `aliases`);
  - `GO-*` → affected modules, version ranges, and `ecosystem_specific.imports[].path`;
  - stdlib maps to Trivy's `stdlib` package name.
- Config: top-level `x-go-vulndb` with `enabled`, `url` (so air-gapped installs can point at an internal mirror of `vulndb.zip`), `sync_interval` and `stale_after`. Read once at startup, like `x-malicious-packages`.
- Metrics and health follow the malicious feed: report a stale or unavailable feed, but don't fail `/health`.

### PR A2: `rule:go-packages` in triage

- New `internal/gobinary` (stdlib only): given an ELF file, return the Go build info (module list, Go version) and the set of package directories from the pclntab file table. Normalise each path:
  - drop the `@version` segments;
  - decode module cache case escaping (`!x` → `X`);
  - keep `vendor/` and GOROOT (`…/src/net/http`) paths as they are.
  
  A package is **present** if any normalised directory equals its import path or ends with `/`+path. Over-matching only makes the rule more cautious; under-matching is the danger.
- Add `triageGoPackages` next to `triageHeaders`, in the same pre-model split. A job is **eligible** when its ID resolves to ≥1 `GO-*` record and every package fact (`Job.Packages` and every `InUse` digest's packages) is `stdlib` or a module that record covers.
- For each in-use digest (capped by a setting, e.g. 5; any more and the job goes to the model): unpack it, find the Go binaries (ELF + build info), and check each binary whose build info contains the affected module at an affected version.
- **Conclude `not_affected` / `vulnerable_code_not_present` only when all of these hold:**
  - every affected record lists `imports`, since a record without them can't be decided;
  - no relevant binary on any in-use digest has a file from any listed import path;
  - **obfuscation guard:** each affected module (`runtime` for stdlib) has at least one file under its real path in that binary. A garble-style build renames files and would otherwise look like "nothing present". This costs ~3% of decisions in the sample;
  - `.suppline-skipped` lists no file that could be an ELF binary (when we can't check a file, we don't assume it's safe);
  - every binary had a readable `.gopclntab` (not gccgo or TinyGo);
  - the DB snapshot is not `unavailable`.
- KEV rule: the same as `decideHeader` (a KEV hit or a KEV feed error → reject/flip, not exempt).
- Anything else → hand the job to the model, and add the result as context in its prompt ("`net/http` code is present in `/usr/bin/foo`"). That's useful evidence for the model either way.
- Provenance detail: rule name, DB `modified` timestamp, the GO IDs, the binaries checked per digest, and which packages were looked for. Expiry: the usual `vex-auto` expiry.
- Cache results per (digest, GO ID, DB modified time) so a recheck doesn't unpack again.
- Tests, from the spike fixtures (rebuild them in `testdata` with a generator script rather than committing binaries):
  - present / absent / inlined / constant-folded;
  - default / `-s -w` / `-trimpath`;
  - a case-escaped module path (`github.com/!azure/...`);
  - vendored build;
  - stripped binary with obfuscated file names;
  - multiple digests with mixed results;
  - skipped large binary;
  - KEV hit;
  - stdlib CVE mapping.

### PR A3: Docs

- [STATE_MACHINE.md](../STATE_MACHINE.md) triage section, [CONFIGURATION.md](../CONFIGURATION.md) `x-go-vulndb`, and the README triage step.

---

## Track B: KEV in CEL policy (first)

### PR B1: Shared KEV feed (implemented on `feat/kev-feed-service`)

- `internal/kev`: a `Catalog` (CVE → `dateAdded`, `dueDate`, ransomware flag) and a `Service` shaped like `malicious.Service` (sync at start, then on a ticker, RWMutex snapshot, health message, metrics). `triage.KEVCache` is gone.
- Snapshot status: `ok`, `stale`, `unavailable`, or `disabled` (nil service).
- `Contains` keeps triage fail-closed: no catalog or a stale one is an error, not "not listed". Triage starts with a lookup that always errors until `SetKEV` installs the shared feed.
- Config: top-level `kev` (the repo dropped the `x-` prefix; the other blocks are `triage` and `malicious-packages`) with `enabled`, `feed_url`, `fallback_url`, `sync_interval` (6h), `stale_after` (48h). Without the block, `triage.kev_feed_url` / `kev_cache_ttl` still apply. `enabled: false` while triage needs KEV refuses to start.
- Runs on **every instance**, not only the leader: the API on a standby calls `KEVBlocked` for VEX expiry facts and would otherwise log a warning per CVE, and B4 needs the catalog there too.
- Behavior change for triage: it used to refetch lazily every 12h and reject on any fetch failure. Now a failed sync keeps the last catalog until `stale_after`.
- Air gap: `enabled: false` or an internal mirror URL. Nothing else in the pipeline needs internet access.

### PR B2: CEL variables (implemented)

Done as planned, plus `kernelHeaderPackage` on each vulnerability (option 2 below). Option 1 (let the header rule exempt KEV-listed kernel CVEs) is not done: it loosens a triage guardrail and needs a decision. The kev package was split: `internal/kev` holds the catalog types with no dependencies, `internal/kev/feed` the syncing service, because `observability` imports `policy` and the policy engine needs the catalog types.


- Per vulnerability: `kev` (bool), `kevDateAdded` (string, `""` if not listed), `kevRansomware` (bool).
- Top level: `kevCount` (KEV findings without an active VEX exemption) and `kevStatus` (`ok`/`stale`/`unavailable`/`disabled`). With `kevStatus`, the policy author decides between failing closed and failing open, e.g. `kevCount == 0 && kevStatus in ["ok", "stale"]`.
- The default policy doesn't change. Nothing behaves differently until someone references these variables.
- **Decide before coding: kernel-header KEV findings.** On internal-1, about 110 of the unexempted KEV findings in passing scans are kernel CVEs reported against `linux-libc-dev`. That package ships headers only, and a container runs the node's kernel, so these aren't real exposure. But `decideHeader` refuses to write VEX for a KEV-listed CVE when `block_kev` is on, so a plain `kevCount == 0` policy would fail those images, and only a hand-written VEX statement could clear them. Options:
  1. **Let the header rule write VEX even for KEV-listed CVEs** (recommended). The KEV refusal exists to stop the *model* from waving away exploited CVEs. The header rule is deterministic and its verdict ("no kernel code in the image") doesn't depend on exploitation. This needs triage enabled, and the image must be running and failing for triage to see it, so it pairs with option 2 for images outside triage.
  2. **Add a per-finding `kernelHeaderOnly` field to CEL** (reusing `kernelHeaderPackage`) so a policy can write `vulnerabilities.exists(v, v.kev && !v.exempted && !v.kernelHeaderOnly)`. Works without triage, but every policy author has to know about it.
  
  Doing both is cheap. Settle this with the user before B2.
- Add the KEV lookup as an `Option` in all three engine construction sites, including the vexaudit replay, so the audit judges with the same inputs.
- Docs: new variables and a "block known-exploited" example in [POLICY.md](../POLICY.md). UI work is in PR B4.

### PR B3: Re-evaluate when KEV grows (implemented)

Done as planned, with one simplification: whether a repository's policy reads KEV is a regex over its expression (`policy.UsesKEV`), not an AST walk. A false match only costs an extra rescan. The first catalog load is not treated as additions, so a restart does not rescan anything.


- On each refresh, diff the CVE set. For newly listed CVEs, find the digests with that finding and queue a **policy re-evaluation** (not a rescan) for them, the way `malicious.Rematcher` does.
- Skip this when no active policy references `kev`, `kevCount`, `kevRansomware` or `kevDateAdded` (check the compiled AST once per engine).
- This matters because the same day a CVE goes on the list, an image that passed policy should fail, not on its next rescan interval.

### PR B4: KEV in the UI (implemented)

Done as planned. Differences: the dashboard numbers come from a new `GET /api/v1/kev` (the dashboard has no single endpoint), `/health` also carries `kevStatus` so the Vulnerabilities view can warn without the heavier overview call, and the card also shows how many affected images passed policy.


KEV gets no page of its own, unlike malicious packages. A malicious finding is removed rather than triaged and has its own exemption rule, so it needs its own page. A KEV finding is an ordinary vulnerability with one extra fact, triaged with the normal VEX flow, so it belongs in the existing views. B4 can ship before B2: it shows exposure before anyone changes a policy. On internal-1 that's 131 passing scans today.

**Backend**
- `/health`: `kevEnabled`, like `maliciousEnabled`, plus the feed status (`ok`/`stale`/`unavailable`) and the last sync time.
- Vulnerabilities query: a `kev=true` filter. Pass the feed snapshot's CVE IDs into SQL (`cve_id = ANY($1)`). Each returned vulnerability gets `kev`, `kevDateAdded` and `kevRansomware`.
- Dashboard data: the number of current images with ≥1 KEV finding not exempted by VEX, and how many of those are running in a cluster (the same runtime-usage source the malicious page uses).
- Scan detail: the same three KEV fields on each vulnerability.

**Frontend** (follow [ui/AGENTS.md](../../ui/AGENTS.md))
- Dashboard: a "Known exploited" `SummaryCard` next to "Policy Failures". It shows the image count with the running count as its detail, links to `/vulnerabilities?kev=true`, and is hidden when `kevEnabled` is false.
- Vulnerabilities page: a "Known exploited only" filter in `PageFiltersBar`, kept in the URL so the dashboard link works, and a KEV badge on rows. The badge tooltip shows the date added and whether the CVE is known to be used in ransomware campaigns.
- Scan detail: the same badge in the vulnerability table, next to `SeverityBadge`.
- Feed warning: when the feed is `stale` or `unavailable`, the card and the filtered list show a warning (copy `maliciousFeedWarning`), so an empty list doesn't look like "nothing exploited".
- Tests: a filter round-trip through the URL, the card hidden when disabled, and the warning states.

Effort: ~1–1.5 days.

---

## Possible follow-ups (not in this plan)

- **Alias-aware VEX.** Use OSV `aliases` so a statement for `CVE-X` also covers the same flaw reported as `GHSA-Y`, in policy, the VEX audit and the vulnerabilities view. Track A's Go-only alias index is a first piece of this.
- **Withdrawn advisories.** Flag findings whose OSV advisory has a `withdrawn` date, and list VEX statements that are now pointless.
- **OSV cross-check for language packages.** Match the SBOM's language packages against osv.dev's per-ecosystem `all.zip`, reusing the malicious matcher, to catch gaps or lag in the Trivy DB.
- **osv.dev links.** Point `GHSA-`/`GO-`/`PYSEC-` IDs at `osv.dev/vulnerability/<id>` in [vulnurl](../../internal/vulnurl/vulnurl.go).
- **Function-level precision for Go.** Add govulncheck's symbol check on top of the package check, only for unstripped binaries, and only once x/vuln matches generic functions (report the `parseName` bug upstream; it's a one-line fix). Spike estimate: about +10–20% decisions on unstripped binaries.
- **Run the Go rule without an LLM, at scan time.** Right now it only runs when triage is enabled and only for images running in a cluster. A deterministic rule could run for every scanned image.
- **Compare Trivy with a second scanner.** Run osv-scanner next to Trivy on a sample of mirrored images and compare the findings. That gives real data for deciding whether to depend on OSV more, or replace Trivy.
