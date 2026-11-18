---
status: accepted
---

# Detect malicious packages in-process from ossf/malicious-packages

Trivy has no data on known-malicious packages. trivy-db ingests only GitHub's *reviewed* advisories, not its malware advisories, and has no ossf/malicious-packages source. suppline therefore matches the language-package purls from Trivy's CycloneDX SBOM against the OSV `MAL-*` entries itself, inside the suppline process. The data comes from a shallow, bare go-git clone of [ossf/malicious-packages](https://github.com/ossf/malicious-packages), synced hourly and indexed in memory. Versions are compared with osv-scalibr's `semantic` package. Trivy remains the only source of vulnerabilities. The MAL check covers only the gap Trivy leaves.

## Considered options

- **osv-scanner binary on the SBOM or the image.** Rejected. It adds a second scanner binary, has no server mode, and its offline database is a set of per-ecosystem zips (npm alone is 222 MB) that must be redownloaded to update. It also reports ordinary vulnerabilities that alias Trivy's CVEs, so we would be filtering most of its output away.
- **osv.dev bucket zips with `modified_id.csv` increments.** Viable, but the image already ships go-git for the gitops integration, and a git tree diff gives "what changed since the last sync" without extra bookkeeping.
- **OSV.dev API.** Rejected. suppline must work without outbound internet access, so the source has to be mirrorable. `repo.url` can point at an internal mirror.
- **Merging all OSV findings with Trivy's.** Rejected. Deduplicating aliases (CVE/GHSA/PYSEC) across two scanners, with conflicting severities and fixed versions and with VEX keyed to the wrong id, is a swamp.

## Decisions a future reader might "fix"

- **MAL findings are not vulnerabilities.** They have no severity, sit in their own `malicious` list in CEL, and stay out of `vulnerabilities` and the severity counts. LLM triage never sees them.
- **False positives are exempted with VEX `false_positive`, by hand only.** On production data, OpenSearch Dashboards matched MAL-2025-9145: it bundles its own workspace package `@opensearch/datemath@5.0.3`, and someone published a malicious npm package with exactly that name and version (dependency confusion). Advisories cover every version, so waiting for upstream to withdraw is not an option, and with the gate on, a policy filter cannot override it either. So the existing VEX machinery handles it (per repository, with expiry, attested, audited), restricted as follows:
  - only state `false_positive` exempts a MAL id ("the image does not contain the malicious package"); `not_affected` with a MAL id is rejected at config validation, because "present but not reachable" is no defence for a package with install scripts;
  - only hand-written `x-vex`; `x-vex-auto` with a MAL id is rejected, so the model never exempts malware;
  - exempted findings stay visible (CEL `malicious[].exempted`, SCAI, UI) and do not count in `maliciousCount` or the gate;
  - the VEX audit judges these statements on presence (is the advisory still matched by a current, checked scan of the repository?), not by replaying policy.
- **The block is a built-in gate, not CEL.** With `x-malicious-packages.block: true` (the default), any MAL finding fails the policy whatever the `x-policy` expression says. Every install writes its own expression, so blocking through CEL alone would depend on everyone remembering to add it.
- **The check fails open.** If the index is unavailable (still building at startup, sync broken) or stale (no successful sync for `stale_after`, default 6h), the scan still completes. The status (`ok`, `unavailable` or `stale`) is recorded on the scan, in SCAI, on the health endpoint and in metrics. Scanning does not wait for the index at startup.
- **Re-matching instead of waiting for rescans.** Each digest's language-package purls are stored at scan time. After every sync, and after the first index load, they are re-matched, and only digests with a new hit are rescanned (high priority). This covers every tracked digest, not only those in use. Without it, an advisory published today would only take effect at the next `rescanInterval`, which defaults to 7 days.
- **SCAI records what was known when it was signed.** It always carries the check status and the database snapshot, even when the image is clean. When a late re-match finds an image clean, its database record is updated, but the signed SCAI is not refreshed until the next normal rescan. Re-signing every image after each restart would cause a rescan storm.

## Consequences

- Storage grows by the bare clone (a few hundred MB under `/data`) and a per-digest package table. In the default Helm install (bundled Postgres), `/data` is an emptyDir, so the clone is fetched again after every restart. Fail-open and re-matching cover that gap.
- The health component always reports `healthy` and gives the check status in its message. The health endpoint has no "degraded" state, and any unhealthy component fails the liveness probe. A stale feed must not restart the pod, because a restart would throw away the clone. Staleness is alerted on through metrics.
- MAL covers language ecosystems only (npm, PyPI, RubyGems, NuGet, crates.io, Go, Maven, Packagist). OS packages are never checked.
