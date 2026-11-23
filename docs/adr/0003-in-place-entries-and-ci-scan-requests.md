---
status: accepted
---

# In-place entries and CI scan requests gate first-party builds without a mirror

Teams want their own CI builds to go merge → build → scan/SBOM → attest → deploy, with Kyverno verifying the attestation at admission. Before this, suppline could only scan what its mirror had copied on a schedule. A pipeline either waited for the next mirror pass (an hour in production) or deployed unscanned images from its own registry, and Kyverno had to exclude that registry. Mirroring first-party images also copied private source-bearing images into the mirror's registry for no benefit: unlike a third-party upstream, the CI registry is already ours.

We decided:

- **A top-level `in-place:` section, keyed by `repository`.** It is not a `sync` entry with a fake source. It takes only per-repository settings (tag filters, policy, VEX, rescan and attestation settings), and strict decoding rejects mirror settings. A repository is either a `sync` target or in-place, never both. Internally each entry becomes an ordinary per-repository record, so catalog, watcher, worker, triage and config edits need no second code path. The mirror only ever sees `sync`.
- **The watcher selects in-place tags itself**, with the same tag filters as the mirror (moved to `internal/tagselect`), plus every tag a cluster runs. Nothing filtered the repository before it reached the registry. Running tags keep being rescanned, so their SCAI `validUntil` keeps being renewed after newer builds leave the `newest` window.
- **No cooldown and no tag runway.** Cooldown protects against a compromised upstream release by holding it before it is published on a tag. An in-place repository publishes nothing, and its builds are our own.
- **Attestations are written where the image lives.** Kyverno already verifies any image against suppline's key, so the cluster pulls from the CI registry and only needs read access to the attestations there. In a repository suppline does not own, cleanup replaces only the attestation kinds suppline writes and leaves cosign signatures alone.
- **`POST /api/v1/scan-requests` queues an urgent scan and waits for the verdict.** It has its own queue tier ahead of discovery. The worker reports every finished task (after retries) to an observer, so a request also ends when a scan fails without persisting a record. Requests wait in slices (`wait`, capped at 10 minutes) and answer 202 with a poll path, so they work behind proxies with short read timeouts.
- **CI authenticates with OIDC ID tokens.** A GitLab `id_token` is verified against the issuer's JWKS, and its `project_path` must be listed in the entry's `scan-requesters`. No shared secret is stored in CI. ID tokens open the scan-request endpoints only.

## Considered Options

- **Keep mirroring first-party images and nudge the mirror from CI**: still copies private images into another registry, and the pipeline waits on a copy it does not need.
- **CI scans and signs itself** (Trivy plus cosign with a CI key): a second signer and a second copy of the policy (CEL, VEX, malicious packages), and nobody renews `validUntil` afterwards.
- **A per-entry `in-place: true` flag on `sync`**: keeps a meaningless `source`/`target` pair and the mirror's defaults, and every mirror loop would need to skip it.
- **A scoped static API key for CI**: simpler, but any project holding it could request scans of any repository, and it is one more secret to rotate.
- **Signer-aware attestation cleanup** (delete only referrers signed by suppline's key): needed only when CI also writes attestations of the same kinds. Left for later.

## Consequences

- The registry credentials for an in-place repository need write access, and delete access to replace attestations. Registry cleanup policies must keep cosign's `sha256-*` tags when the registry has no referrers API.
- A pipeline depends on suppline being up for new deploys. Running workloads and rollbacks to attested builds don't: Kyverno verifies signatures from the registry.
- A new critical CVE fails a running digest on its next rescan and replaces its passing SCAI. With pod-level admission, that blocks reschedules of the workload. Choose deploy-level admission for first-party workloads if that matters more than failing closed.
