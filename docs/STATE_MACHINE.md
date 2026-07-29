# Image Lifecycle State Machine

How a single image digest moves through suppline, from upstream registry to a policy verdict the cluster can enforce.

## Full lifecycle

```mermaid
stateDiagram-v2
    direction TB

    [*] --> Mirrored : regsync sync from upstream

    Mirrored --> Watched : watcher poll resolves tag → digest

    Watched --> Skipped : digest unchanged and within rescanInterval<br/>or manual rescan already queued
    Skipped --> Watched : next poll

    Watched --> Queued : never scanned · digest changed<br/>interval elapsed · API rescan · startup replay

    Queued --> Scanning : worker dequeue (deduped by digest)

    Scanning --> Retrying : transient error
    Retrying --> Scanning : exponential backoff
    Retrying --> Abandoned : attempts exhausted
    Scanning --> ScanFailed : permanent error
    Scanning --> Vanished : MANIFEST_UNKNOWN

    Scanning --> Evaluating : SBOM + vulnerabilities

    Evaluating --> Attesting : passed or failed
    Evaluating --> Persisted : pending, attestation skipped
    Attesting --> Persisted : signatures pushed

    Persisted --> Passed : policy_status = passed
    Persisted --> Failed : policy_status = failed
    Persisted --> Pending : policy_status = pending

    Passed --> Watched : rescan interval or new digest
    Failed --> Watched : rescan, VEX update, policy re-eval
    Pending --> Watched : minimum release age reached
    ScanFailed --> Watched : manual rescan or startup replay
    Abandoned --> Watched : next poll
    Vanished --> [*] : state purged

    Mirrored : local registry holds the digest
    Watched : shouldScanImage gate
    Skipped : no task enqueued, alias tag may be bound
    Queued : ScanTask with repo, digest, tag, VEX
    Scanning : Trivy produces SBOM and CVEs
    Evaluating : VEX exemptions, then CEL expression
    Attesting : cosign SBOM, vuln, VEX, SCAI
    Persisted : SQLite scan record written
    Passed : deployable under verified-only admission
    Failed : blocked, evidence still published
    Pending : held below minimumReleaseAge, no attestation
    ScanFailed : error record, visible as failed in UI
    Abandoned : no record written, retried on next poll
    Vanished : digest gone from registry
```

## Watcher scan gate

`shouldScanImage` decides whether a polled tag becomes a queued task. It fails open: if the state lookup itself errors, the image is enqueued rather than silently skipped.

```mermaid
flowchart TD
    A[Tag digest from local registry] --> B{Scan record for this digest?}
    B -- no --> E[Enqueue: IsFirstScan]
    B -- yes --> C{Digest matches record?}
    C -- no --> F[Enqueue: fresh scan]
    C -- yes --> D{rescanInterval elapsed?}
    D -- yes --> G[Enqueue: IsRescan]
    D -- no --> H{Manual rescan pending?}
    H -- yes --> I[Skip, task already queued]
    H -- no --> J[Skip, up to date]
    B -. lookup error .-> K[Enqueue anyway, fail-open]
```

## Pipeline phases

The worker runs four phases per task. Each phase can end the task early.

| Phase | Does | Early exits |
|-------|------|-------------|
| Scan | Trivy SBOM + vulnerability scan | `MANIFEST_UNKNOWN` triggers digest cleanup; permanent errors record a failed scan |
| Evaluate | Apply active `not_affected` VEX, then the CEL expression | `pending` verdict sets `ShouldAttest=false` and skips attestation |
| Attest | cosign SBOM, vulnerability, VEX, and SCAI attestations | VEX attestation only when CVEs were exempted |
| Persist | Write scan record, vulnerabilities, tag bindings | Transient errors retry; permanent errors are logged without undoing attestations |

## Error handling

| Error class | Behavior | Resulting state |
|-------------|----------|-----------------|
| Transient | Retry with backoff up to `RetryAttempts` (default 3) | Recovers, or abandoned with no record |
| Permanent | No retry | `ScanFailed` record with `policy_status=failed` |
| Manifest not found | Cleanup of stored state for the digest | Removed from tracking |
| Unknown | Treated as permanent | `ScanFailed` |

## Policy terminals

| Status | Attested | Meaning | Typical cause |
|--------|----------|---------|---------------|
| `passed` | Yes | Gate open, deployable under verified-only admission | CEL expression true after VEX exemptions |
| `failed` | Yes | Gate closed, evidence still published for audit | CEL expression false, e.g. `criticalCount > 0` |
| `pending` | No | Held, re-evaluated on a later scan | `minimumReleaseAge` unmet or no age source available |

See [POLICY.md](POLICY.md) for CEL expressions and VEX semantics, and [CONFIGURATION.md](CONFIGURATION.md) for `rescanInterval` and `minimumReleaseAge`.
