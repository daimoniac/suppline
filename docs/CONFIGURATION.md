# Configuration Reference

Complete reference for all configuration options in suppline.

## Table of Contents

- [Configuration Sources](#configuration-sources)
- [Secrets (environment variables)](#secrets-environment-variables)
- [Runtime settings](#runtime-settings)
- [Sync configuration](#sync-configuration)
- [Examples](#examples)
- [Triage (`triage`)](#triage-triage)
- [Malicious packages (`malicious-packages`)](#malicious-packages-malicious-packages)

## Configuration Sources

suppline has two configuration sources:

1. **`suppline.yml`** — everything that is not a secret: runtime settings (ports, base path, log level, Trivy, store, attestation), defaults, sync entries, policy, VEX, triage and malicious-package detection. `SUPPLINE_CONFIG` holds its path.
2. **Environment variables** — secrets only, plus `SUPPLINE_CONFIG`. `suppline.yml` can pull further secrets in with `{{ env "NAME" }}` (see [Credentials Section](#credentials-section)).

The file is parsed strictly: an unknown or misspelled key is a startup error, so a renamed setting never silently drops out.

suppline reads `suppline.yml` at startup and checks that same file every 15 seconds. A change that still parses replaces the running configuration, and current scans of repositories whose decision changed are queued again. A repository the change adds is discovered at once instead of on the next full discovery pass. Discovery, rescan intervals, attestation toggles, API tasks and policy all read the running configuration, so they follow the change. When the change touches what the mirror copies (sync entries, credentials or mirror defaults), the mirror stops its schedule and starts a new one from the new file, beginning with a pass over missing tags; VEX and policy edits leave it running. The chart mounts the ConfigMap at `/config` without `subPath`, so kubelet refreshes the file and the running process picks it up. Credentials used by discovery and cosign, triage settings, and the runtime settings below stay as they were at startup until the process restarts. A Helm upgrade that changes the chart config still restarts the pod. A triage accept updates memory immediately. The reload applies when the file bytes change. An older ConfigMap that arrives before that accept is published drops the statement until a later file contains it.

## Secrets (environment variables)

| Variable | Required | Description |
|----------|----------|-------------|
| `SUPPLINE_CONFIG` | no (default `suppline.yml`) | Path to `suppline.yml` |
| `SUPPLINE_API_KEY` | yes, unless `server.allowNoAuth` | API key for the UI and API. The cluster-inventory webhook and cluster list stay unauthenticated |
| `ATTESTATION_KEY` | yes | Base64-encoded cosign private key |
| `ATTESTATION_KEY_PASSWORD` | if the key is encrypted | Password for `ATTESTATION_KEY` |
| `POSTGRES_URL` | yes | PostgreSQL connection URL, e.g. `postgres://user:pass@host:5432/suppline?sslmode=disable` |
| `TRIVY_TOKEN` | no | Token for the Trivy server |
| `SUPPLINE_LLM_API_KEY` | no | Bearer token for the Triage OpenAI-compatible endpoint. If `triage.enabled` is true and this is empty, Triage stays off |
| `SUPPLINE_GITHUB_TOKEN` | no | GitHub token for Triage code and commit search. A generic `GITHUB_TOKEN` is ignored |

A `.env` file in the working directory is loaded before these are read.

## Runtime settings

Top-level sections of `suppline.yml`, read once at startup. Every key is optional; the values shown are the defaults.

```yaml
server:
  port: 8080            # web UI, REST API and Swagger
  basePath: ""          # serve everything under a prefix, e.g. /suppline (see below)
  readOnly: false       # disable write operations, including rescans
  allowNoAuth: false    # start without SUPPLINE_API_KEY; isolated evaluation only
  oidc:                 # accept CI ID tokens on the scan-request endpoints (optional, off when unset)
    issuer: https://gitlab.com
    audience: https://suppline.example.com
    claim: project_path # token claim matched against an in-place entry's scan-requesters
  advertiseAddress: ""  # URL other instances use to reach this one, e.g. http://10.0.3.7:8080 (default: first non-loopback IPv4 + port)

observability:
  logLevel: info        # debug, info, warn, error
  port: 9090            # /metrics, /health, /ready, /live

mirror:
  enabled: true         # copy sync entries into the target registry in-process

scanner:
  server: localhost:4954  # Trivy server, host:port
  timeout: 5m           # per scan
  insecure: false       # skip TLS verification / allow HTTP registries (eval only)
  localFallback: true   # retry a failed server-mode scan locally

attestation:
  commandTimeout: 2m    # per cosign invocation
  allowHttpRegistry: false  # pass --allow-http-registry to cosign (Compose eval / HTTP registries only)
  newBundleFormat: true # Cosign v3 protobuf bundles via OCI referrers; false writes classic sha256-<digest>.att tags
```

Queue and worker tuning stays under `defaults` (`rescanInterval`, `worker-poll-interval`, `worker-concurrency`, `worker-urgent-concurrency`, `worker-retry-attempts`, `worker-retry-backoff`, `queue-buffer-size`).

`worker-urgent-concurrency` (default 3) starts workers that take only scan requests, on top of `worker-concurrency`, so a CI job never waits for discovery scans or rescans to finish. `0` reserves none; scan requests then still go first, but wait for a regular worker.

**`server.advertiseAddress`** matters only with more than one instance. Instances share one PostgreSQL database and elect a leader with an advisory lock; only the leader runs the watcher, worker, mirror, triage and the other background jobs. The leader writes this address to the database; a standby forwards every request on the API port (API, UI, Swagger) to it and marks responses with `X-Suppline-Served-By`. With no reachable leader a standby waits up to 10 s, then answers 503 with `Retry-After`. A request that fails because PostgreSQL dropped the connection, as in a switchover, also gets 503 with `Retry-After` instead of 500, so clients can retry it. Instances must reach each other on `server.port`. In Kubernetes set it from the pod IP: `advertiseAddress: 'http://{{ env "POD_IP" }}:8080'`. See [ADR 0004](adr/0004-warm-standby-with-postgres-leader-election.md).

**`server.basePath`** must start with `/`; a trailing `/` is ignored. suppline serves the UI, API and Swagger under it and expects proxies to forward paths unchanged (no prefix stripping); requests outside the prefix get 404. The Helm chart uses it as the ingress path.

### State store

suppline keeps its state in PostgreSQL and refuses to start without `POSTGRES_URL`
(for example `postgres://user:pass@host:5432/suppline?sslmode=disable`). SQLite
support was removed; a leftover `store:` section in `suppline.yml` fails startup.
The default rescan interval is `defaults.rescanInterval` (7 days when unset).

Compose and the Helm
chart default to a bundled PostgreSQL 18 instance. Official 18 images store data
under `/var/lib/postgresql/18/docker`; Compose and the chart mount
`/var/lib/postgresql`. Existing PostgreSQL 16 volumes cannot be reused.

## Sync configuration

Besides the runtime settings, `suppline.yml` defines registry credentials, sync entries, in-place entries, and VEX (Vulnerability Exploitability Exchange) statements. The `creds`, `defaults` and `sync` fields follow regsync's names; suppline copies those entries in-process. `suppline-ignore` does not stop copying. `in-place` entries are never copied: suppline scans and attests them in the registry they were pushed to (see [In-place entries](#in-place-entries)).

### File Structure

```yaml
version: 1

# Registry credentials
creds:
  - registry: string          # Registry hostname
    user: string              # Username or token name
    pass: string              # Password or token value
    repoAuth: bool            # Use repository-scoped authentication
    reqPerSec: int            # Rate limit (requests per second)
    reqConcurrent: int        # Concurrent request limit
    tls: string               # optional: enabled (default), insecure, or disabled (HTTP)

# Default settings
defaults:
  parallel: int               # Parallel sync operations
  rescanInterval: string    # Default rescan interval (e.g., "7d", "24h")
  createVulnerabilityAttestation: bool  # Publish a cosign vulnerability attestation (default: true)
  createSBOMAttestation: bool           # Publish a cosign SBOM attestation (default: true)
  policy:                   # Default policy
    expression: string        # CEL expression
    failureMessage: string    # Custom failure message
  vex:                     # Default VEX statements (optional)
    - id: string              # CVE identifier
      state: string           # Analysis state (not_affected, affected, in_triage, false_positive, resolved, resolved_with_pedigree)
      justification: string   # Justification (required when state is not_affected)
      detail: string          # Explanation / reason
      expires_at: string      # RFC3339 timestamp or date (YYYY-MM-DD) (optional)

# Sync entries
sync:
  - source: string            # Source repository
    target: string            # Target repository
    type: string              # Type: "image" or "repository"
    schedule: string          # Cron schedule (optional)
    tags:                     # Tag filters (optional)
      allow: [string]           # Anchored regexes a tag must match
      deny: [string]            # Anchored regexes that drop a tag
      semverRange: [string]     # Semver ranges; several are OR
      newest: int               # Keep only the N tags built last (optional)
    cleanupKeepRunning: bool  # Cleanup keeps tags a cluster runs (default: false)
    suppline-ignore: bool   # If true, the entry is only mirrored: no scan, policy, or attestation (default: false)
    rescanInterval: string  # Rescan interval override (optional)
    createVulnerabilityAttestation: bool  # Override the default for this entry (optional)
    createSBOMAttestation: bool           # Override the default for this entry (optional)
    policy:                 # Policy override (optional)
      expression: string
      failureMessage: string
    vex:                    # VEX statements (optional)
      - id: string            # CVE identifier
        state: string         # Analysis state
        justification: string # Justification (for not_affected state)
        detail: string        # Explanation / reason
        expires_at: string    # RFC3339 timestamp or date (YYYY-MM-DD) (optional)

# In-place entries: scanned and attested where they live, never copied
in-place:
  - repository: string        # Repository, e.g. registry.gitlab.com/group/app (no tag or digest)
    tags:                     # Same tag filters as sync entries (optional)
      allow: [string]
      deny: [string]
      semverRange: [string]
      newest: int
    scan-requesters: [string] # CI identities allowed to request scans (optional)
    rescanInterval: string
    scaiValidityExtension: string
    createVulnerabilityAttestation: bool
    createSBOMAttestation: bool
    policy: {expression: string, failureMessage: string}
    vex-repo: bool
    vex: [...]                # Same statements as on sync entries
    vex-auto: [...]           # Written by triage
```

### Credentials Section

Credentials support Go template syntax for environment variable expansion, allowing you to keep secrets out of configuration files.

**Template Syntax:**
- Use `{{ env "VAR_NAME" }}` to expand environment variables
- Quotes are required around the template expression in YAML
- If no template syntax is present, values are used as-is

**Examples:**

```yaml
creds:
  # Using environment variables (recommended for secrets)
  - registry: registry-1.docker.io
    user: '{{ env "DOCKER_USERNAME" }}'
    pass: '{{ env "DOCKER_PASSWORD" }}'
    repoAuth: false
    reqPerSec: 10
    reqConcurrent: 10
  
  - registry: docker.io
    user: '{{ env "DOCKER_USERNAME" }}'
    pass: '{{ env "DOCKER_PASSWORD" }}'
    repoAuth: false
    reqPerSec: 10
    reqConcurrent: 10

  # Local HTTP registry (Compose eval / lab only)
  - registry: registry:5000
    tls: disabled
  
  # Plain text credentials (not recommended for production)
  - registry: registry.example.com
    user: admin
    pass: secretpassword
    repoAuth: false
```

**Environment Variables:**
```bash
export DOCKER_USERNAME=myusername
export DOCKER_PASSWORD=dckr_pat_xxxxxxxxxxxxx
```

**Security Best Practices:**
- Always use environment variables for credentials in production
- Never commit credentials to version control
- Use Kubernetes Secrets or similar secret management systems
- Rotate credentials regularly

### Sync Entries

```yaml
sync:
  # Sync entire repository
  - source: nginx
    target: myregistry.example.com/nginx
    type: repository
  
  # Sync with tag filters
  - source: alpine
    target: myregistry.example.com/alpine
    type: repository
    tags:
      semverRange:
        - ">=3.18.0"
      deny:
        - "latest"
  
  # Keep only the newest builds of a CI-tagged repository
  - source: registry.example.com/team/app
    target: myregistry.example.com/app
    type: repository
    tags:
      allow:
        - 'sha[0-9a-f]{8,}'
      newest: 30
  
  # Temporarily skip an entry without removing it
  - source: legacy-app
    target: myregistry.example.com/legacy-app
    type: repository
    suppline-ignore: true
```

### Newest tags

`tags.newest: N` keeps only the N tags whose images were built last. Use it for repositories that CI tags with commit hashes or build numbers, where tag names have no version order and the repository holds hundreds of builds.

- **It runs after `allow`, `deny` and `semverRange`.** Those filters pick the candidates. `newest` keeps the N built last. In `tagSets`, each set has its own window.
- **Build time is the image config's `created` field**, read for the entry's `platform` (or the first of `platforms`). Ties, including images whose `created` is unset or fixed by a reproducible build, go to the higher tag name.
- **Cleanup trims the window.** With `cleanupTags`, a target tag that falls out of the newest N is deleted, because the target's copies sort the same way as the source.
- **Build times are cached in memory** for 24 hours per tag, so a pass only reads the build time of new tags. After a restart, the first pass reads every candidate tag again: about two registry requests per tag.
- The publisher sets `created`, so `newest` only decides which tags are copied. Every copied image is still scanned and gated. See [ADR 0002](adr/0002-newest-tags-by-build-time.md).

### Keeping running tags

`cleanupKeepRunning: true` (on `defaults` or a sync entry) stops cleanup from deleting a target tag that the latest report of any [clusterstate-agent](../clusterstate-agent/) cluster runs. Use it with `newest` or with source repositories whose own cleanup deletes tags still deployed.

- A cluster that stopped reporting still counts: its last report keeps its tags.
- **Without any cluster report**, for example right after the database is rebuilt, cleanup deletes none of the tags it would otherwise delete for that target, apart from cosign `.sig`/`.att` tags whose subject is gone. It deletes them on a later pass once a cluster has reported.
- Tags are matched by repository and tag name. A pod that pulls only by digest does not keep a tag.

### Ignoring Sync Entries

The `suppline-ignore` field lets you temporarily disable a sync entry without deleting it from `suppline.yml`.

**Behaviour:**
- When `true`, the entry is only mirrored. Suppline skips scanning, policy, and attestation for it, and the in-process mirror moves its tags as soon as it copies, without waiting for an attestation. Use it for artifacts Trivy cannot scan, such as Helm charts.
- When `false` (default), the entry is scanned and copied.
- The field is per-entry only; there is no defaults-level equivalent.

**Examples:**

```yaml
sync:
  # Active entry — processed normally
  - source: nginx
    target: myregistry.example.com/nginx
    type: repository

  # Temporarily ignored — still copied, not scanned
  - source: legacy-app
    target: myregistry.example.com/legacy-app
    type: repository
    suppline-ignore: true

  # Explicit false — same as omitting the field
  - source: alpine
    target: myregistry.example.com/alpine
    type: repository
    suppline-ignore: false
```

### In-place entries

An `in-place` entry names a repository suppline scans and attests where it lives, without copying it. Use it for images you build yourself and push to your own registry, such as CI builds in a GitLab project's container registry. Clusters pull those images from that registry, and Kyverno or OPA verifies the SCAI attestation suppline writes next to each digest.

```yaml
in-place:
  - repository: registry.gitlab.com/group/app
    scan-requesters: [group/app]
    createSBOMAttestation: true
    tags:
      allow: ['sha[0-9a-f]{8,}']
      newest: 30
```

- **What the entry takes:** only per-repository settings (tag filters, policy, VEX, rescan and attestation settings). Mirror settings such as `source`, `target`, `type`, `schedule`, `cleanupTags` or `cooldown` are rejected. Shared defaults (policy, `defaults.vex`, `rescanInterval`, the attestation toggles) apply; mirror defaults never do.
- **One owner per repository:** a repository is either a `sync` target or `in-place`, never both. The repository must not name a tag or a digest.
- **Which tags are scanned:** the watcher lists the repository and applies the entry's tag filters itself, `newest` included, because no mirror filtered the repository first. Tags a cluster runs are always scanned as well, so a running image keeps getting rescanned and its attestation renewed after newer builds push it out of the `newest` window.
- **No cooldown:** a cooldown holds a digest before it is published on a tag, and an in-place repository publishes nothing. Its scans are never `pending`, whatever `defaults.cooldown` says.
- **Nothing is deleted from the repository** except older suppline attestations of the kind just written. suppline owns the SCAI, SBOM, vulnerability and VEX attestation kinds on an in-place digest; cosign signatures and attestations of other kinds stay. The registry credentials for the repository therefore need write access (and delete access for replacing attestations).
- **`scan-requesters`** lists the CI identities allowed to request a scan of the repository through the scan-request API. See [Scan requests from CI](#scan-requests-from-ci).

### Scan requests from CI

A CI job can ask suppline to scan an image of an in-place repository right after pushing it, and wait for the verdict, instead of waiting for the next watcher poll:

```bash
curl -sS -X POST "$SUPPLINE_URL/api/v1/scan-requests?wait=55s" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"image":"registry.gitlab.com/group/app:sha1a2b3c4d"}'
```

- **200** returns the verdict once a scan newer than the request finished: `state` (`done` or `error`), `verdict.status` (`passed`, `failed`, `pending`), `verdict.findings`, the vulnerability counts and `verdict.attested.scai`. Gate a deploy on `state == "done" && verdict.status == "passed" && verdict.attested.scai`.
- **202** means the scan is still queued or running when `wait` ran out. Poll the returned `poll` path (`GET /api/v1/scan-requests/<digest>?repository=…&after=…&wait=55s`) until it answers 200. Waiting in slices below 60 seconds keeps the request under the default read timeout of most ingress controllers; the server caps `wait` at 10 minutes.
- **The image must be in an in-place repository** (404 for an unknown repository, 422 for a mirrored one), and the tag must pass the entry's tag filters (422) and resolve in the registry (404). A digest after the tag (`repo:tag@sha256:…`) must be the one the tag names (409).
- **Scan requests run first.** They use their own queue tier ahead of discovery and rescans, and `worker-urgent-concurrency` workers (default 3) take nothing else. Attestations are pushed in parallel, and older ones are replaced in the background, so a request answers as soon as the new attestations are published.
- **Read-only mode** refuses new scan requests.
- **Retry when the leader changes.** With more than one instance, a queued request lives in the leader's memory. When the leader restarts or fails over, an open request answers 202 or drops the connection, and a later poll can answer **404** because the new leader never heard of it. Send the POST again on a 404 from a poll, a 5xx or a dropped connection. A repeated POST queues one more scan at most. A brief PostgreSQL outage, such as a switchover, does not need a retry: the POST retries its database read for up to 20 s, and an open wait keeps polling the database until its verdict or its `wait` runs out. A longer outage answers 503 with `Retry-After`.

**Authentication.** The API key may request scans of every in-place repository. With `server.oidc` set, a CI job can instead send an OIDC ID token, such as a GitLab CI `id_token` whose `aud` is `server.oidc.audience`. suppline verifies it against the issuer's published keys and accepts it only when the token's `claim` (default `project_path`) is listed in the repository's `scan-requesters`. ID tokens open the scan-request endpoints only; every other route still needs the API key. The issuer is discovered on the first ID token, so suppline starts even when it is unreachable; until it is reachable, ID tokens get 503.

```yaml
# .gitlab-ci.yml
suppline_scan:
  stage: build
  needs: [image]
  image: alpine:3.22
  id_tokens:
    SUPPLINE_ID_TOKEN:
      aud: https://suppline.example.com
  script:
    - apk add --no-cache curl jq
    - |
      auth="Authorization: Bearer $SUPPLINE_ID_TOKEN"
      request() {
        curl -sS -o out.json -w '%{http_code}' -X POST "$SUPPLINE_URL/api/v1/scan-requests?wait=55s" \
          -H "$auth" -d "{\"image\":\"$CI_REGISTRY_IMAGE:sha$CI_COMMIT_SHORT_SHA\"}" || true
      }
      poll() {
        curl -sS -o out.json -w '%{http_code}' "$SUPPLINE_URL$(jq -r .poll out.json)&wait=55s" -H "$auth" || true
      }
      retries=0
      code=$(request)
      while [ "$code" != 200 ]; do
        case "$code" in
          202) code=$(poll); [ "$code" = 404 ] && code=retry ;;
          5??|000|retry)
            # The leader changed and the request went with it: ask again.
            retries=$((retries + 1)); [ "$retries" -le 3 ] || break
            sleep 5; code=$(request) ;;
          *) break ;;
        esac
      done
      jq . out.json
      [ "$code" = 200 ] && jq -e '.state == "done" and .verdict.status == "passed" and .verdict.attested.scai' out.json
```

### Rescan Interval Configuration

The `rescanInterval` field controls how often images are rescanned even if their digest hasn't changed.

**Interval Notation:**
- `m` - minutes (e.g., `30m`, `90m`)
- `h` - hours (e.g., `2h`, `12h`, `24h`)
- `d` - days (e.g., `1d`, `3d`, `7d`)

**Configuration Levels:**

1. **Sync Entry Level** - Highest priority, applies to specific repository
2. **Defaults Level** - Applies to all sync entries without explicit interval
3. **Hardcoded Default** - Falls back to `7d` if not configured

**Examples:**

```yaml
defaults:
  rescanInterval: 7d        # Default: rescan every 7 days

sync:
  # Uses default interval (7d)
  - source: nginx
    target: myregistry.example.com/nginx
    type: repository
  
  # Override with shorter interval for critical images
  - source: postgres
    target: myregistry.example.com/postgres
    type: repository
    rescanInterval: 3d      # Rescan every 3 days
  
  # Short interval for development images
  - source: myapp-dev
    target: myregistry.example.com/myapp-dev
    type: repository
    rescanInterval: 12h     # Rescan every 12 hours
```

### Policy Configuration

Policies use CEL (Common Expression Language) to evaluate security posture.

**Available Variables:**
- `criticalCount` - Number of critical vulnerabilities (excluding VEX-exempted)
- `highCount` - Number of high vulnerabilities (excluding VEX-exempted)
- `mediumCount` - Number of medium vulnerabilities (excluding VEX-exempted)
- `lowCount` - Number of low vulnerabilities (excluding VEX-exempted)
- `exemptedCount` - Number of VEX-exempted vulnerabilities
- `vulnerabilities` - List of all vulnerabilities with details
- `imageRef` - Image reference being evaluated

**Examples:**

```yaml
defaults:
  policy:
    expression: "criticalCount == 0"
    failureMessage: "critical vulnerabilities found"

sync:
  # Strict policy for production
  - source: myapp-prod
    target: myregistry.example.com/myapp-prod
    type: repository
    policy:
      expression: "criticalCount == 0 && highCount == 0"
      failureMessage: "critical or high vulnerabilities found"
  
  # Lenient policy for development
  - source: myapp-dev
    target: myregistry.example.com/myapp-dev
    type: repository
    policy:
      expression: "criticalCount <= 5"
      failureMessage: "too many critical vulnerabilities"
```

### Cooldown

`cooldown` keeps a new upstream digest out until the cooldown has passed since suppline first saw it. Set it on `defaults` and override it per sync entry; `"0"` turns it off for an entry. It is off unless set. An invalid duration stops suppline from loading the file.

```yaml
defaults:
  cooldown: 7d

sync:
  - source: docker.io/library/nginx
    target: myregistry.example.com/nginx
    type: repository
    cooldown: 3d
    cooldown-release:          # written by "Release now" on the Mirror page
      - digest: sha256:4f1c…
        reason: CVE-2026-1234 hotfix
        at: "2026-11-18T10:00:00Z"
```

- **The clock** starts when suppline first sees the digest upstream, never at the image's `created` date: a publisher sets that, and reproducible builds set it to 1970.
- **During the cooldown** the digest is scanned at once. A passing scan stays `pending` with no attestation; a failing one fails and can be triaged. Once the cooldown is over, the next scan attests the digest.
- **With the in-process mirror** the digest is copied by digest only and its tag, a new tag included, moves only after the passing scan. Renovate pointed at your registry therefore never sees the release before then. Renovate pointed at the upstream registry bypasses the cooldown; use Renovate's own `minimumReleaseAge` there as a second layer. See [STATE_MACHINE.md](STATE_MACHINE.md) for how the tag runway holds digests, and [REGISTRY.md](REGISTRY.md#hold-tags) for the hold tags it writes.
- **Without the mirror** suppline cannot hold the import. The cooldown only withholds the attestation, counting from the digest's first scan.
- **Grandfathering:** a digest a target tag already names when the cooldown is switched on, or when suppline starts with a new database, counts as past its cooldown.
- **`cooldown-release`** skips the rest of one digest's cooldown. It never skips the scan or the attestation. The Mirror page writes it as a config edit, committed to the config repository when one is configured, and rescans the held digest at once, so its tag moves as soon as that scan passes. A release edited into the file directly takes effect on the next mirror pass.

### VEX Statements

VEX (Vulnerability Exploitability Exchange) statements follow the CycloneDX VEX standard and can be defined at two levels:

1. **Default Level** - Applied to all sync targets
2. **Sync Entry Level** - Applied to specific repositories

VEX statements from both levels are **merged together**, with sync-specific statements added to the default ones.

**Default VEX Example:**

```yaml
defaults:
  vex:
    # These VEX statements apply to ALL sync targets
    - id: CVE-2024-00001
      state: false_positive
      detail: "Known false positive across all images"
      expires_at: 2025-12-31T23:59:59Z
    
    - id: CVE-2024-00002
      state: not_affected
      justification: vulnerable_code_not_present
      detail: "Accepted risk - no fix available in base images"

sync:
  - source: nginx
    target: myregistry.example.com/nginx
    type: repository
    # This target gets both default VEX statements PLUS the one below
    vex:
      - id: CVE-2024-56171
        state: not_affected
        justification: vulnerable_code_not_in_execute_path
        detail: "Nginx-specific exemption"
        expires_at: 2025-12-31T23:59:59Z
  
  - source: alpine
    target: myregistry.example.com/alpine
    type: repository
    # This target gets only the default VEX statements
```

**Sync-Specific VEX Example:**

```yaml
sync:
  - source: nginx
    target: myregistry.example.com/nginx
    type: repository
    vex:
      # Temporary exemption with expiry
      - id: CVE-2024-56171
        state: not_affected
        justification: vulnerable_code_not_present
        detail: "Initial VEX statement when introducing supplychain"
        expires_at: 2025-12-31T23:59:59Z
      
      # Permanent exemption
      - id: CVE-2025-0838
        state: not_affected
        justification: vulnerable_code_not_in_execute_path
        detail: "No fix available, accepted risk after security review"
      
      # False positive
      - id: CVE-2024-12345
        state: false_positive
        detail: "Not applicable to our use case"
        expires_at: 2025-06-30T23:59:59Z
```

**Fields:**
- `id` (required): CVE identifier (e.g., `CVE-2024-56171`)
- `state` (required): VEX analysis state. One of:
  - `not_affected` - The vulnerability does not affect this component (exempts from policy counts)
  - `affected` - The vulnerability affects this component
  - `in_triage` - Under investigation
  - `false_positive` - Incorrectly identified as vulnerable, e.g. a backported fix the scanner does not see (exempts from policy counts; the triage dialog requires a detail)
  - `resolved` - The vulnerability has been remediated
  - `resolved_with_pedigree` - Resolved and provenance is tracked
- `justification` (required when state is `not_affected`): Canonical values:
  - `code_not_present`
  - `code_not_reachable`
  - `requires_configuration`
  - `requires_dependency`
  - `requires_environment`
  - `protected_by_compiler`
  - `protected_at_runtime`
  - `protected_at_perimeter`
  - `protected_by_mitigations`
  - Legacy aliases are still accepted and normalized internally:
  - `component_not_present` -> `code_not_present`
  - `vulnerable_code_not_present` -> `code_not_present`
  - `vulnerable_code_cannot_be_controlled_by_adversary` -> `code_not_reachable`
  - `vulnerable_code_not_in_execute_path` -> `code_not_reachable`
  - `inline_mitigations_already_exist` -> `protected_by_mitigations`
  - `protected_by_mitigating_control` -> `protected_by_mitigations`
- `detail` (optional): Human-readable explanation for audit and compliance
- `expires_at` (optional): When the statement expires. Supports:
  - RFC3339 timestamp: `2026-02-28T23:59:59Z`
  - Date only (sets to 23:59:59 UTC): `2026-02-28`
  - Date validation ensures valid dates (e.g., Feb 29 only in leap years)

**Behavior:**
- Only VEX statements with state `not_affected` or `false_positive` that are not expired exempt CVEs from policy evaluation. `resolved` and `resolved_with_pedigree` do not: a statement covers every tag of the repository, and a build that really carries the fix no longer reports the CVE, so the exemption would only ever apply to unfixed tags. Rebuild or upgrade instead
- Default VEX statements are merged with sync-specific statements
- Expired statements are ignored (CVE counts normally)
- Warnings logged for statements expiring within 7 days
- Statements without `expires_at` never expire

## Examples

### Local development

```yaml
# suppline.yml
version: 1
observability:
  logLevel: debug
defaults:
  rescanInterval: 1h
sync: []
```

```bash
# .env
ATTESTATION_KEY=<base64 -w0 cosign.key>
ATTESTATION_KEY_PASSWORD=<password>
SUPPLINE_API_KEY=dev-secret-key
POSTGRES_URL=postgres://suppline:suppline@localhost:5432/suppline?sslmode=disable
```

### Production (Helm)

```yaml
# backend.supplineConfig
version: 1
server:
  basePath: /suppline   # also the chart's ingress path
scanner:
  server: localhost:4954  # the chart's Trivy sidecar
  timeout: 10m
defaults:
  rescanInterval: 1d
  queue-buffer-size: 2000
sync: [...]
```

Secrets go in `backend.secrets` (`SUPPLINE_API_KEY`, `ATTESTATION_KEY`, `ATTESTATION_KEY_PASSWORD`, registry credentials). The bundled PostgreSQL provides `POSTGRES_URL`.

## Triage (`triage`)

Triage runs after a CEL failure on a repository that is currently running in a cluster (`only_in_use`, default true; the same runtime window as `source="runtime"` alerts). The statement covers every tag, so one session inspects one representative digest and decides the repository's CVEs together. A CVE that is only present on an idle digest is not triaged while `only_in_use` is on. Set `only_in_use: false` to triage every failure. When triage is enabled, the policy views show **Triage now** and **Fix using coding agent** together. **Triage now** queues the failures in the current image-usage view. The coding-agent button copies a prompt for those same failures. The Triage view, and the Tasks triage card, list current automated runs that were rejected or left unresolved. Each row can be requeued or copied as **Fix this using coding assistant**, and **Fix all open using coding assistant** copies that whole set. Triage checks out the gitops repositories in `context_repos`, asks an OpenAI-compatible chat model whether the CVE affects this deployment, and may write `vex-auto` on the matching sync entry. The model can also read the latest image snapshots reported by the cluster agents, fetch the public CVE or GHSA advisory, and check out one directory of the image's source commit. That commit comes from the OCI labels `org.opencontainers.image.source` and `org.opencontainers.image.revision` when they are present. Otherwise triage reads the upstream tag's SLSA provenance (`configSource.uri` on the attestation attached to the catalog source image). A `-sha-` tag is searched on GitHub only when that attestation is missing, and only a single matching repository is used. When the source label names a GitHub repository but no revision, a version tag such as `3.5.0` is looked up there as `3.5.0` or `v3.5.0`. The checkout is searched with the same grep and read_file tools as the gitops repos. `dependency_sources` then checks out at most five direct npm or pnpm dependents of the vulnerable package. `requires_configuration` and `requires_environment` may cite a gitops line or a line from one of those checkouts. `code_not_reachable`, and `code_not_present` when allowed, may cite a public line, an empty grep by the `grep_id` of a directory that was fully fetched (a parent that was not fetched is not absence), an empty grep of the scanned image when that search reports absence, an empty `image_files` path search of the image, or the `package_files` rows that list what the matched package installs. A CVE reported only in kernel header packages (`linux-libc-dev`, `linux-headers`, `linux-headers-*`, `kernel-headers`, `linux-api-headers`, `linux-uapi-headers`) on every current digest is decided without the model: suppline writes `not_affected` with `code_not_present`, because a container runs the node's kernel and a header package ships no kernel code. The KEV rule still applies. This decision does not cover the node kernel, which is patched on the host. Other kernel packages (`linux`, `kernel`) go to the model, which stays uncertain so a person reviews them. The image checkout is named `image` and is used when the image has no source commit. It searches scripts, source files, and Go binaries. A skipped stripped native library that belongs to the package is not absence. A `grep_id` whose search returned rows is those lines. An empty grep does not satisfy `requires_configuration` or `requires_environment`. An empty grep of the gitops tree stays uncertain. `SUPPLINE_GITHUB_TOKEN` is used for GitHub code search and for the commit-search fallback. Hand-written `vex` is never modified and wins when both lists contain the same id. The workflow, dedupe rules, and guardrails are in [STATE_MACHINE.md](STATE_MACHINE.md).

```yaml
triage:
  enabled: true
  only_in_use: true      # default; false triages images that are not running
  mode: dry-run          # dry-run (default) | enforce
  llm:
    base_url: https://llm.internal/v1
    model: anthropic/claude-sonnet-5.5
    max_steps: 20          # per phase: context, then each CVE
    max_group: 8           # CVEs per session; larger repositories are split
    daily_token_budget: 2000000  # UTC day; the Triage view can start a new window before midnight
  min_confidence: 0.8
  expiry: 30d
  renew_before: 7d
  retriage_interval: 24h
  allowed_justifications:
    - requires_configuration
    - requires_environment
    - protected_at_perimeter
    - protected_at_runtime
    - protected_by_mitigations
    - code_not_reachable
  block_kev: true
  checkout_dir: /data/gitops
  backup_retention: 10
  context_repos:
    - name: infra
      url: https://git.example/infra/gitops.git
      auth: { type: https-token, env: GITOPS_INFRA_TOKEN }
      include: ["**/*.yaml"]
  config_repo:            # omit to edit the local suppline.yml instead
    url: ssh://git@git.example/infra/suppline-config.git
    path: suppline.yml
    auth:
      type: ssh
      key_env: SUPPLINE_CONFIG_REPO_KEY
      known_hosts_env: SUPPLINE_KNOWN_HOSTS
    author: { name: suppline-triage, email: triage@suppline.local }
```

`prompt` replaces the built-in decision policy. Leave it unset to accept a low residual risk with `requires_configuration` or `requires_environment`, and to rate a finding that is not exposed to the public down one severity step (`critical -> high`, `high -> medium`, `medium -> low`). The tool workflow and the JSON output contract stay in place either way.

Git credentials and `SUPPLINE_LLM_API_KEY` come from the environment, not from this file. SSH auth requires both a private key and `known_hosts`. An empty `branch` follows the remote HEAD. `config_repo.path` is a plain file inside that repository. In enforce mode without `config_repo`, the local file must be writable; a read-only ConfigMap mount refuses to start. Local writes keep `suppline.yml.bak.1` (newest) through `.bak.N`. The Tasks view uses the same writer for semver range updates, removing unused sync entries, and removing unused VEX statements. The unused list covers statements that are never applied to any scan. A background audit, hourly and once at startup, also lists sync-entry `vex` and `vex-auto` `not_affected` statements whose removal leaves the pass/fail result of every repository artifact's latest scan unchanged. The check uses the severity recorded on each finding. A later scan that rates the same CVE differently does not rewrite an earlier finding, and a finding with no recorded severity is left in place. Removing one of those edits only its own sync entry, never `defaults`. A configured `config_repo` is committed and pushed, otherwise the local file is updated. Those actions stay available when the LLM loop is off, as long as the file or config repository can be written.

Per-sync auto statements:

```yaml
sync:
  - source: nginx
    target: registry.example/nginx
    type: repository
    vex: []        # people
    vex-auto: []   # Triage
```

## Malicious packages (`malicious-packages`)

suppline matches the language packages in every scan's SBOM against [ossf/malicious-packages](https://github.com/ossf/malicious-packages) (OSV `MAL-*` advisories). It keeps a shallow, bare git clone of that repository, syncs it on `sync_interval`, and indexes it in memory; no extra scanner binary is involved. The design is in [adr/0001-in-process-malicious-package-detection.md](adr/0001-in-process-malicious-package-detection.md). The block is read at startup only; restart suppline to change it.

The feature is on when the block is missing. Every key is optional:

```yaml
malicious-packages:
  enabled: true            # false turns detection off
  block: true              # a malicious package fails policy whatever the expression says
  repo:
    url: https://github.com/ossf/malicious-packages.git   # or an internal mirror
    ref: main
    auth: { type: https-token, env: MAL_FEED_TOKEN }       # optional; same shape as triage repos, empty is anonymous
  checkout_dir: /data/malicious-packages
  sync_interval: 1h
  stale_after: 6h          # must be at least sync_interval
  ecosystems: [npm, PyPI, RubyGems, NuGet, crates.io, Go, Maven, Packagist]
```

How it behaves:

- **Scans never wait for the feed.** Until the first index load (about 30 s to clone and 15 s to index on a fresh volume), scans record the check as `unavailable` and pass it. Once the index loads, those images are matched again; only images with a match are rescanned.
- **Stale data still counts.** If no sync succeeds for `stale_after`, scans keep matching against the old data and record the check as `stale`. When syncing recovers, every stored image is matched again.
- **New advisories reach existing images within one sync.** Each scan stores the image's language packages. After every sync, images holding a package that a new or changed advisory names are rescanned at high priority. An image that was scanned while the feed was unavailable or stale, and has no match, has its stored check updated to `ok`; its signed SCAI keeps the original status until the next rescan.
- **The SCAI attestation** always carries a `malicious-package-check` attribute with the status, the feed commit and time it matched against, and any findings.
- **Health** reports `malicious_packages` as healthy in every state, with the status in the message. `/health` has no degraded state, so a stale feed must not mark the instance unhealthy. Alert on the metrics instead.
- **Disk:** the bare clone is under 100 MB. With the bundled PostgreSQL in the Helm chart, `/data` is an emptyDir, so the feed is cloned again after each restart.
- **False positives:** exempt them per repository with a hand-written `vex` statement in state `false_positive` (see [POLICY.md](POLICY.md#malicious-packages)). `not_affected` and `vex-auto` are rejected for MAL ids. The VEX audit in the Tasks view lists such a statement as unused once no current, checked scan of the repository matches the advisory.
- **UI:** the **Malicious Packages** view shows the feed's sync state, how many current images were checked on current data, and every affected image grouped by package or by image, with images running in a cluster first. `GET /api/v1/malicious` returns the same data.

The eval stack (`suppline.demo.yml`) sets `enabled: false` so it boots quickly.

## Duration Format

Duration values use Go's duration format:

- `s` - seconds (e.g., `30s`)
- `m` - minutes (e.g., `5m`)
- `h` - hours (e.g., `24h`)
- Combined (e.g., `1h30m`, `2h45m30s`)

**Examples:**
```yaml
scanner:
  timeout: 5m
defaults:
  worker-poll-interval: 5s
  worker-retry-backoff: 30s
```

`rescanInterval`, `cooldown` and `scaiValidityExtension` also accept days, e.g. `7d`.

## Boolean Format

Booleans in `suppline.yml` are YAML booleans: `true` or `false`.

## Configuration Best Practices

### Security

1. **Never commit secrets** to version control
2. **Use strong API keys** (minimum 32 characters)
3. **Rotate credentials regularly** (every 90 days)
4. **Use repository-scoped tokens** instead of user passwords
5. **Enable TLS** for Trivy server in production
6. **Restrict API access** with network policies

### Performance

1. **Adjust queue buffer size** based on registry size
2. **Tune rescan interval** to balance freshness and load
3. **Increase Trivy timeout** for large images
4. **Monitor queue depth** and adjust worker settings

### Reliability

1. **Set appropriate retry attempts** (3-5 recommended)
2. **Use exponential backoff** for retries
3. **Enable health checks** in orchestrator
4. **Configure resource limits** appropriately
5. **Use persistent storage** for state store

### Observability

1. **Use structured logging** (JSON format)
2. **Set appropriate log level** (info for production)
3. **Enable Prometheus metrics** for monitoring
4. **Configure alerting** on key metrics
5. **Integrate with log aggregation** systems
