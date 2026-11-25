---
status: accepted
---

# A warm standby takes over through a PostgreSQL advisory lock, and standbys proxy all API traffic to the leader

suppline runs as a single replica. When its pod or node goes, CI scan requests, mirroring, rescans and attestation renewal stop until Kubernetes reschedules it. That takes minutes after a crash, longer after a node loss, and the Trivy cache on a non-replicated volume can pin the pod to the dead node. Admission does not depend on suppline: Kyverno verifies attestations from the registry, so running workloads and deploys of attested images keep working. The outage budget is the `validUntil` margin of those attestations, and the CI gate.

suppline cannot simply run two replicas. The scan queue and its digest dedup live in memory. The watcher, worker, triage, vexaudit, malicious-package sync and rematcher, config reload and the in-process mirror assume they are the only copy. Nearly every API endpoint reads that in-process state: the scan-request waiter, triage status, mirror activity, cooldown holds, the malicious feed snapshot, and config-edit and gitops status.

We decided:

- **One leader, any number of warm standbys, chosen by a PostgreSQL session advisory lock.**
  - The key is a fixed constant, so there is one suppline per database.
  - Election is always on: a single replica simply wins at once. It also stops two instances that share a database by mistake.
  - The lock lives on a dedicated connection. That session sets `tcp_keepalives_idle=10`, `tcp_keepalives_interval=5` and `tcp_keepalives_count=3`, so PostgreSQL drops the session of a vanished node, and its lock, in about 25 s rather than the kernel default of two hours.
- **Losing the lock ends the process.**
  - Every 5 s the leader checks, on the lock connection with a 3 s timeout, that `pg_locks` still shows the lock granted to its own backend. If the check fails, the process exits.
  - Kubernetes restarts it, and it comes back as a standby. There is no in-process step-down.
- **A standby validates the setup and waits.** It loads config, migrates, checks Trivy, builds the attestor and logs in to registries, so a broken config or credential fails on the standby before it is needed. It runs no enqueues and no component `Start`/`Run` until it wins.
- **Schema migrations run under a second, blocking advisory lock.** Two pods never migrate at once. Migrations are not required to be compatible with the previous version; see below.
- **The leader advertises itself in a `leader` row; standbys reverse-proxy the whole API port to it.**
  - The row holds `holder`, `address`, `backend_pid` and `acquired_at`. `address` comes from `server.advertiseAddress`; the chart sets it from the pod IP, and the default is the first non-loopback IP and the API port.
  - A standby trusts the row only while `pg_locks` shows the lock granted to `backend_pid`, so it never forwards to a stale or reused address.
  - It caches the answer for 2 s.
  - With no valid leader it holds a request up to 10 s, then answers 503 with `Retry-After`.
  - Proxied requests carry a marker header. A standby answers 503 to a request that already carries it, so a stale view can never loop.
  - Every response has `X-Suppline-Served-By`.
- **The observability port stays local to each pod.**
  - `/health` gains a `standby` status that counts as healthy, so liveness never kills a standby.
  - A standby's `/metrics` serves its own small registry: `suppline_leader 0` plus Go and process metrics. Business metrics come only from the leader, so alerts and dashboards see one suppline.
- **Graceful shutdown drains, then releases the lock.**
  - On SIGTERM a leader stops accepting requests. Open scan-request long-polls answer 202 with their poll path, other requests finish while the worker still runs, then components stop and the lock is released.
  - All of this is bounded by 60 s, with a 90 s termination grace period.
  - A standby drains its proxied requests the same way. A lock loss exits at once, because another pod may already lead.
- **A new leader continues the previous leader's schedules instead of starting them over.**
  - The mirror skips an entry's startup "missing" pass when `mirror_syncs` shows a successful finish within the entry's interval, and schedules its next copy from that finish.
  - Startup cleanup runs only for targets whose entry ran its startup pass.
  - Startup re-queues only **in-use** policy-failed artifacts, as urgent, and only if their last scan is older than `worker-poll-interval`. Unused ones wait for their rescan interval, as before.
  - Watcher discovery stays immediate. It runs every poll interval anyway and repopulates the queue the old leader lost.
  - Without this, every failover, and so every rollout, would add a full pass over every upstream registry.
- **CI clients re-POST a scan request** when the connection drops, or when a poll answers 404 because a new leader never heard of the request. Outstanding scan requests are not persisted.
- **The chart runs suppline as a Deployment.**
  - `RollingUpdate` with `maxSurge: 1, maxUnavailable: 0`. With more than one replica: a PDB with `minAvailable: 1` and required pod anti-affinity.
  - The Trivy cache becomes an `emptyDir`, so no volume ties a pod to a node.

## Considered Options

- **Readiness follows leadership**: deadlocks rolling updates, because the updated pod never becomes Ready while the old one holds the lock.
- **Leader labels its own pod and the Service selects the label**: needs Kubernetes API calls (client-go or a hand-written PATCH) and RBAC. Leadership would then live in two systems, the lock and the label, which can disagree. It also only works on Kubernetes.
- **Kubernetes Lease election** (client-go `leaderelection`): well-proven, but it adds the client-go dependency tree to a supply-chain tool, it is Kubernetes-only, and routing would still need the label.
- **Standbys serve reads from PostgreSQL themselves**: most endpoints read leader memory, so they would answer wrongly. Proxying only some routes means classifying every endpoint and keeping that list right.
- **Active/active with a PostgreSQL queue** (`FOR UPDATE SKIP LOCKED`, persisted scan requests, `LISTEN/NOTIFY`): needed for scan throughput, not for availability. Much larger, and it can build on this.
- **One shared Trivy server instead of a sidecar per pod**: saves one Trivy's requests. It was rejected because Trivy would become a separate failure point for scanning, and `localFallback` would have to be turned off.
- **Smaller requests on both pods, relying on limits**: cheaper. It was rejected because under node memory pressure the leader would be evicted first, and every eviction is a failover.
- **Proxy `/metrics` to the leader**: Prometheus labels each scrape target, so every series would appear once per pod and every `sum` would double.

## Decisions a future reader might "fix"

- **The lock is not a fencing token.** When PostgreSQL restarts or fails over, the old leader may keep working for up to one check interval after another pod wins. That costs a duplicate scan or attestation (idempotent), a little extra LLM spend in triage, or a git conflict that the push rejects. None of these corrupts state, so fencing isn't worth its cost.
- **Migrations need not be backward compatible.** During a rollout the new pod migrates while the old leader runs. A destructive migration can break the old leader for the seconds until the rollout replaces it. That is accepted for its simplicity: destructive migrations are rare, and a rollout ends that window.
- **Exit instead of step-down.** A process that has lost the lock may hold half-started components, queued tasks and waiters. Exiting drops all of it at once.
- **The standby re-checks `pg_locks` instead of trusting the `leader` row.** Pod IPs are reused. A stale row could forward API-key and OIDC-authenticated requests to an unrelated pod.

## Consequences

- Reserved resources double. Every pod, including the standby, keeps the leader's requests and its own Trivy sidecar, so a takeover always has its capacity. An idle standby uses far less than it reserves.
- PostgreSQL is now the single point of failure. Its HA (CNPG with several instances and backups) is a prerequisite, not part of this decision. During a PostgreSQL failover the leader exits, and whichever pod reconnects first leads.
- Failover takes about 30 s after a pod crash or drain, and about 60 s after a node vanishes.
- A rollout causes one or two failovers, depending on which old pod leads. Because schedules continue from stored state, a failover adds only one watcher discovery pass against the target registry (HEAD requests). Mirror entries that never synced, failed last time, or are new in the config still run at once.
- Requests that reach a standby take one extra in-cluster hop. Pods must be able to reach each other on the API port, which matters under NetworkPolicies.
- After a failover the leader's metrics continue under another pod's label. `rate()`/`increase()` handle the counter reset; panels that filter on a specific pod don't.
- A new pod downloads the Trivy DB at start, because the cache is no longer persistent.
- Required anti-affinity combined with `maxSurge: 1` needs one more schedulable node than replicas, or the rollout stalls.
