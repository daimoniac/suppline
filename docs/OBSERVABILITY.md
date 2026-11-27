---
layout: default
title: Observability
description: Health endpoints and Prometheus metrics for suppline
---

# Observability

Prometheus metrics on `:9090/metrics`, JSON logs on stdout, and component health on `:9090/health`. The health payload covers config, queue, worker, trivy, database, watcher and malicious_packages, plus the instance's `role` (`leader` or `standby`).

On a standby the leader-only components report `standby`, which counts as healthy, and `/metrics` carries only `suppline_leader 0` and Go runtime metrics. `malicious_packages` always reports healthy; its message carries `ok`, `unavailable` or `stale`, so alert on the metrics below. `database` is re-checked every 15 s.

`/ready` fails while an instance drains on shutdown or a component is unhealthy. Point liveness probes at `/live`, which only checks that the process answers: restarting suppline does not fix PostgreSQL or Trivy.

Log level and the metrics port are `observability.logLevel` and `observability.port` in [CONFIGURATION.md](CONFIGURATION.md#runtime-settings).

| Metric | Tells you |
|--------|-----------|
| `suppline_policy_failed_current{source="registry\|runtime"}` | Failing images, split by mirrored vs actually running. `runtime` includes digests a tag has moved off while pods still run them; `GET /api/v1/images/running-failures` lists that same set |
| `suppline_vulnerabilities_total` | Vulnerabilities by severity |
| `suppline_scans_total` | Scans by status |
| `suppline_queue_depth` | Backlog. If this climbs, add workers or slow the watcher |
| `suppline_leader` | 1 on the leader, 0 on a standby. Alert when `sum(suppline_leader) != 1` |
| `suppline_scan_duration_seconds` | Scan latency histogram |
| `suppline_triage_runs_total{status}` | Triage decisions by status |
| `suppline_triage_tokens_total` | Tokens reported by the triage model |
| `suppline_triage_push_failures_total` | Config-repo pushes rejected after retries |
| `suppline_triage_budget_exhausted` | 1 while the daily token budget is used up |
| `suppline_malicious_images_current{repository,in_use}` | Current images whose latest scan found a known-malicious package. Alert on any `in_use="true"` |
| `suppline_malicious_db_last_sync_success_timestamp_seconds` | Last successful malicious-packages sync. `time() - …` is the feed's age |
| `suppline_malicious_db_sync_errors_total` | Failed malicious-packages syncs |
| `suppline_malicious_db_packages{ecosystem}` | Packages with an active malicious-package advisory |
| `suppline_malicious_rematch_rescans_total` | Rescans queued because a new advisory matched a stored image |

A starter Grafana dashboard lives in [grafana/](https://github.com/daimoniac/suppline/tree/main/grafana).
