---
name: suppline-production-db
description: 'Access and query the suppline production SQLite database. Use when: inspecting scan results, vulnerability counts, policy decisions, cluster inventory, repository state, or debugging production data issues. Covers kubectl exec access, safe read-only queries, schema reference, and common diagnostic queries.'
argument-hint: 'What do you want to look up? (e.g. failing policy scans, CVEs for an image, cluster inventory, repositories)'
---

# Suppline Production Database Access

## When to Use
- Inspect scan history, vulnerability records, or policy decisions for a specific image
- Debug discrepancies between API responses and expected data
- Audit cluster inventory or runtime usage
- Answer ad-hoc data questions not exposed by the API
- Investigate cleanup, orphan records, or schema migration issues

---

## Step 1: Locate and Access the Database

The database is a SQLite file at `/data/suppline.db` on the `data-suppline-backend-0` PVC. The suppline container does not include the `sqlite3` binary, so access it via a short-lived debug pod that mounts the same PVC.

### Spin up the debug pod

```bash
cat <<'YAML' | kubectl --context internal-1 apply -n suppline -f -
apiVersion: v1
kind: Pod
metadata:
  name: sqlite-debug
spec:
  restartPolicy: Never
  containers:
  - name: sqlite
    image: nouchka/sqlite3:latest
    command: ["sh","-lc","sleep infinity"]
    volumeMounts:
    - name: data
      mountPath: /data
  volumes:
  - name: data
    persistentVolumeClaim:
      claimName: data-suppline-backend-0
YAML

# Wait for it to be ready
kubectl --context internal-1 wait -n suppline pod/sqlite-debug --for=condition=Ready --timeout=60s
```

### Open an interactive shell

```bash
# Interactive SQLite shell
kubectl --context internal-1 exec -it -n suppline sqlite-debug -- sqlite3 /data/suppline.db

# Or run a single query non-interactively
kubectl --context internal-1 exec -n suppline sqlite-debug -- \
  sqlite3 /data/suppline.db "SELECT count(*) FROM scan_records;"
```

### Tear down when done

```bash
kubectl --context internal-1 delete pod -n suppline sqlite-debug
```

> **Safety rule**: Open with `.open --readonly` or use `sqlite3` flags for read-only access when inspecting production data. Never run `UPDATE`, `DELETE`, or `INSERT` without an explicit backup first.

### Take a Backup Before Any Writes

```bash
# Copy the database file out of the debug pod
kubectl --context internal-1 cp suppline/sqlite-debug:/data/suppline.db ./suppline-backup-$(date +%Y%m%d%H%M%S).db
```

---

## Step 2: Verify WAL Mode and Integrity

```sql
PRAGMA journal_mode;        -- should be 'wal'
PRAGMA foreign_keys;        -- should be 1
PRAGMA integrity_check;     -- should return 'ok'
```

---

## Schema Reference

| Table | Key Columns | Purpose |
|-------|-------------|---------|
| `repositories` | `id`, `name`, `registry`, `created_at` | Registry repositories being tracked |
| `artifacts` | `id`, `repository_id`, `digest`, `tag`, `first_seen`, `last_seen`, `next_scan_at`, `last_scan_id` | Image artifacts (digest+tag combos) |
| `scan_records` | `id`, `artifact_id`, `critical_vuln_count`, `high_vuln_count`, `policy_passed`, `policy_status`, `policy_reason`, `error_message`, `created_at`, `scan_duration_ms` | One row per scan run |
| `vulnerabilities` | `id`, `scan_record_id`, `cve_id`, `severity`, `package_name`, `installed_version`, `fixed_version` | CVEs found in a scan |
| `clusters` | `id`, `name`, `last_reported_at` | Kubernetes clusters reporting runtime state |
| `cluster_images` | `id`, `cluster_id`, `namespace`, `image_ref`, `tag`, `digest`, `reported_at` | Current live cluster image snapshot |
| `cluster_images_seen` | `id`, `cluster_id`, `namespace`, `image_ref`, `tag`, `digest`, `first_seen_at`, `last_seen_at` | Historical runtime image inventory |
| `runtime_unused_repository_whitelist` | `repository` | Repos excluded from "unused" runtime alerts |

> All `*_at` / `created_at` timestamps are **Unix epoch integers**. Use `datetime(column, 'unixepoch')` to render them.

---

## Step 3: Common Diagnostic Queries

### Overall scan health
```sql
SELECT
  COUNT(*) AS total_scans,
  SUM(CASE WHEN policy_passed THEN 1 ELSE 0 END) AS passed,
  SUM(CASE WHEN NOT policy_passed THEN 1 ELSE 0 END) AS failed,
  SUM(CASE WHEN error_message IS NOT NULL AND error_message != '' THEN 1 ELSE 0 END) AS errored
FROM scan_records;
```

### Latest scan for each artifact
```sql
SELECT
  r.name AS repository,
  a.tag,
  a.digest,
  datetime(sr.created_at, 'unixepoch') AS last_scanned,
  sr.critical_vuln_count,
  sr.high_vuln_count,
  sr.policy_passed,
  sr.policy_reason
FROM artifacts a
JOIN repositories r ON r.id = a.repository_id
JOIN scan_records sr ON sr.id = a.last_scan_id
ORDER BY sr.created_at DESC
LIMIT 50;
```

### Images currently failing policy
```sql
SELECT
  r.name AS repository,
  a.tag,
  a.digest,
  sr.policy_status,
  sr.policy_reason,
  sr.critical_vuln_count,
  sr.high_vuln_count,
  datetime(sr.created_at, 'unixepoch') AS scanned_at
FROM artifacts a
JOIN repositories r ON r.id = a.repository_id
JOIN scan_records sr ON sr.id = a.last_scan_id
WHERE sr.policy_passed = 0
ORDER BY sr.critical_vuln_count DESC;
```

### CVEs for a specific image
```sql
-- Replace ? with the digest or repository name
SELECT v.cve_id, v.severity, v.package_name, v.installed_version, v.fixed_version
FROM vulnerabilities v
JOIN scan_records sr ON sr.id = v.scan_record_id
JOIN artifacts a ON a.id = sr.artifact_id
JOIN repositories repo ON repo.id = a.repository_id
WHERE repo.name = 'myregistry.com/myimage'
  AND sr.id = a.last_scan_id
ORDER BY
  CASE v.severity
    WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2
    WHEN 'MEDIUM' THEN 3 WHEN 'LOW' THEN 4 ELSE 5
  END;
```

### Images due for rescan (overdue)
```sql
SELECT
  r.name,
  a.tag,
  a.digest,
  datetime(a.next_scan_at, 'unixepoch') AS next_scan_due
FROM artifacts a
JOIN repositories r ON r.id = a.repository_id
WHERE a.next_scan_at < cast(strftime('%s', 'now') as integer)
ORDER BY a.next_scan_at ASC
LIMIT 30;
```

### Cluster runtime inventory
```sql
SELECT
  c.name AS cluster,
  ci.namespace,
  ci.image_ref,
  ci.tag,
  ci.digest,
  datetime(ci.reported_at, 'unixepoch') AS reported_at
FROM cluster_images ci
JOIN clusters c ON c.id = ci.cluster_id
ORDER BY c.name, ci.namespace, ci.image_ref;
```

### Clusters and last report time
```sql
SELECT name, datetime(last_reported_at, 'unixepoch') AS last_reported
FROM clusters
ORDER BY last_reported_at DESC;
```

### Scan error log (recent failures)
```sql
SELECT
  r.name AS repository, a.tag, a.digest,
  datetime(sr.created_at, 'unixepoch') AS scanned_at,
  sr.error_message
FROM scan_records sr
JOIN artifacts a ON a.id = sr.artifact_id
JOIN repositories r ON r.id = a.repository_id
WHERE sr.error_message IS NOT NULL AND sr.error_message != ''
ORDER BY sr.created_at DESC
LIMIT 20;
```

---

## Step 4: Completion Check

- [ ] Queried in read-only mode (no writes without backup)
- [ ] Used `datetime(col, 'unixepoch')` for all timestamp columns
- [ ] Verified `PRAGMA integrity_check` returned `ok` if any concerns arose
- [ ] Copied database file as backup before any schema or data changes

---

## Safety Rules

1. **Never modify production data without a backup** — copy the `.db` file out first.
2. **Avoid long-running queries** — SQLite uses WAL mode with a 3-second busy timeout; heavy reads can delay write operations from the suppline process.
3. **Don't run VACUUM** — the live process holds WAL files; VACUUM can interfere.
4. **No DDL changes** — schema is managed by `initSchema()` and `ensureSchemaColumns()` in `internal/statestore/sqlite.go`.
