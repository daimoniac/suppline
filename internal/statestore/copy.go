package statestore

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"strings"

	"github.com/daimoniac/suppline/internal/errors"
)

var sqliteBoolColumns = map[string]struct{}{
	"policy_passed": {},
	"sbom_attested": {},
	"vuln_attested": {},
	"scai_attested": {},
	"vex_attested":  {},
}

// CopySQLiteToPostgres copies a catalog-schema SQLite database into PostgreSQL,
// preserving row IDs. The destination must be empty (no repositories).
func CopySQLiteToPostgres(ctx context.Context, sqlitePath, postgresURL string, logger *slog.Logger) error {
	if logger == nil {
		logger = slog.Default()
	}

	src, err := openSQLiteReadOnly(sqlitePath)
	if err != nil {
		return err
	}
	defer src.Close()

	dst, err := NewPostgresStore(postgresURL)
	if err != nil {
		return err
	}
	defer dst.Close()

	var repoCount int
	if err := dst.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM repositories`).Scan(&repoCount); err != nil {
		return errors.NewTransientf("count destination repositories: %w", err)
	}
	if repoCount > 0 {
		return errors.NewPermanentf("destination postgres already has %d repositories; refusing to copy", repoCount)
	}

	tx, err := dst.db.BeginTx(ctx, nil)
	if err != nil {
		return errors.NewTransientf("begin copy transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	type artifactScanPtr struct {
		id         int64
		lastScanID sql.NullInt64
	}
	var artifactPtrs []artifactScanPtr

	hasSuperseded, err := sqliteHasColumn(ctx, src, "artifacts", "superseded")
	if err != nil {
		return err
	}
	hasFindingSeverity, err := sqliteHasColumn(ctx, src, "scan_findings", "severity")
	if err != nil {
		return err
	}
	artRows, err := src.QueryContext(ctx, `
		SELECT id, repository_id, digest, tag, first_seen, last_seen, image_created_at, last_scan_id, next_scan_at, created_at
		FROM artifacts
	`)
	if err != nil {
		return errors.NewTransientf("select artifacts: %w", err)
	}
	defer artRows.Close()
	for artRows.Next() {
		var (
			id, repositoryID, firstSeen, lastSeen, createdAt int64
			digest                                           string
			tag                                              sql.NullString
			imageCreatedAt, lastScanID, nextScanAt           sql.NullInt64
		)
		if err := artRows.Scan(&id, &repositoryID, &digest, &tag, &firstSeen, &lastSeen, &imageCreatedAt, &lastScanID, &nextScanAt, &createdAt); err != nil {
			return errors.NewTransientf("scan artifact: %w", err)
		}
		artifactPtrs = append(artifactPtrs, artifactScanPtr{id: id, lastScanID: lastScanID})
	}
	if err := artRows.Err(); err != nil {
		return errors.NewTransientf("iterate artifacts: %w", err)
	}

	artifactCopyQuery := `SELECT id, repository_id, digest, tag, first_seen, last_seen, image_created_at, NULL, next_scan_at, created_at, 0 AS superseded FROM artifacts`
	if hasSuperseded {
		artifactCopyQuery = `SELECT id, repository_id, digest, tag, first_seen, last_seen, image_created_at, NULL, next_scan_at, created_at, superseded FROM artifacts`
	}
	artifactCopyInsert := `INSERT INTO artifacts (id, repository_id, digest, tag, first_seen, last_seen, image_created_at, last_scan_id, next_scan_at, created_at, superseded) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	copies := []struct {
		name   string
		query  string
		insert string
	}{
		{
			name:   "repositories",
			query:  `SELECT id, name, registry, created_at FROM repositories`,
			insert: `INSERT INTO repositories (id, name, registry, created_at) VALUES (?, ?, ?, ?)`,
		},
		{
			name:   "artifacts",
			query:  artifactCopyQuery,
			insert: artifactCopyInsert,
		},
		{
			name:   "scan_records",
			query:  `SELECT id, artifact_id, scan_duration_ms, critical_vuln_count, high_vuln_count, medium_vuln_count, low_vuln_count, policy_passed, policy_status, policy_reason, policy_failure_findings_json, release_age_seconds, minimum_release_age_seconds, release_age_source, sbom_attested, vuln_attested, scai_attested, COALESCE(vex_attested, 0) AS vex_attested, error_message, vex_statements_json, created_at FROM scan_records`,
			insert: `INSERT INTO scan_records (id, artifact_id, scan_duration_ms, critical_vuln_count, high_vuln_count, medium_vuln_count, low_vuln_count, policy_passed, policy_status, policy_reason, policy_failure_findings_json, release_age_seconds, minimum_release_age_seconds, release_age_source, sbom_attested, vuln_attested, scai_attested, vex_attested, error_message, vex_statements_json, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		},
		{
			name:   "cve_catalog",
			query:  `SELECT cve_id, severity, title, description, primary_url FROM cve_catalog`,
			insert: `INSERT INTO cve_catalog (cve_id, severity, title, description, primary_url) VALUES (?, ?, ?, ?, ?)`,
		},
		{
			name:   "scan_findings",
			query:  findingCopyQuery(hasFindingSeverity),
			insert: findingCopyInsert(hasFindingSeverity),
		},
		{
			name:   "cve_first_seen",
			query:  `SELECT artifact_id, cve_id, first_seen_at FROM cve_first_seen`,
			insert: `INSERT INTO cve_first_seen (artifact_id, cve_id, first_seen_at) VALUES (?, ?, ?)`,
		},
		{
			name:   "clusters",
			query:  `SELECT id, name, last_reported_at, created_at FROM clusters`,
			insert: `INSERT INTO clusters (id, name, last_reported_at, created_at) VALUES (?, ?, ?, ?)`,
		},
		{
			name:   "cluster_images",
			query:  `SELECT id, cluster_id, namespace, image_ref, tag, digest, reported_at FROM cluster_images`,
			insert: `INSERT INTO cluster_images (id, cluster_id, namespace, image_ref, tag, digest, reported_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		},
		{
			name:   "cluster_images_seen",
			query:  `SELECT id, cluster_id, namespace, image_ref, tag, digest, first_seen_at, last_seen_at FROM cluster_images_seen`,
			insert: `INSERT INTO cluster_images_seen (id, cluster_id, namespace, image_ref, tag, digest, first_seen_at, last_seen_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		},
		{
			name:   "runtime_unused_repository_whitelist",
			query:  `SELECT repository, created_at FROM runtime_unused_repository_whitelist`,
			insert: `INSERT INTO runtime_unused_repository_whitelist (repository, created_at) VALUES (?, ?)`,
		},
	}

	var triageTable int
	if err := src.QueryRowContext(ctx, `SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'triage_runs'`).Scan(&triageTable); err != nil {
		return errors.NewTransientf("inspect triage_runs: %w", err)
	}
	if triageTable > 0 {
		hasSession, err := sqliteHasColumn(ctx, src, "triage_runs", "session_id")
		if err != nil {
			return err
		}
		query := `SELECT id, repository, cve_id, verdict, justification, confidence, evidence_json, reasoning, model, repo_shas_json, cve_hash, tokens, status, commit_sha, created_at FROM triage_runs`
		insert := `INSERT INTO triage_runs (id, repository, cve_id, verdict, justification, confidence, evidence_json, reasoning, model, repo_shas_json, cve_hash, tokens, status, commit_sha, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
		if hasSession {
			query = `SELECT id, repository, cve_id, verdict, justification, confidence, evidence_json, reasoning, model, repo_shas_json, cve_hash, tokens, status, session_id, commit_sha, created_at FROM triage_runs`
			insert = `INSERT INTO triage_runs (id, repository, cve_id, verdict, justification, confidence, evidence_json, reasoning, model, repo_shas_json, cve_hash, tokens, status, session_id, commit_sha, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
		}
		copies = append(copies, struct {
			name   string
			query  string
			insert string
		}{
			name:   "triage_runs",
			query:  query,
			insert: insert,
		})
	}

	var budgetTable int
	if err := src.QueryRowContext(ctx, `SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'triage_budget'`).Scan(&budgetTable); err != nil {
		return errors.NewTransientf("inspect triage_budget: %w", err)
	}
	if budgetTable > 0 {
		copies = append(copies, struct {
			name   string
			query  string
			insert string
		}{
			name:   "triage_budget",
			query:  `SELECT id, reset_at FROM triage_budget`,
			insert: `INSERT INTO triage_budget (id, reset_at) VALUES (?, ?)`,
		})
	}

	for _, job := range copies {
		n, err := copyQuery(ctx, src, tx, job.query, job.insert)
		if err != nil {
			return errors.NewTransientf("copy %s: %w", job.name, err)
		}
		logger.Info("copied table", "table", job.name, "rows", n)
	}

	for _, a := range artifactPtrs {
		if !a.lastScanID.Valid {
			continue
		}
		if _, err := tx.ExecContext(ctx, `UPDATE artifacts SET last_scan_id = ? WHERE id = ?`, a.lastScanID.Int64, a.id); err != nil {
			return errors.NewTransientf("restore artifact last_scan_id: %w", err)
		}
	}

	sequences := []string{
		"repositories_id_seq",
		"artifacts_id_seq",
		"scan_records_id_seq",
		"scan_findings_id_seq",
		"clusters_id_seq",
		"cluster_images_id_seq",
		"cluster_images_seen_id_seq",
	}
	tables := []string{
		"repositories",
		"artifacts",
		"scan_records",
		"scan_findings",
		"clusters",
		"cluster_images",
		"cluster_images_seen",
	}
	for i, seq := range sequences {
		if _, err := tx.ExecContext(ctx, fmt.Sprintf(`
			SELECT setval('%s', COALESCE((SELECT MAX(id) FROM %s), 1), (SELECT MAX(id) FROM %s) IS NOT NULL)
		`, seq, tables[i], tables[i])); err != nil {
			return errors.NewTransientf("set sequence %s: %w", seq, err)
		}
	}
	if triageTable > 0 {
		if _, err := tx.ExecContext(ctx, `
			SELECT setval('triage_runs_id_seq', COALESCE((SELECT MAX(id) FROM triage_runs), 1), (SELECT MAX(id) FROM triage_runs) IS NOT NULL)
		`); err != nil {
			return errors.NewTransientf("set sequence triage_runs_id_seq: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return errors.NewTransientf("commit copy: %w", err)
	}
	logger.Info("sqlite to postgres copy complete")
	return nil
}

func sqliteHasColumn(ctx context.Context, src *DB, table, column string) (bool, error) {
	rows, err := src.QueryContext(ctx, fmt.Sprintf("PRAGMA table_info(%s)", table))
	if err != nil {
		return false, errors.NewTransientf("inspect %s columns: %w", table, err)
	}
	defer rows.Close()
	for rows.Next() {
		var (
			cid        int
			name       string
			colType    string
			notNull    int
			defaultV   sql.NullString
			primaryKey int
		)
		if err := rows.Scan(&cid, &name, &colType, &notNull, &defaultV, &primaryKey); err != nil {
			return false, errors.NewTransientf("scan %s column info: %w", table, err)
		}
		if name == column {
			return true, nil
		}
	}
	if err := rows.Err(); err != nil {
		return false, errors.NewTransientf("iterate %s column info: %w", table, err)
	}
	return false, nil
}

func findingCopyQuery(hasSeverity bool) string {
	if hasSeverity {
		return `SELECT id, scan_record_id, cve_id, package_name, installed_version, fixed_version, severity, created_at FROM scan_findings`
	}
	return `SELECT id, scan_record_id, cve_id, package_name, installed_version, fixed_version, created_at FROM scan_findings`
}

func findingCopyInsert(hasSeverity bool) string {
	if hasSeverity {
		return `INSERT INTO scan_findings (id, scan_record_id, cve_id, package_name, installed_version, fixed_version, severity, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
	}
	return `INSERT INTO scan_findings (id, scan_record_id, cve_id, package_name, installed_version, fixed_version, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)`
}

func openSQLiteReadOnly(dbPath string) (*DB, error) {
	connStr := dbPath + "?_foreign_keys=1&mode=ro"
	db, err := sql.Open("sqlite3", connStr)
	if err != nil {
		return nil, errors.NewTransientf("open sqlite for copy: %w", err)
	}
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, errors.NewTransientf("ping sqlite for copy: %w", err)
	}
	return wrapDB(db, dialectSQLite), nil
}

func copyQuery(ctx context.Context, src *DB, dst *Tx, selectSQL, insertSQL string) (int, error) {
	rows, err := src.QueryContext(ctx, selectSQL)
	if err != nil {
		return 0, err
	}
	defer rows.Close()

	cols, err := rows.Columns()
	if err != nil {
		return 0, err
	}

	n := 0
	for rows.Next() {
		vals := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return n, err
		}
		for i, col := range cols {
			vals[i] = normalizeCopyValue(col, vals[i])
		}
		if _, err := dst.ExecContext(ctx, insertSQL, vals...); err != nil {
			return n, err
		}
		n++
	}
	return n, rows.Err()
}

func normalizeCopyValue(column string, v any) any {
	if v == nil {
		return nil
	}
	if _, ok := sqliteBoolColumns[strings.ToLower(column)]; ok {
		switch t := v.(type) {
		case bool:
			return t
		case int64:
			return t != 0
		case int:
			return t != 0
		case []byte:
			s := string(t)
			return s == "1" || strings.EqualFold(s, "true")
		case string:
			return t == "1" || strings.EqualFold(t, "true")
		}
	}
	if b, ok := v.([]byte); ok {
		return string(b)
	}
	return v
}
