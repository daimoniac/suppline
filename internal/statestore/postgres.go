package statestore

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/daimoniac/suppline/internal/errors"
	_ "github.com/jackc/pgx/v5/stdlib"
)

// NewPostgresStore opens PostgreSQL and creates the catalog schema if needed.
func NewPostgresStore(url string) (*SQLiteStore, error) {
	db, err := sql.Open("pgx", url)
	if err != nil {
		return nil, errors.NewTransientf("failed to open postgres database: %w", err)
	}

	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(time.Hour)

	if err := db.Ping(); err != nil {
		db.Close()
		return nil, errors.NewTransientf("failed to ping postgres: %w", err)
	}

	store := &SQLiteStore{db: wrapDB(db, dialectPostgres), runtimeInUseWindow: defaultRuntimeInUseWindow}
	if err := store.initSchema(); err != nil {
		db.Close()
		return nil, errors.NewPermanentf("failed to initialize schema: %w", err)
	}
	return store, nil
}

func (s *SQLiteStore) initPostgresSchema() error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS repositories (
			id BIGSERIAL PRIMARY KEY,
			name TEXT NOT NULL UNIQUE,
			registry TEXT,
			created_at BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM CLOCK_TIMESTAMP())::BIGINT)
		)`,
		`CREATE TABLE IF NOT EXISTS artifacts (
			id BIGSERIAL PRIMARY KEY,
			repository_id BIGINT NOT NULL REFERENCES repositories(id),
			digest TEXT NOT NULL,
			tag TEXT,
			first_seen BIGINT NOT NULL,
			last_seen BIGINT NOT NULL,
			image_created_at BIGINT,
			last_scan_id BIGINT,
			next_scan_at BIGINT,
			created_at BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM CLOCK_TIMESTAMP())::BIGINT),
			UNIQUE(repository_id, digest, tag)
		)`,
		`CREATE TABLE IF NOT EXISTS scan_records (
			id BIGSERIAL PRIMARY KEY,
			artifact_id BIGINT NOT NULL REFERENCES artifacts(id) ON DELETE CASCADE,
			scan_duration_ms BIGINT,
			critical_vuln_count INTEGER NOT NULL,
			high_vuln_count INTEGER NOT NULL,
			medium_vuln_count INTEGER NOT NULL,
			low_vuln_count INTEGER NOT NULL,
			policy_passed BOOLEAN NOT NULL,
			policy_status TEXT NOT NULL DEFAULT '',
			policy_reason TEXT NOT NULL DEFAULT '',
			policy_failure_findings_json TEXT,
			release_age_seconds INTEGER NOT NULL DEFAULT 0,
			minimum_release_age_seconds INTEGER NOT NULL DEFAULT 0,
			release_age_source TEXT NOT NULL DEFAULT '',
			sbom_attested BOOLEAN NOT NULL,
			vuln_attested BOOLEAN NOT NULL,
			scai_attested BOOLEAN NOT NULL,
			vex_attested BOOLEAN NOT NULL DEFAULT FALSE,
			error_message TEXT,
			vex_statements_json TEXT,
			created_at BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM CLOCK_TIMESTAMP())::BIGINT)
		)`,
		`CREATE TABLE IF NOT EXISTS cve_catalog (
			cve_id TEXT PRIMARY KEY,
			severity TEXT NOT NULL,
			title TEXT,
			description TEXT,
			primary_url TEXT
		)`,
		`CREATE TABLE IF NOT EXISTS scan_findings (
			id BIGSERIAL PRIMARY KEY,
			scan_record_id BIGINT NOT NULL REFERENCES scan_records(id) ON DELETE CASCADE,
			cve_id TEXT NOT NULL REFERENCES cve_catalog(cve_id),
			package_name TEXT NOT NULL,
			installed_version TEXT,
			fixed_version TEXT,
			created_at BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM CLOCK_TIMESTAMP())::BIGINT)
		)`,
		`CREATE TABLE IF NOT EXISTS cve_first_seen (
			artifact_id BIGINT NOT NULL REFERENCES artifacts(id) ON DELETE CASCADE,
			cve_id TEXT NOT NULL REFERENCES cve_catalog(cve_id),
			first_seen_at BIGINT NOT NULL,
			PRIMARY KEY (artifact_id, cve_id)
		)`,
		`CREATE TABLE IF NOT EXISTS clusters (
			id BIGSERIAL PRIMARY KEY,
			name TEXT NOT NULL UNIQUE,
			last_reported_at BIGINT,
			created_at BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM CLOCK_TIMESTAMP())::BIGINT)
		)`,
		`CREATE TABLE IF NOT EXISTS cluster_images (
			id BIGSERIAL PRIMARY KEY,
			cluster_id BIGINT NOT NULL REFERENCES clusters(id) ON DELETE CASCADE,
			namespace TEXT NOT NULL,
			image_ref TEXT NOT NULL,
			tag TEXT,
			digest TEXT,
			reported_at BIGINT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS cluster_images_seen (
			id BIGSERIAL PRIMARY KEY,
			cluster_id BIGINT NOT NULL REFERENCES clusters(id) ON DELETE CASCADE,
			namespace TEXT NOT NULL,
			image_ref TEXT NOT NULL,
			tag TEXT NOT NULL DEFAULT '',
			digest TEXT NOT NULL DEFAULT '',
			first_seen_at BIGINT NOT NULL,
			last_seen_at BIGINT NOT NULL,
			UNIQUE(cluster_id, namespace, image_ref, tag, digest)
		)`,
		`CREATE TABLE IF NOT EXISTS runtime_unused_repository_whitelist (
			repository TEXT PRIMARY KEY,
			created_at BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM CLOCK_TIMESTAMP())::BIGINT)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_artifacts_repository ON artifacts(repository_id)`,
		`CREATE INDEX IF NOT EXISTS idx_artifacts_digest ON artifacts(digest)`,
		`CREATE INDEX IF NOT EXISTS idx_artifacts_next_scan ON artifacts(next_scan_at)`,
		`CREATE INDEX IF NOT EXISTS idx_scan_records_artifact ON scan_records(artifact_id)`,
		`CREATE INDEX IF NOT EXISTS idx_scan_records_created ON scan_records(created_at)`,
		`CREATE INDEX IF NOT EXISTS idx_scan_findings_scan ON scan_findings(scan_record_id)`,
		`CREATE INDEX IF NOT EXISTS idx_scan_findings_cve_scan ON scan_findings(cve_id, scan_record_id)`,
		`CREATE INDEX IF NOT EXISTS idx_cve_catalog_severity ON cve_catalog(severity)`,
		`CREATE INDEX IF NOT EXISTS idx_artifacts_last_scan ON artifacts(last_scan_id)`,
		`CREATE INDEX IF NOT EXISTS idx_artifacts_last_scan_repo_digest ON artifacts(last_scan_id, repository_id, digest)`,
		`CREATE INDEX IF NOT EXISTS idx_cluster_images_cluster ON cluster_images(cluster_id)`,
		`CREATE INDEX IF NOT EXISTS idx_cluster_images_digest ON cluster_images(digest)`,
		`CREATE INDEX IF NOT EXISTS idx_cluster_images_image_ref_tag ON cluster_images(image_ref, tag)`,
		`CREATE INDEX IF NOT EXISTS idx_cluster_images_seen_cluster ON cluster_images_seen(cluster_id)`,
		`CREATE INDEX IF NOT EXISTS idx_cluster_images_seen_digest ON cluster_images_seen(digest)`,
		`CREATE INDEX IF NOT EXISTS idx_cluster_images_seen_image_ref_tag ON cluster_images_seen(image_ref, tag)`,
		`CREATE INDEX IF NOT EXISTS idx_cluster_images_seen_last_seen_at ON cluster_images_seen(last_seen_at)`,
		`CREATE INDEX IF NOT EXISTS idx_runtime_unused_repo_whitelist_created_at ON runtime_unused_repository_whitelist(created_at)`,
	}

	for _, stmt := range stmts {
		if _, err := s.db.Exec(stmt); err != nil {
			return fmt.Errorf("postgres schema: %w", err)
		}
	}

	// Drop SQLite-era indexes that Postgres does not use (prefix or covering duplicates).
	for _, name := range []string{
		"idx_scan_findings_cve",
		"idx_scan_findings_scan_cve",
		"idx_cve_first_seen_cve",
	} {
		if _, err := s.db.Exec(`DROP INDEX IF EXISTS ` + name); err != nil {
			return fmt.Errorf("drop redundant index %s: %w", name, err)
		}
	}

	var fkExists int
	if err := s.db.QueryRow(`
		SELECT COUNT(*) FROM pg_constraint WHERE conname = 'artifacts_last_scan_id_fkey'
	`).Scan(&fkExists); err != nil {
		return fmt.Errorf("inspect artifacts last_scan_id fk: %w", err)
	}
	if fkExists == 0 {
		if _, err := s.db.Exec(`
			ALTER TABLE artifacts
			ADD CONSTRAINT artifacts_last_scan_id_fkey
			FOREIGN KEY (last_scan_id) REFERENCES scan_records(id)
		`); err != nil {
			return fmt.Errorf("add artifacts last_scan_id fk: %w", err)
		}
	}

	return nil
}
