package statestore

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/daimoniac/suppline/internal/errors"
	_ "github.com/mattn/go-sqlite3"
)

// SQLiteStore implements StateStore using SQLite
type SQLiteStore struct {
	db                 *sql.DB
	runtimeInUseWindow time.Duration
}

const defaultRuntimeInUseWindow = 7 * 24 * time.Hour

type clusterImageIdentity struct {
	namespace string
	imageRef  string
	tag       string
}

type normalizedClusterImageGroup struct {
	identity   clusterImageIdentity
	digests    []string
	digestSeen map[string]struct{}
	hasEmpty   bool
}

// NewSQLiteStore creates a new SQLite state store
func NewSQLiteStore(dbPath string) (*SQLiteStore, error) {
	// Add pragmas and optimizations for better concurrent access
	// _foreign_keys=1: Ensures CASCADE DELETE works properly
	// mode=rwc: Read/Write/Create mode
	// _journal_mode=WAL: Write-Ahead Logging allows concurrent readers and a single writer
	// _busy_timeout=3000: Wait up to 3 seconds for locks to allow metrics to succeed
	connStr := dbPath + "?_foreign_keys=1&mode=rwc&_journal_mode=WAL&_busy_timeout=3000"

	db, err := sql.Open("sqlite3", connStr)
	if err != nil {
		return nil, errors.NewTransientf("failed to open sqlite database: %w", err)
	}

	// Configure connection pool for concurrent access with WAL mode
	// WAL mode supports one writer and multiple concurrent readers
	db.SetMaxOpenConns(5)
	db.SetMaxIdleConns(2)
	db.SetConnMaxLifetime(time.Hour)

	// Verify foreign keys are enabled
	var fkEnabled int
	if err := db.QueryRow("PRAGMA foreign_keys").Scan(&fkEnabled); err != nil {
		db.Close()
		return nil, errors.NewTransientf("failed to check foreign keys status: %w", err)
	}
	if fkEnabled != 1 {
		db.Close()
		return nil, errors.NewTransientf("foreign keys are not enabled (got %d, expected 1)", fkEnabled)
	}

	store := &SQLiteStore{db: db, runtimeInUseWindow: defaultRuntimeInUseWindow}

	// Initialize schema
	if err := store.initSchema(); err != nil {
		db.Close()
		return nil, errors.NewPermanentf("failed to initialize schema: %w", err)
	}

	return store, nil
}

// Close closes the database connection
func (s *SQLiteStore) Close() error {
	return s.db.Close()
}

// SetRuntimeInUseWindow configures the time window used to treat runtime images as in use.
func (s *SQLiteStore) SetRuntimeInUseWindow(window time.Duration) {
	if window <= 0 {
		s.runtimeInUseWindow = defaultRuntimeInUseWindow
		return
	}

	s.runtimeInUseWindow = window
}

// initSchema creates the database schema with all tables and indexes
func (s *SQLiteStore) initSchema() error {
	schema := `
	CREATE TABLE IF NOT EXISTS repositories (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL UNIQUE,
		registry TEXT,
		created_at INTEGER NOT NULL DEFAULT (cast(strftime('%s', 'now') as integer))
	);

	CREATE TABLE IF NOT EXISTS artifacts (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		repository_id INTEGER NOT NULL,
		digest TEXT NOT NULL,
		tag TEXT,
		first_seen INTEGER NOT NULL,
		last_seen INTEGER NOT NULL,
		image_created_at INTEGER,
		last_scan_id INTEGER,
		next_scan_at INTEGER,
		created_at INTEGER NOT NULL DEFAULT (cast(strftime('%s', 'now') as integer)),
		FOREIGN KEY (repository_id) REFERENCES repositories(id),
		FOREIGN KEY (last_scan_id) REFERENCES scan_records(id),
		UNIQUE(repository_id, digest, tag)
	);

	CREATE TABLE IF NOT EXISTS scan_records (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		artifact_id INTEGER NOT NULL,
		scan_duration_ms INTEGER,
		critical_vuln_count INTEGER NOT NULL,
		high_vuln_count INTEGER NOT NULL,
		medium_vuln_count INTEGER NOT NULL,
		low_vuln_count INTEGER NOT NULL,
		policy_passed BOOLEAN NOT NULL,
		policy_status TEXT NOT NULL DEFAULT '',
		policy_reason TEXT NOT NULL DEFAULT '',
		release_age_seconds INTEGER NOT NULL DEFAULT 0,
		minimum_release_age_seconds INTEGER NOT NULL DEFAULT 0,
		release_age_source TEXT NOT NULL DEFAULT '',
		sbom_attested BOOLEAN NOT NULL,
		vuln_attested BOOLEAN NOT NULL,
		scai_attested BOOLEAN NOT NULL,
		error_message TEXT,
		created_at INTEGER NOT NULL DEFAULT (cast(strftime('%s', 'now') as integer)),
		FOREIGN KEY (artifact_id) REFERENCES artifacts(id) ON DELETE CASCADE
	);

	CREATE TABLE IF NOT EXISTS vulnerabilities (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		scan_record_id INTEGER NOT NULL,
		cve_id TEXT NOT NULL,
		severity TEXT NOT NULL,
		package_name TEXT NOT NULL,
		installed_version TEXT,
		fixed_version TEXT,
		title TEXT,
		description TEXT,
		primary_url TEXT,
		created_at INTEGER NOT NULL DEFAULT (cast(strftime('%s', 'now') as integer)),
		FOREIGN KEY (scan_record_id) REFERENCES scan_records(id) ON DELETE CASCADE
	);

	CREATE TABLE IF NOT EXISTS clusters (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL UNIQUE,
		last_reported_at INTEGER,
		created_at INTEGER NOT NULL DEFAULT (cast(strftime('%s', 'now') as integer))
	);

	CREATE TABLE IF NOT EXISTS cluster_images (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		cluster_id INTEGER NOT NULL,
		namespace TEXT NOT NULL,
		image_ref TEXT NOT NULL,
		tag TEXT,
		digest TEXT,
		reported_at INTEGER NOT NULL,
		FOREIGN KEY (cluster_id) REFERENCES clusters(id) ON DELETE CASCADE
	);

	CREATE TABLE IF NOT EXISTS cluster_images_seen (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		cluster_id INTEGER NOT NULL,
		namespace TEXT NOT NULL,
		image_ref TEXT NOT NULL,
		tag TEXT NOT NULL DEFAULT '',
		digest TEXT NOT NULL DEFAULT '',
		first_seen_at INTEGER NOT NULL,
		last_seen_at INTEGER NOT NULL,
		FOREIGN KEY (cluster_id) REFERENCES clusters(id) ON DELETE CASCADE,
		UNIQUE(cluster_id, namespace, image_ref, tag, digest)
	);

	CREATE TABLE IF NOT EXISTS runtime_unused_repository_whitelist (
		repository TEXT PRIMARY KEY,
		created_at INTEGER NOT NULL DEFAULT (cast(strftime('%s', 'now') as integer))
	);

	CREATE INDEX IF NOT EXISTS idx_artifacts_repository ON artifacts(repository_id);
	CREATE INDEX IF NOT EXISTS idx_artifacts_digest ON artifacts(digest);
	CREATE INDEX IF NOT EXISTS idx_artifacts_next_scan ON artifacts(next_scan_at);
	CREATE INDEX IF NOT EXISTS idx_scan_records_artifact ON scan_records(artifact_id);
	CREATE INDEX IF NOT EXISTS idx_scan_records_created ON scan_records(created_at);
	CREATE INDEX IF NOT EXISTS idx_vulnerabilities_scan ON vulnerabilities(scan_record_id);
	CREATE INDEX IF NOT EXISTS idx_vulnerabilities_cve ON vulnerabilities(cve_id);
	CREATE INDEX IF NOT EXISTS idx_vulnerabilities_cve_scan ON vulnerabilities(cve_id, scan_record_id);
	CREATE INDEX IF NOT EXISTS idx_vulnerabilities_severity ON vulnerabilities(severity);
	CREATE INDEX IF NOT EXISTS idx_artifacts_last_scan ON artifacts(last_scan_id);
	CREATE INDEX IF NOT EXISTS idx_vulnerabilities_scan_severity_cve ON vulnerabilities(scan_record_id, severity, cve_id);
	CREATE INDEX IF NOT EXISTS idx_artifacts_last_scan_repo_digest ON artifacts(last_scan_id, repository_id, digest);
	CREATE INDEX IF NOT EXISTS idx_cluster_images_cluster ON cluster_images(cluster_id);
	CREATE INDEX IF NOT EXISTS idx_cluster_images_digest ON cluster_images(digest);
	CREATE INDEX IF NOT EXISTS idx_cluster_images_image_ref_tag ON cluster_images(image_ref, tag);
	CREATE INDEX IF NOT EXISTS idx_cluster_images_seen_cluster ON cluster_images_seen(cluster_id);
	CREATE INDEX IF NOT EXISTS idx_cluster_images_seen_digest ON cluster_images_seen(digest);
	CREATE INDEX IF NOT EXISTS idx_cluster_images_seen_image_ref_tag ON cluster_images_seen(image_ref, tag);
	CREATE INDEX IF NOT EXISTS idx_cluster_images_seen_last_seen_at ON cluster_images_seen(last_seen_at);
	CREATE INDEX IF NOT EXISTS idx_runtime_unused_repo_whitelist_created_at ON runtime_unused_repository_whitelist(created_at);
	`

	_, err := s.db.Exec(schema)
	if err != nil {
		return err
	}

	if err := s.ensureSchemaColumns(); err != nil {
		return err
	}

	return nil
}

func (s *SQLiteStore) ensureSchemaColumns() error {
	type colDef struct {
		table      string
		column     string
		definition string
	}

	columns := []colDef{
		{table: "artifacts", column: "image_created_at", definition: "INTEGER"},
		{table: "scan_records", column: "policy_status", definition: "TEXT NOT NULL DEFAULT ''"},
		{table: "scan_records", column: "policy_reason", definition: "TEXT NOT NULL DEFAULT ''"},
		{table: "scan_records", column: "release_age_seconds", definition: "INTEGER NOT NULL DEFAULT 0"},
		{table: "scan_records", column: "minimum_release_age_seconds", definition: "INTEGER NOT NULL DEFAULT 0"},
		{table: "scan_records", column: "release_age_source", definition: "TEXT NOT NULL DEFAULT ''"},
		{table: "scan_records", column: "vex_statements_json", definition: "TEXT"},
		{table: "scan_records", column: "vex_attested", definition: "BOOLEAN NOT NULL DEFAULT 0"},
	}

	for _, col := range columns {
		hasCol, err := s.hasColumn(col.table, col.column)
		if err != nil {
			return err
		}
		if hasCol {
			continue
		}

		if _, err := s.db.Exec(fmt.Sprintf("ALTER TABLE %s ADD COLUMN %s %s", col.table, col.column, col.definition)); err != nil {
			return err
		}
	}

	return nil
}

func (s *SQLiteStore) hasColumn(tableName, columnName string) (bool, error) {
	rows, err := s.db.Query(fmt.Sprintf("PRAGMA table_info(%s)", tableName))
	if err != nil {
		return false, errors.NewTransientf("failed to inspect schema for table %s: %w", tableName, err)
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
			return false, errors.NewTransientf("failed to parse schema info for table %s: %w", tableName, err)
		}
		if name == columnName {
			return true, nil
		}
	}

	if err := rows.Err(); err != nil {
		return false, errors.NewTransientf("failed to iterate schema info for table %s: %w", tableName, err)
	}

	return false, nil
}
