package statestore

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/daimoniac/suppline/internal/errors"
	"github.com/daimoniac/suppline/internal/types"
)

// SQLiteStore implements StateStore using SQLite
type SQLiteStore struct {
	db *sql.DB
}

// NewSQLiteStore creates a new SQLite state store
func NewSQLiteStore(dbPath string) (*SQLiteStore, error) {
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, errors.NewTransientf("failed to open sqlite database: %w", err)
	}

	// Enable foreign keys
	if _, err := db.Exec("PRAGMA foreign_keys = ON"); err != nil {
		db.Close()
		return nil, errors.NewTransientf("failed to enable foreign keys: %w", err)
	}

	store := &SQLiteStore{db: db}

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
		digest TEXT NOT NULL UNIQUE,
		tag TEXT,
		first_seen INTEGER NOT NULL,
		last_seen INTEGER NOT NULL,
		last_scan_id INTEGER,
		next_scan_at INTEGER,
		created_at INTEGER NOT NULL DEFAULT (cast(strftime('%s', 'now') as integer)),
		FOREIGN KEY (repository_id) REFERENCES repositories(id),
		FOREIGN KEY (last_scan_id) REFERENCES scan_records(id)
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

	CREATE TABLE IF NOT EXISTS tolerated_cves (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		repository_id INTEGER NOT NULL,
		artifact_id INTEGER,
		cve_id TEXT NOT NULL,
		statement TEXT NOT NULL,
		tolerated_at INTEGER NOT NULL,
		expires_at INTEGER,
		created_at INTEGER NOT NULL DEFAULT (cast(strftime('%s', 'now') as integer)),
		FOREIGN KEY (repository_id) REFERENCES repositories(id),
		FOREIGN KEY (artifact_id) REFERENCES artifacts(id),
		UNIQUE(repository_id, cve_id)
	);

	CREATE INDEX IF NOT EXISTS idx_artifacts_repository ON artifacts(repository_id);
	CREATE INDEX IF NOT EXISTS idx_artifacts_digest ON artifacts(digest);
	CREATE INDEX IF NOT EXISTS idx_artifacts_next_scan ON artifacts(next_scan_at);
	CREATE INDEX IF NOT EXISTS idx_scan_records_artifact ON scan_records(artifact_id);
	CREATE INDEX IF NOT EXISTS idx_scan_records_created ON scan_records(created_at);
	CREATE INDEX IF NOT EXISTS idx_vulnerabilities_scan ON vulnerabilities(scan_record_id);
	CREATE INDEX IF NOT EXISTS idx_vulnerabilities_cve ON vulnerabilities(cve_id);
	CREATE INDEX IF NOT EXISTS idx_vulnerabilities_severity ON vulnerabilities(severity);
	CREATE INDEX IF NOT EXISTS idx_tolerated_repository ON tolerated_cves(repository_id);
	CREATE INDEX IF NOT EXISTS idx_tolerated_cve ON tolerated_cves(cve_id);
	CREATE INDEX IF NOT EXISTS idx_tolerated_expires ON tolerated_cves(expires_at) WHERE expires_at IS NOT NULL;
	`

	_, err := s.db.Exec(schema)
	return err
}

// RecordScan saves scan results with full vulnerability details in a transaction
func (s *SQLiteStore) RecordScan(ctx context.Context, record *ScanRecord) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return errors.NewTransientf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// Create or get repository by name
	var repositoryID int64
	err = tx.QueryRowContext(ctx, `
		SELECT id FROM repositories WHERE name = ?
	`, record.Repository).Scan(&repositoryID)
	if err == sql.ErrNoRows {
		// Repository doesn't exist, create it
		result, err := tx.ExecContext(ctx, `
			INSERT INTO repositories (name) VALUES (?)
		`, record.Repository)
		if err != nil {
			return errors.NewTransientf("failed to insert repository: %w", err)
		}
		repositoryID, err = result.LastInsertId()
		if err != nil {
			return errors.NewTransientf("failed to get repository ID: %w", err)
		}
	} else if err != nil {
		return errors.NewTransientf("failed to query repository: %w", err)
	}

	// Create or update artifact
	nowUnix := time.Now().Unix()
	var artifactID int64
	var existingArtifactID sql.NullInt64
	err = tx.QueryRowContext(ctx, `
		SELECT id FROM artifacts WHERE digest = ?
	`, record.Digest).Scan(&existingArtifactID)
	if err == sql.ErrNoRows {
		// Artifact doesn't exist, create it
		result, err := tx.ExecContext(ctx, `
			INSERT INTO artifacts (repository_id, digest, tag, first_seen, last_seen)
			VALUES (?, ?, ?, ?, ?)
		`, repositoryID, record.Digest, record.Tag, nowUnix, nowUnix)
		if err != nil {
			return errors.NewTransientf("failed to insert artifact: %w", err)
		}
		artifactID, err = result.LastInsertId()
		if err != nil {
			return errors.NewTransientf("failed to get artifact ID: %w", err)
		}
	} else if err != nil {
		return errors.NewTransientf("failed to query artifact: %w", err)
	} else {
		// Artifact exists, update last_seen and tag
		artifactID = existingArtifactID.Int64
		_, err := tx.ExecContext(ctx, `
			UPDATE artifacts SET last_seen = ?, tag = ? WHERE id = ?
		`, nowUnix, record.Tag, artifactID)
		if err != nil {
			return errors.NewTransientf("failed to update artifact: %w", err)
		}
	}

	// Insert scan record
	result, err := tx.ExecContext(ctx, `
		INSERT INTO scan_records (
			artifact_id, scan_duration_ms,
			critical_vuln_count, high_vuln_count, medium_vuln_count, low_vuln_count,
			policy_passed, sbom_attested, vuln_attested, scai_attested, error_message
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`,
		artifactID, record.ScanDurationMs,
		record.CriticalVulnCount, record.HighVulnCount, record.MediumVulnCount, record.LowVulnCount,
		record.PolicyPassed, record.SBOMAttested, record.VulnAttested, record.SCAIAttested, record.ErrorMessage,
	)
	if err != nil {
		return errors.NewTransientf("failed to insert scan record: %w", err)
	}

	scanRecordID, err := result.LastInsertId()
	if err != nil {
		return errors.NewTransientf("failed to get scan record ID: %w", err)
	}

	// Update artifact's last_scan_id and next_scan_at
	// Set next_scan_at to now (due for rescan immediately by default)
	// This will be updated by the worker based on scan interval configuration
	_, err = tx.ExecContext(ctx, `
		UPDATE artifacts SET last_scan_id = ?, next_scan_at = ? WHERE id = ?
	`, scanRecordID, nowUnix, artifactID)
	if err != nil {
		return errors.NewTransientf("failed to update artifact last_scan_id and next_scan_at: %w", err)
	}

	// Insert vulnerabilities linked to this scan record
	if len(record.Vulnerabilities) > 0 {
		vulnStmt, err := tx.PrepareContext(ctx, `
			INSERT INTO vulnerabilities (
				scan_record_id, cve_id, severity, package_name,
				installed_version, fixed_version, title, description, primary_url
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		`)
		if err != nil {
			return errors.NewTransientf("failed to prepare vulnerability statement: %w", err)
		}
		defer vulnStmt.Close()

		for _, vuln := range record.Vulnerabilities {
			_, err := vulnStmt.ExecContext(ctx,
				scanRecordID, vuln.CVEID, vuln.Severity, vuln.PackageName,
				vuln.InstalledVersion, vuln.FixedVersion, vuln.Title, vuln.Description, vuln.PrimaryURL,
			)
			if err != nil {
				return errors.NewTransientf("failed to insert vulnerability: %w", err)
			}
		}
	}

	// Insert tolerated CVEs
	if len(record.ToleratedCVEs) > 0 {
		toleratedStmt, err := tx.PrepareContext(ctx, `
			INSERT INTO tolerated_cves (
				repository_id, cve_id, statement, tolerated_at, expires_at
			) VALUES (?, ?, ?, ?, ?)
			ON CONFLICT(repository_id, cve_id) DO UPDATE SET
				statement = excluded.statement,
				tolerated_at = excluded.tolerated_at,
				expires_at = excluded.expires_at
		`)
		if err != nil {
			return errors.NewTransientf("failed to prepare tolerated CVE statement: %w", err)
		}
		defer toleratedStmt.Close()

		for _, tolerated := range record.ToleratedCVEs {
			var expiresAtUnix interface{} = nil
			if tolerated.ExpiresAt != nil {
				expiresAtUnix = *tolerated.ExpiresAt
			}
			_, err := toleratedStmt.ExecContext(ctx,
				repositoryID, tolerated.CVEID, tolerated.Statement, tolerated.ToleratedAt, expiresAtUnix,
			)
			if err != nil {
				return errors.NewTransientf("failed to insert tolerated CVE: %w", err)
			}
		}
	}

	if err := tx.Commit(); err != nil {
		return errors.NewTransientf("failed to commit transaction: %w", err)
	}

	return nil
}

// GetLastScan retrieves the most recent scan for a digest with vulnerabilities
func (s *SQLiteStore) GetLastScan(ctx context.Context, digest string) (*ScanRecord, error) {
	var record ScanRecord
	var repositoryID int64

	err := s.db.QueryRowContext(ctx, `
		SELECT sr.id, sr.artifact_id, sr.scan_duration_ms,
			sr.critical_vuln_count, sr.high_vuln_count, sr.medium_vuln_count, sr.low_vuln_count,
			sr.policy_passed, sr.sbom_attested, sr.vuln_attested, sr.scai_attested, sr.error_message, sr.created_at,
			a.digest, a.tag, r.name, r.id
		FROM scan_records sr
		JOIN artifacts a ON sr.artifact_id = a.id
		JOIN repositories r ON a.repository_id = r.id
		WHERE a.digest = ?
		ORDER BY sr.created_at DESC, sr.id DESC
		LIMIT 1
	`, digest).Scan(
		&record.ID, &record.ArtifactID, &record.ScanDurationMs,
		&record.CriticalVulnCount, &record.HighVulnCount, &record.MediumVulnCount, &record.LowVulnCount,
		&record.PolicyPassed, &record.SBOMAttested, &record.VulnAttested, &record.SCAIAttested, &record.ErrorMessage, &record.CreatedAt,
		&record.Digest, &record.Tag, &record.Repository, &repositoryID,
	)
	if err == sql.ErrNoRows {
		return nil, ErrScanNotFound
	}
	if err != nil {
		return nil, errors.NewTransientf("failed to query scan record: %w", err)
	}

	// Load vulnerabilities for this scan
	vulns, err := s.loadVulnerabilitiesByScan(ctx, record.ID)
	if err != nil {
		return nil, err
	}
	record.Vulnerabilities = vulns

	// Load tolerated CVEs
	tolerated, err := s.loadToleratedCVEsByRepository(ctx, repositoryID)
	if err != nil {
		return nil, err
	}
	record.ToleratedCVEs = tolerated

	return &record, nil
}

// ListDueForRescan returns digests that need rescanning
// Returns artifacts where next_scan_at is in the past (due for rescan now)
func (s *SQLiteStore) ListDueForRescan(ctx context.Context, interval time.Duration) ([]string, error) {
	nowUnix := time.Now().Unix()

	rows, err := s.db.QueryContext(ctx, `
		SELECT digest
		FROM artifacts
		WHERE last_scan_id IS NOT NULL AND next_scan_at < ?
		ORDER BY next_scan_at ASC
	`, nowUnix)
	if err != nil {
		return nil, errors.NewTransientf("failed to query due for rescan: %w", err)
	}
	defer rows.Close()

	var digests []string
	for rows.Next() {
		var digest string
		if err := rows.Scan(&digest); err != nil {
			return nil, errors.NewTransientf("failed to scan digest: %w", err)
		}
		digests = append(digests, digest)
	}

	if err := rows.Err(); err != nil {
		return nil, errors.NewTransientf("error iterating rows: %w", err)
	}

	return digests, nil
}

// GetScanHistory returns scan history for a digest with full details
func (s *SQLiteStore) GetScanHistory(ctx context.Context, digest string, limit int) ([]*ScanRecord, error) {
	query := `
		SELECT sr.id, sr.artifact_id, sr.scan_duration_ms,
			sr.critical_vuln_count, sr.high_vuln_count, sr.medium_vuln_count, sr.low_vuln_count,
			sr.policy_passed, sr.sbom_attested, sr.vuln_attested, sr.scai_attested, sr.error_message, sr.created_at,
			a.digest, a.tag, r.name, r.id
		FROM scan_records sr
		JOIN artifacts a ON sr.artifact_id = a.id
		JOIN repositories r ON a.repository_id = r.id
		WHERE a.digest = ?
		ORDER BY sr.created_at DESC
	`
	if limit > 0 {
		query += fmt.Sprintf(" LIMIT %d", limit)
	}

	rows, err := s.db.QueryContext(ctx, query, digest)
	if err != nil {
		return nil, errors.NewTransientf("failed to query scan history: %w", err)
	}
	defer rows.Close()

	var records []*ScanRecord
	for rows.Next() {
		var record ScanRecord
		var repositoryID int64

		err := rows.Scan(
			&record.ID, &record.ArtifactID, &record.ScanDurationMs,
			&record.CriticalVulnCount, &record.HighVulnCount, &record.MediumVulnCount, &record.LowVulnCount,
			&record.PolicyPassed, &record.SBOMAttested, &record.VulnAttested, &record.SCAIAttested, &record.ErrorMessage, &record.CreatedAt,
			&record.Digest, &record.Tag, &record.Repository, &repositoryID,
		)
		if err != nil {
			return nil, errors.NewTransientf("failed to scan row: %w", err)
		}

		// Load vulnerabilities for this scan
		vulns, err := s.loadVulnerabilitiesByScan(ctx, record.ID)
		if err != nil {
			return nil, err
		}
		record.Vulnerabilities = vulns

		// Load tolerated CVEs
		tolerated, err := s.loadToleratedCVEsByRepository(ctx, repositoryID)
		if err != nil {
			return nil, err
		}
		record.ToleratedCVEs = tolerated

		records = append(records, &record)
	}

	if err := rows.Err(); err != nil {
		return nil, errors.NewTransientf("error iterating rows: %w", err)
	}

	return records, nil
}

// QueryVulnerabilities searches vulnerabilities across all scans
func (s *SQLiteStore) QueryVulnerabilities(ctx context.Context, filter VulnFilter) ([]*types.VulnerabilityRecord, error) {
	query := `
		SELECT v.cve_id, v.severity, v.package_name,
			v.installed_version, v.fixed_version, v.title, v.description, v.primary_url,
			r.name, a.tag, a.digest, sr.created_at
		FROM vulnerabilities v
		JOIN scan_records sr ON v.scan_record_id = sr.id
		JOIN artifacts a ON sr.artifact_id = a.id
		JOIN repositories r ON a.repository_id = r.id
		WHERE sr.id = a.last_scan_id
	`
	args := []interface{}{}

	if filter.CVEID != "" {
		query += " AND v.cve_id = ?"
		args = append(args, filter.CVEID)
	}

	if filter.Severity != "" {
		query += " AND v.severity = ?"
		args = append(args, filter.Severity)
	}

	if filter.PackageName != "" {
		query += " AND v.package_name = ?"
		args = append(args, filter.PackageName)
	}

	if filter.Repository != "" {
		query += " AND r.name = ?"
		args = append(args, filter.Repository)
	}

	query += " ORDER BY v.severity, v.cve_id, r.name, a.tag"

	if filter.Limit > 0 {
		query += " LIMIT ?"
		args = append(args, filter.Limit)
	}

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, errors.NewTransientf("failed to query vulnerabilities: %w", err)
	}
	defer rows.Close()

	var vulnerabilities []*types.VulnerabilityRecord
	for rows.Next() {
		var vuln types.VulnerabilityRecord
		err := rows.Scan(
			&vuln.CVEID, &vuln.Severity, &vuln.PackageName,
			&vuln.InstalledVersion, &vuln.FixedVersion, &vuln.Title, &vuln.Description, &vuln.PrimaryURL,
			&vuln.Repository, &vuln.Tag, &vuln.Digest, &vuln.ScannedAt,
		)
		if err != nil {
			return nil, errors.NewTransientf("failed to scan vulnerability: %w", err)
		}
		vulnerabilities = append(vulnerabilities, &vuln)
	}

	if err := rows.Err(); err != nil {
		return nil, errors.NewTransientf("error iterating rows: %w", err)
	}

	return vulnerabilities, nil
}

// GetImagesByCVE returns all images affected by a specific CVE
func (s *SQLiteStore) GetImagesByCVE(ctx context.Context, cveID string) ([]*ScanRecord, error) {
	query := `
		SELECT DISTINCT sr.id, sr.artifact_id, sr.scan_duration_ms,
			sr.critical_vuln_count, sr.high_vuln_count, sr.medium_vuln_count, sr.low_vuln_count,
			sr.policy_passed, sr.sbom_attested, sr.vuln_attested, sr.scai_attested, sr.error_message, sr.created_at,
			a.digest, a.tag, r.name, r.id
		FROM scan_records sr
		JOIN artifacts a ON sr.artifact_id = a.id
		JOIN repositories r ON a.repository_id = r.id
		JOIN vulnerabilities v ON sr.id = v.scan_record_id
		WHERE v.cve_id = ?
		ORDER BY sr.created_at DESC
	`

	rows, err := s.db.QueryContext(ctx, query, cveID)
	if err != nil {
		return nil, errors.NewTransientf("failed to query images by CVE: %w", err)
	}
	defer rows.Close()

	var records []*ScanRecord
	for rows.Next() {
		var record ScanRecord
		var repositoryID int64

		err := rows.Scan(
			&record.ID, &record.ArtifactID, &record.ScanDurationMs,
			&record.CriticalVulnCount, &record.HighVulnCount, &record.MediumVulnCount, &record.LowVulnCount,
			&record.PolicyPassed, &record.SBOMAttested, &record.VulnAttested, &record.SCAIAttested, &record.ErrorMessage, &record.CreatedAt,
			&record.Digest, &record.Tag, &record.Repository, &repositoryID,
		)
		if err != nil {
			return nil, errors.NewTransientf("failed to scan row: %w", err)
		}

		// Load vulnerabilities for this scan
		vulns, err := s.loadVulnerabilitiesByScan(ctx, record.ID)
		if err != nil {
			return nil, err
		}
		record.Vulnerabilities = vulns

		// Load tolerated CVEs
		tolerated, err := s.loadToleratedCVEsByRepository(ctx, repositoryID)
		if err != nil {
			return nil, err
		}
		record.ToleratedCVEs = tolerated

		records = append(records, &record)
	}

	if err := rows.Err(); err != nil {
		return nil, errors.NewTransientf("error iterating rows: %w", err)
	}

	return records, nil
}

// loadVulnerabilitiesByScan loads all vulnerabilities for a specific scan record
func (s *SQLiteStore) loadVulnerabilitiesByScan(ctx context.Context, scanRecordID int64) ([]types.VulnerabilityRecord, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT cve_id, severity, package_name, installed_version, fixed_version,
			title, description, primary_url
		FROM vulnerabilities
		WHERE scan_record_id = ?
		ORDER BY severity, cve_id
	`, scanRecordID)
	if err != nil {
		return nil, errors.NewTransientf("failed to query vulnerabilities: %w", err)
	}
	defer rows.Close()

	var vulnerabilities []types.VulnerabilityRecord
	for rows.Next() {
		var vuln types.VulnerabilityRecord
		err := rows.Scan(
			&vuln.CVEID, &vuln.Severity, &vuln.PackageName, &vuln.InstalledVersion, &vuln.FixedVersion,
			&vuln.Title, &vuln.Description, &vuln.PrimaryURL,
		)
		if err != nil {
			return nil, errors.NewTransientf("failed to scan vulnerability: %w", err)
		}
		vulnerabilities = append(vulnerabilities, vuln)
	}

	if err := rows.Err(); err != nil {
		return nil, errors.NewTransientf("error iterating vulnerability rows: %w", err)
	}

	return vulnerabilities, nil
}

// loadToleratedCVEsByRepository loads all tolerated CVEs for a repository
func (s *SQLiteStore) loadToleratedCVEsByRepository(ctx context.Context, repositoryID int64) ([]types.ToleratedCVE, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT cve_id, statement, tolerated_at, expires_at
		FROM tolerated_cves
		WHERE repository_id = ?
		ORDER BY cve_id
	`, repositoryID)
	if err != nil {
		return nil, errors.NewTransientf("failed to query tolerated CVEs: %w", err)
	}
	defer rows.Close()

	var tolerated []types.ToleratedCVE
	for rows.Next() {
		var cve types.ToleratedCVE
		var expiresAtUnix sql.NullInt64
		err := rows.Scan(&cve.CVEID, &cve.Statement, &cve.ToleratedAt, &expiresAtUnix)
		if err != nil {
			return nil, errors.NewTransientf("failed to scan tolerated CVE: %w", err)
		}

		if expiresAtUnix.Valid {
			cve.ExpiresAt = &expiresAtUnix.Int64
		}

		tolerated = append(tolerated, cve)
	}

	if err := rows.Err(); err != nil {
		return nil, errors.NewTransientf("error iterating tolerated CVE rows: %w", err)
	}

	return tolerated, nil
}

// ListScans returns scan records with optional filters
func (s *SQLiteStore) ListScans(ctx context.Context, filter ScanFilter) ([]*ScanRecord, error) {
	query := `
		SELECT sr.id, sr.artifact_id, sr.scan_duration_ms,
			sr.critical_vuln_count, sr.high_vuln_count, sr.medium_vuln_count, sr.low_vuln_count,
			sr.policy_passed, sr.sbom_attested, sr.vuln_attested, sr.scai_attested, sr.error_message, sr.created_at,
			a.digest, a.tag, r.name
		FROM scan_records sr
		JOIN artifacts a ON sr.artifact_id = a.id
		JOIN repositories r ON a.repository_id = r.id
		WHERE 1=1
	`
	args := []interface{}{}

	if filter.Repository != "" {
		query += " AND r.name = ?"
		args = append(args, filter.Repository)
	}

	if filter.PolicyPassed != nil {
		query += " AND sr.policy_passed = ?"
		args = append(args, *filter.PolicyPassed)
	}

	// Add age filter if specified
	if filter.MaxAge > 0 {
		query += " AND sr.created_at >= strftime('%s', 'now', '-' || ? || ' seconds')"
		args = append(args, filter.MaxAge)
	}

	// Add sorting - currently only age_desc is supported (and is the default)
	switch filter.SortBy {
	case "age_desc", "":
		query += " ORDER BY sr.created_at DESC"
	default:
		// Default to age_desc for any unrecognized sort option
		query += " ORDER BY sr.created_at DESC"
	}

	if filter.Limit > 0 {
		query += " LIMIT ?"
		args = append(args, filter.Limit)
	}

	if filter.Offset > 0 {
		query += " OFFSET ?"
		args = append(args, filter.Offset)
	}

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, errors.NewTransientf("failed to list scans: %w", err)
	}
	defer rows.Close()

	var records []*ScanRecord
	for rows.Next() {
		var record ScanRecord

		err := rows.Scan(
			&record.ID, &record.ArtifactID, &record.ScanDurationMs,
			&record.CriticalVulnCount, &record.HighVulnCount, &record.MediumVulnCount, &record.LowVulnCount,
			&record.PolicyPassed, &record.SBOMAttested, &record.VulnAttested, &record.SCAIAttested, &record.ErrorMessage, &record.CreatedAt,
			&record.Digest, &record.Tag, &record.Repository,
		)
		if err != nil {
			return nil, errors.NewTransientf("failed to scan row: %w", err)
		}

		// Don't load vulnerabilities or tolerated CVEs for list operations
		// These are only needed for detail views, which use GetLastScan directly
		// This keeps list responses lightweight and fast

		records = append(records, &record)
	}

	if err := rows.Err(); err != nil {
		return nil, errors.NewTransientf("error iterating rows: %w", err)
	}

	return records, nil
}

// ListTolerations returns tolerated CVEs with optional filters
// Returns one entry per unique repository + CVE ID combination
func (s *SQLiteStore) ListTolerations(ctx context.Context, filter TolerationFilter) ([]*types.TolerationInfo, error) {
	query := `
		SELECT 
			tc.cve_id, 
			tc.statement, 
			tc.tolerated_at,
			tc.expires_at,
			r.name
		FROM tolerated_cves tc
		JOIN repositories r ON tc.repository_id = r.id
		WHERE 1=1
	`
	args := []interface{}{}

	if filter.CVEID != "" {
		query += " AND tc.cve_id = ?"
		args = append(args, filter.CVEID)
	}

	if filter.Repository != "" {
		query += " AND r.name = ?"
		args = append(args, filter.Repository)
	}

	nowUnix := time.Now().Unix()

	if filter.Expired != nil {
		if *filter.Expired {
			// Only expired tolerations
			query += " AND tc.expires_at IS NOT NULL AND tc.expires_at < ?"
			args = append(args, nowUnix)
		} else {
			// Only non-expired tolerations
			query += " AND (tc.expires_at IS NULL OR tc.expires_at >= ?)"
			args = append(args, nowUnix)
		}
	}

	if filter.ExpiringSoon != nil && *filter.ExpiringSoon {
		// Expiring within 7 days
		sevenDaysFromNowUnix := time.Now().Add(7 * 24 * time.Hour).Unix()
		query += " AND tc.expires_at IS NOT NULL AND tc.expires_at >= ? AND tc.expires_at <= ?"
		args = append(args, nowUnix, sevenDaysFromNowUnix)
	}

	query += " ORDER BY tc.expires_at, tc.cve_id, r.name"

	if filter.Limit > 0 {
		query += " LIMIT ?"
		args = append(args, filter.Limit)
	}

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, errors.NewTransientf("failed to list tolerations: %w", err)
	}
	defer rows.Close()

	var tolerations []*types.TolerationInfo
	for rows.Next() {
		var info types.TolerationInfo
		var expiresAtUnix sql.NullInt64

		err := rows.Scan(
			&info.CVEID,
			&info.Statement,
			&info.ToleratedAt,
			&expiresAtUnix,
			&info.Repository,
		)
		if err != nil {
			return nil, errors.NewTransientf("failed to scan toleration: %w", err)
		}

		if expiresAtUnix.Valid {
			info.ExpiresAt = &expiresAtUnix.Int64
		}

		tolerations = append(tolerations, &info)
	}

	if err := rows.Err(); err != nil {
		return nil, errors.NewTransientf("error iterating rows: %w", err)
	}

	return tolerations, nil
}

// ListRepositories returns all repositories with aggregated metadata
func (s *SQLiteStore) ListRepositories(ctx context.Context, filter RepositoryFilter) (*RepositoriesListResponse, error) {
	// First, get total count
	countQuery := `
		SELECT COUNT(DISTINCT r.id)
		FROM repositories r
		LEFT JOIN artifacts a ON r.id = a.repository_id
		LEFT JOIN scan_records sr ON a.last_scan_id = sr.id
		WHERE 1=1
	`
	countArgs := []interface{}{}

	if filter.Search != "" {
		countQuery += " AND r.name LIKE ?"
		countArgs = append(countArgs, "%"+filter.Search+"%")
	}

	if filter.MaxAge > 0 {
		countQuery += " AND (SELECT MAX(sr2.created_at) FROM scan_records sr2 JOIN artifacts a2 ON sr2.artifact_id = a2.id WHERE a2.repository_id = r.id) >= ?"
		countArgs = append(countArgs, time.Now().Unix()-int64(filter.MaxAge))
	}

	var total int
	err := s.db.QueryRowContext(ctx, countQuery, countArgs...).Scan(&total)
	if err != nil {
		return nil, errors.NewTransientf("failed to count repositories: %w", err)
	}

	// Query repositories with aggregated data
	query := `
		SELECT 
			r.id,
			r.name,
			COUNT(DISTINCT a.id) as tag_count,
			(SELECT MAX(sr2.created_at) FROM scan_records sr2 
			 JOIN artifacts a2 ON sr2.artifact_id = a2.id 
			 WHERE a2.repository_id = r.id) as last_scan_time,
			MAX(sr.critical_vuln_count) as max_critical,
			MAX(sr.high_vuln_count) as max_high,
			MAX(sr.medium_vuln_count) as max_medium,
			MAX(sr.low_vuln_count) as max_low,
			CASE WHEN COUNT(CASE WHEN sr.policy_passed = 0 THEN 1 END) > 0 THEN 0 ELSE 1 END as policy_passed
		FROM repositories r
		LEFT JOIN artifacts a ON r.id = a.repository_id
		LEFT JOIN scan_records sr ON a.last_scan_id = sr.id
		WHERE 1=1
	`
	args := []interface{}{}

	if filter.Search != "" {
		query += " AND r.name LIKE ?"
		args = append(args, "%"+filter.Search+"%")
	}

	if filter.MaxAge > 0 {
		query += " AND (SELECT MAX(sr2.created_at) FROM scan_records sr2 JOIN artifacts a2 ON sr2.artifact_id = a2.id WHERE a2.repository_id = r.id) >= ?"
		args = append(args, time.Now().Unix()-int64(filter.MaxAge))
	}

	query += " GROUP BY r.id, r.name"

	// Add sorting
	switch filter.SortBy {
	case "name_asc":
		query += " ORDER BY r.name ASC"
	case "name_desc":
		query += " ORDER BY r.name DESC"
	case "age_desc", "":
		// Default: most recently scanned first
		query += " ORDER BY last_scan_time DESC NULLS LAST"
	case "age_asc":
		// Oldest scanned first
		query += " ORDER BY last_scan_time ASC NULLS FIRST"
	case "status_asc":
		// Failed first (0), then passed (1)
		query += " ORDER BY policy_passed ASC, r.name ASC"
	case "status_desc":
		// Passed first (1), then failed (0)
		query += " ORDER BY policy_passed DESC, r.name ASC"
	default:
		query += " ORDER BY r.name ASC"
	}

	if filter.Limit > 0 {
		query += " LIMIT ?"
		args = append(args, filter.Limit)
	}

	if filter.Offset > 0 {
		query += " OFFSET ?"
		args = append(args, filter.Offset)
	}

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, errors.NewTransientf("failed to list repositories: %w", err)
	}
	defer rows.Close()

	var repositories []RepositoryInfo
	for rows.Next() {
		var repo RepositoryInfo
		var repoID int64 // repository id (not needed in response, but must scan into something)
		var lastScanTimeUnix sql.NullInt64
		var maxCritical sql.NullInt64
		var maxHigh sql.NullInt64
		var maxMedium sql.NullInt64
		var maxLow sql.NullInt64
		var policyPassed int

		err := rows.Scan(
			&repoID, // repository id (not needed in response)
			&repo.Name,
			&repo.TagCount,
			&lastScanTimeUnix,
			&maxCritical,
			&maxHigh,
			&maxMedium,
			&maxLow,
			&policyPassed,
		)
		if err != nil {
			return nil, errors.NewTransientf("failed to scan repository row: %w", err)
		}

		// Store Unix timestamps directly
		if lastScanTimeUnix.Valid {
			repo.LastScanTime = &lastScanTimeUnix.Int64
		}

		// Aggregate vulnerability counts from most vulnerable artifact
		if maxCritical.Valid {
			repo.VulnerabilityCount.Critical = int(maxCritical.Int64)
		}
		if maxHigh.Valid {
			repo.VulnerabilityCount.High = int(maxHigh.Int64)
		}
		if maxMedium.Valid {
			repo.VulnerabilityCount.Medium = int(maxMedium.Int64)
		}
		if maxLow.Valid {
			repo.VulnerabilityCount.Low = int(maxLow.Int64)
		}

		repo.PolicyPassed = policyPassed == 1

		repositories = append(repositories, repo)
	}

	if err := rows.Err(); err != nil {
		return nil, errors.NewTransientf("error iterating repository rows: %w", err)
	}

	return &RepositoriesListResponse{
		Repositories: repositories,
		Total:        total,
	}, nil
}

// GetRepository returns a repository with all its tags
func (s *SQLiteStore) GetRepository(ctx context.Context, name string, filter RepositoryTagFilter) (*RepositoryDetail, error) {
	// First, get total count of tags for this repository
	countQuery := `
		SELECT COUNT(DISTINCT a.id)
		FROM artifacts a
		JOIN repositories r ON a.repository_id = r.id
		WHERE r.name = ?
	`
	countArgs := []interface{}{name}

	if filter.Search != "" {
		countQuery += " AND a.tag LIKE ?"
		countArgs = append(countArgs, "%"+filter.Search+"%")
	}

	var total int
	err := s.db.QueryRowContext(ctx, countQuery, countArgs...).Scan(&total)
	if err != nil {
		return nil, errors.NewTransientf("failed to count tags: %w", err)
	}

	// Query tags with their scan data
	query := `
		SELECT 
			a.tag,
			a.digest,
			sr.created_at as last_scan_time,
			a.next_scan_at,
			COALESCE(sr.critical_vuln_count, 0) as critical,
			COALESCE(sr.high_vuln_count, 0) as high,
			COALESCE(sr.medium_vuln_count, 0) as medium,
			COALESCE(sr.low_vuln_count, 0) as low,
			COALESCE(sr.policy_passed, 1) as policy_passed
		FROM artifacts a
		JOIN repositories r ON a.repository_id = r.id
		LEFT JOIN scan_records sr ON a.last_scan_id = sr.id
		WHERE r.name = ?
	`
	args := []interface{}{name}

	if filter.Search != "" {
		query += " AND a.tag LIKE ?"
		args = append(args, "%"+filter.Search+"%")
	}

	query += " GROUP BY a.id"
	query += " ORDER BY a.tag ASC"

	if filter.Limit > 0 {
		query += " LIMIT ?"
		args = append(args, filter.Limit)
	}

	if filter.Offset > 0 {
		query += " OFFSET ?"
		args = append(args, filter.Offset)
	}

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, errors.NewTransientf("failed to get repository tags: %w", err)
	}
	defer rows.Close()

	detail := &RepositoryDetail{
		Name:  name,
		Tags:  []TagInfo{},
		Total: total,
	}

	for rows.Next() {
		var tag TagInfo
		var lastScanTimeUnix sql.NullInt64
		var nextScanTimeUnix sql.NullInt64
		var policyPassed int

		err := rows.Scan(
			&tag.Name,
			&tag.Digest,
			&lastScanTimeUnix,
			&nextScanTimeUnix,
			&tag.VulnerabilityCount.Critical,
			&tag.VulnerabilityCount.High,
			&tag.VulnerabilityCount.Medium,
			&tag.VulnerabilityCount.Low,
			&policyPassed,
		)
		if err != nil {
			return nil, errors.NewTransientf("failed to scan tag row: %w", err)
		}

		if lastScanTimeUnix.Valid {
			tag.LastScanTime = &lastScanTimeUnix.Int64
		}
		if nextScanTimeUnix.Valid {
			tag.NextScanTime = &nextScanTimeUnix.Int64
		}

		tag.PolicyPassed = policyPassed == 1

		detail.Tags = append(detail.Tags, tag)
	}

	if err := rows.Err(); err != nil {
		return nil, errors.NewTransientf("error iterating tag rows: %w", err)
	}

	return detail, nil
}

// CleanupArtifactScans removes all scan records for an artifact (MANIFEST_UNKNOWN case).
// Also removes the artifact and repository if they become empty.
// This is used when a manifest is no longer available in the registry.
func (s *SQLiteStore) CleanupArtifactScans(ctx context.Context, digest string) error {
	return s.executeCleanup(ctx, func(tx *sql.Tx) error {
		// First, get the artifact ID and repository ID
		var artifactID, repositoryID int64
		err := tx.QueryRowContext(ctx, `
			SELECT a.id, a.repository_id 
			FROM artifacts a 
			WHERE a.digest = ?
		`, digest).Scan(&artifactID, &repositoryID)
		if err == sql.ErrNoRows {
			// Artifact doesn't exist, nothing to clean up
			return nil
		}
		if err != nil {
			return errors.NewTransientf("failed to query artifact for cleanup: %w", err)
		}

		// First, clear the last_scan_id reference to avoid foreign key constraint issues
		_, err = tx.ExecContext(ctx, `
			UPDATE artifacts SET last_scan_id = NULL WHERE id = ?
		`, artifactID)
		if err != nil {
			return errors.NewTransientf("failed to clear last_scan_id reference: %w", err)
		}

		// Delete all scan records for this artifact (vulnerabilities will cascade delete)
		_, err = tx.ExecContext(ctx, `
			DELETE FROM scan_records WHERE artifact_id = ?
		`, artifactID)
		if err != nil {
			return errors.NewTransientf("failed to delete scan records: %w", err)
		}

		// Delete the artifact itself
		_, err = tx.ExecContext(ctx, `
			DELETE FROM artifacts WHERE id = ?
		`, artifactID)
		if err != nil {
			return errors.NewTransientf("failed to delete artifact: %w", err)
		}

		// Check if repository has any remaining artifacts or tolerated CVEs
		var remainingArtifacts, remainingToleratedCVEs int
		err = tx.QueryRowContext(ctx, `
			SELECT COUNT(*) FROM artifacts WHERE repository_id = ?
		`, repositoryID).Scan(&remainingArtifacts)
		if err != nil {
			return errors.NewTransientf("failed to count remaining artifacts: %w", err)
		}

		err = tx.QueryRowContext(ctx, `
			SELECT COUNT(*) FROM tolerated_cves WHERE repository_id = ?
		`, repositoryID).Scan(&remainingToleratedCVEs)
		if err != nil {
			return errors.NewTransientf("failed to count remaining tolerated CVEs: %w", err)
		}

		// If no artifacts and no tolerated CVEs remain, delete the repository
		if remainingArtifacts == 0 && remainingToleratedCVEs == 0 {
			_, err = tx.ExecContext(ctx, `
				DELETE FROM repositories WHERE id = ?
			`, repositoryID)
			if err != nil {
				return errors.NewTransientf("failed to delete empty repository: %w", err)
			}
		}

		return nil
	})
}

// executeCleanup is a helper method for transaction management in cleanup operations
func (s *SQLiteStore) executeCleanup(ctx context.Context, operation func(*sql.Tx) error) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return errors.NewTransientf("failed to begin cleanup transaction: %w", err)
	}
	defer tx.Rollback()

	if err := operation(tx); err != nil {
		return err // Error already classified by operation
	}

	if err := tx.Commit(); err != nil {
		return errors.NewTransientf("failed to commit cleanup transaction: %w", err)
	}

	return nil
}



// CleanupOrphanedRepositories removes repositories with no remaining artifacts.
// Returns a list of deleted repository names for logging purposes.
func (s *SQLiteStore) CleanupOrphanedRepositories(ctx context.Context) ([]string, error) {
	var deletedRepos []string

	err := s.executeCleanup(ctx, func(tx *sql.Tx) error {
		// Find repositories with no artifacts and no tolerated CVEs
		rows, err := tx.QueryContext(ctx, `
			SELECT r.id, r.name 
			FROM repositories r 
			LEFT JOIN artifacts a ON r.id = a.repository_id 
			LEFT JOIN tolerated_cves tc ON r.id = tc.repository_id
			WHERE a.id IS NULL AND tc.id IS NULL
		`)
		if err != nil {
			return errors.NewTransientf("failed to query orphaned repositories: %w", err)
		}
		defer rows.Close()

		var repoIDs []int64
		for rows.Next() {
			var repoID int64
			var repoName string
			if err := rows.Scan(&repoID, &repoName); err != nil {
				return errors.NewTransientf("failed to scan orphaned repository: %w", err)
			}
			repoIDs = append(repoIDs, repoID)
			deletedRepos = append(deletedRepos, repoName)
		}

		if err := rows.Err(); err != nil {
			return errors.NewTransientf("error iterating orphaned repositories: %w", err)
		}

		// Delete the orphaned repositories
		for _, repoID := range repoIDs {
			_, err := tx.ExecContext(ctx, `
				DELETE FROM repositories WHERE id = ?
			`, repoID)
			if err != nil {
				return errors.NewTransientf("failed to delete orphaned repository: %w", err)
			}
		}

		return nil
	})

	if err != nil {
		return nil, err
	}

	return deletedRepos, nil
}

// CleanupExcessScans removes excess scan records for an artifact, keeping only the most recent N scans.
// This provides a more robust cleanup that handles concurrent scans and ensures a maximum number of scans per artifact.
func (s *SQLiteStore) CleanupExcessScans(ctx context.Context, digest string, maxScansToKeep int) error {
	if maxScansToKeep <= 0 {
		return errors.NewPermanentf("maxScansToKeep must be positive, got %d", maxScansToKeep)
	}

	return s.executeCleanup(ctx, func(tx *sql.Tx) error {
		// First, get the artifact ID
		var artifactID int64
		err := tx.QueryRowContext(ctx, `
			SELECT id FROM artifacts WHERE digest = ?
		`, digest).Scan(&artifactID)
		if err == sql.ErrNoRows {
			// Artifact doesn't exist, nothing to clean up
			return nil
		}
		if err != nil {
			return errors.NewTransientf("failed to query artifact for cleanup: %w", err)
		}

		// Get scan IDs to keep (most recent N scans)
		rows, err := tx.QueryContext(ctx, `
			SELECT id FROM scan_records 
			WHERE artifact_id = ? 
			ORDER BY created_at DESC, id DESC 
			LIMIT ?
		`, artifactID, maxScansToKeep)
		if err != nil {
			return errors.NewTransientf("failed to query scans to keep: %w", err)
		}
		defer rows.Close()

		var keepScanIDs []int64
		for rows.Next() {
			var scanID int64
			if err := rows.Scan(&scanID); err != nil {
				return errors.NewTransientf("failed to scan keep scan ID: %w", err)
			}
			keepScanIDs = append(keepScanIDs, scanID)
		}

		if err := rows.Err(); err != nil {
			return errors.NewTransientf("error iterating keep scan IDs: %w", err)
		}

		// If we have fewer scans than the limit, nothing to clean up
		if len(keepScanIDs) < maxScansToKeep {
			return nil
		}

		// Build placeholders for the IN clause
		placeholders := make([]string, len(keepScanIDs))
		args := make([]interface{}, len(keepScanIDs)+1)
		args[0] = artifactID
		for i, scanID := range keepScanIDs {
			placeholders[i] = "?"
			args[i+1] = scanID
		}

		// Delete scan records not in the keep list
		deleteQuery := fmt.Sprintf(`
			DELETE FROM scan_records 
			WHERE artifact_id = ? AND id NOT IN (%s)
		`, strings.Join(placeholders, ","))

		result, err := tx.ExecContext(ctx, deleteQuery, args...)
		if err != nil {
			return errors.NewTransientf("failed to delete excess scan records: %w", err)
		}

		deletedCount, err := result.RowsAffected()
		if err != nil {
			return errors.NewTransientf("failed to get deleted rows count: %w", err)
		}

		if deletedCount > 0 {
			// Update artifact's last_scan_id to point to the most recent remaining scan
			if len(keepScanIDs) > 0 {
				_, err = tx.ExecContext(ctx, `
					UPDATE artifacts 
					SET last_scan_id = ?
					WHERE id = ?
				`, keepScanIDs[0], artifactID) // keepScanIDs[0] is the most recent
				if err != nil {
					return errors.NewTransientf("failed to update artifact last_scan_id: %w", err)
				}
			}
		}

		return nil
	})
}
