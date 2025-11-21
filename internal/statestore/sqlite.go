package statestore

import (
	"context"
	"database/sql"
	"fmt"
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
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS artifacts (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		repository_id INTEGER NOT NULL,
		digest TEXT NOT NULL UNIQUE,
		tag TEXT,
		first_seen TIMESTAMP NOT NULL,
		last_seen TIMESTAMP NOT NULL,
		last_scan_id INTEGER,
		next_scan_at TIMESTAMP,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
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
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
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
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (scan_record_id) REFERENCES scan_records(id) ON DELETE CASCADE
	);

	CREATE TABLE IF NOT EXISTS tolerated_cves (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		repository_id INTEGER NOT NULL,
		artifact_id INTEGER,
		cve_id TEXT NOT NULL,
		statement TEXT NOT NULL,
		tolerated_at TIMESTAMP NOT NULL,
		expires_at TIMESTAMP,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
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
	now := time.Now()
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
		`, repositoryID, record.Digest, record.Tag, now, now)
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
		`, now, record.Tag, artifactID)
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
	`, scanRecordID, now, artifactID)
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
			_, err := toleratedStmt.ExecContext(ctx,
				repositoryID, tolerated.CVEID, tolerated.Statement, tolerated.ToleratedAt, tolerated.ExpiresAt,
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
		ORDER BY sr.created_at DESC
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
	now := time.Now()

	rows, err := s.db.QueryContext(ctx, `
		SELECT digest
		FROM artifacts
		WHERE last_scan_id IS NOT NULL AND next_scan_at < ?
		ORDER BY next_scan_at ASC
	`, now)
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
		var scannedAt sql.NullTime
		err := rows.Scan(
			&vuln.CVEID, &vuln.Severity, &vuln.PackageName,
			&vuln.InstalledVersion, &vuln.FixedVersion, &vuln.Title, &vuln.Description, &vuln.PrimaryURL,
			&vuln.Repository, &vuln.Tag, &vuln.Digest, &scannedAt,
		)
		if err != nil {
			return nil, errors.NewTransientf("failed to scan vulnerability: %w", err)
		}
		if scannedAt.Valid {
			vuln.ScannedAt = scannedAt.Time
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
		var expiresAt sql.NullTime
		err := rows.Scan(&cve.CVEID, &cve.Statement, &cve.ToleratedAt, &expiresAt)
		if err != nil {
			return nil, errors.NewTransientf("failed to scan tolerated CVE: %w", err)
		}
		if expiresAt.Valid {
			cve.ExpiresAt = &expiresAt.Time
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

	query += " ORDER BY sr.created_at DESC"

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

	now := time.Now()

	if filter.Expired != nil {
		if *filter.Expired {
			// Only expired tolerations
			query += " AND tc.expires_at IS NOT NULL AND tc.expires_at < ?"
			args = append(args, now)
		} else {
			// Only non-expired tolerations
			query += " AND (tc.expires_at IS NULL OR tc.expires_at >= ?)"
			args = append(args, now)
		}
	}

	if filter.ExpiringSoon != nil && *filter.ExpiringSoon {
		// Expiring within 7 days
		sevenDaysFromNow := now.Add(7 * 24 * time.Hour)
		query += " AND tc.expires_at IS NOT NULL AND tc.expires_at >= ? AND tc.expires_at <= ?"
		args = append(args, now, sevenDaysFromNow)
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
		var expiresAt sql.NullTime

		err := rows.Scan(
			&info.CVEID,
			&info.Statement,
			&info.ToleratedAt,
			&expiresAt,
			&info.Repository,
		)
		if err != nil {
			return nil, errors.NewTransientf("failed to scan toleration: %w", err)
		}

		if expiresAt.Valid {
			info.ExpiresAt = &expiresAt.Time
		}

		tolerations = append(tolerations, &info)
	}

	if err := rows.Err(); err != nil {
		return nil, errors.NewTransientf("error iterating rows: %w", err)
	}

	return tolerations, nil
}
