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
	CREATE TABLE IF NOT EXISTS scan_records (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		digest TEXT NOT NULL,
		repository TEXT NOT NULL,
		tag TEXT,
		scanned_at TIMESTAMP NOT NULL,
		critical_vuln_count INTEGER NOT NULL,
		high_vuln_count INTEGER NOT NULL,
		medium_vuln_count INTEGER NOT NULL,
		low_vuln_count INTEGER NOT NULL,
		policy_passed BOOLEAN NOT NULL,
		sbom_attested BOOLEAN NOT NULL,
		vuln_attested BOOLEAN NOT NULL,
		error_message TEXT,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
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
		scan_record_id INTEGER NOT NULL,
		cve_id TEXT NOT NULL,
		statement TEXT NOT NULL,
		tolerated_at TIMESTAMP NOT NULL,
		expires_at TIMESTAMP,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (scan_record_id) REFERENCES scan_records(id) ON DELETE CASCADE
	);

	CREATE INDEX IF NOT EXISTS idx_digest_scanned ON scan_records(digest, scanned_at DESC);
	CREATE INDEX IF NOT EXISTS idx_scanned_at ON scan_records(scanned_at);
	CREATE INDEX IF NOT EXISTS idx_repository ON scan_records(repository);
	CREATE INDEX IF NOT EXISTS idx_policy_passed ON scan_records(policy_passed);
	CREATE INDEX IF NOT EXISTS idx_vulnerabilities_scan ON vulnerabilities(scan_record_id);
	CREATE INDEX IF NOT EXISTS idx_vulnerabilities_cve ON vulnerabilities(cve_id);
	CREATE INDEX IF NOT EXISTS idx_vulnerabilities_severity ON vulnerabilities(severity);
	CREATE INDEX IF NOT EXISTS idx_tolerated_scan ON tolerated_cves(scan_record_id);
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

	// Insert scan record
	result, err := tx.ExecContext(ctx, `
		INSERT INTO scan_records (
			digest, repository, tag, scanned_at,
			critical_vuln_count, high_vuln_count, medium_vuln_count, low_vuln_count,
			policy_passed, sbom_attested, vuln_attested, error_message
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`,
		record.Digest, record.Repository, record.Tag, record.ScannedAt,
		record.CriticalVulnCount, record.HighVulnCount, record.MediumVulnCount, record.LowVulnCount,
		record.PolicyPassed, record.SBOMAttested, record.VulnAttested, record.ErrorMessage,
	)
	if err != nil {
		return errors.NewTransientf("failed to insert scan record: %w", err)
	}

	scanRecordID, err := result.LastInsertId()
	if err != nil {
		return errors.NewTransientf("failed to get scan record ID: %w", err)
	}

	// Insert vulnerabilities
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
				scan_record_id, cve_id, statement, tolerated_at, expires_at
			) VALUES (?, ?, ?, ?, ?)
		`)
		if err != nil {
			return errors.NewTransientf("failed to prepare tolerated CVE statement: %w", err)
		}
		defer toleratedStmt.Close()

		for _, tolerated := range record.ToleratedCVEs {
			_, err := toleratedStmt.ExecContext(ctx,
				scanRecordID, tolerated.CVEID, tolerated.Statement, tolerated.ToleratedAt, tolerated.ExpiresAt,
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
	var scanRecordID int64

	err := s.db.QueryRowContext(ctx, `
		SELECT id, digest, repository, tag, scanned_at,
			critical_vuln_count, high_vuln_count, medium_vuln_count, low_vuln_count,
			policy_passed, sbom_attested, vuln_attested, error_message
		FROM scan_records
		WHERE digest = ?
		ORDER BY scanned_at DESC
		LIMIT 1
	`, digest).Scan(
		&scanRecordID, &record.Digest, &record.Repository, &record.Tag, &record.ScannedAt,
		&record.CriticalVulnCount, &record.HighVulnCount, &record.MediumVulnCount, &record.LowVulnCount,
		&record.PolicyPassed, &record.SBOMAttested, &record.VulnAttested, &record.ErrorMessage,
	)
	if err == sql.ErrNoRows {
		return nil, ErrScanNotFound
	}
	if err != nil {
		return nil, errors.NewTransientf("failed to query scan record: %w", err)
	}

	// Load vulnerabilities
	vulns, err := s.loadVulnerabilities(ctx, scanRecordID)
	if err != nil {
		return nil, err
	}
	record.Vulnerabilities = vulns

	// Load tolerated CVEs
	tolerated, err := s.loadToleratedCVEs(ctx, scanRecordID)
	if err != nil {
		return nil, err
	}
	record.ToleratedCVEs = tolerated

	return &record, nil
}

// ListDueForRescan returns digests that need rescanning
func (s *SQLiteStore) ListDueForRescan(ctx context.Context, interval time.Duration) ([]string, error) {
	cutoffTime := time.Now().Add(-interval)

	rows, err := s.db.QueryContext(ctx, `
		SELECT DISTINCT digest
		FROM scan_records
		WHERE scanned_at < ?
		ORDER BY scanned_at ASC
	`, cutoffTime)
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
		SELECT id, digest, repository, tag, scanned_at,
			critical_vuln_count, high_vuln_count, medium_vuln_count, low_vuln_count,
			policy_passed, sbom_attested, vuln_attested, error_message
		FROM scan_records
		WHERE digest = ?
		ORDER BY scanned_at DESC
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
		var scanRecordID int64

		err := rows.Scan(
			&scanRecordID, &record.Digest, &record.Repository, &record.Tag, &record.ScannedAt,
			&record.CriticalVulnCount, &record.HighVulnCount, &record.MediumVulnCount, &record.LowVulnCount,
			&record.PolicyPassed, &record.SBOMAttested, &record.VulnAttested, &record.ErrorMessage,
		)
		if err != nil {
			return nil, errors.NewTransientf("failed to scan row: %w", err)
		}

		// Load vulnerabilities
		vulns, err := s.loadVulnerabilities(ctx, scanRecordID)
		if err != nil {
			return nil, err
		}
		record.Vulnerabilities = vulns

		// Load tolerated CVEs
		tolerated, err := s.loadToleratedCVEs(ctx, scanRecordID)
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
			sr.repository, sr.tag, sr.digest, sr.scanned_at
		FROM vulnerabilities v
		JOIN scan_records sr ON v.scan_record_id = sr.id
		WHERE 1=1
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
		query += " AND sr.repository = ?"
		args = append(args, filter.Repository)
	}

	query += " ORDER BY v.severity, v.cve_id, sr.repository, sr.tag"

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
		SELECT DISTINCT sr.id, sr.digest, sr.repository, sr.tag, sr.scanned_at,
			sr.critical_vuln_count, sr.high_vuln_count, sr.medium_vuln_count, sr.low_vuln_count,
			sr.policy_passed, sr.sbom_attested, sr.vuln_attested, sr.error_message
		FROM scan_records sr
		JOIN vulnerabilities v ON sr.id = v.scan_record_id
		WHERE v.cve_id = ?
		ORDER BY sr.scanned_at DESC
	`

	rows, err := s.db.QueryContext(ctx, query, cveID)
	if err != nil {
		return nil, errors.NewTransientf("failed to query images by CVE: %w", err)
	}
	defer rows.Close()

	var records []*ScanRecord
	for rows.Next() {
		var record ScanRecord
		var scanRecordID int64

		err := rows.Scan(
			&scanRecordID, &record.Digest, &record.Repository, &record.Tag, &record.ScannedAt,
			&record.CriticalVulnCount, &record.HighVulnCount, &record.MediumVulnCount, &record.LowVulnCount,
			&record.PolicyPassed, &record.SBOMAttested, &record.VulnAttested, &record.ErrorMessage,
		)
		if err != nil {
			return nil, errors.NewTransientf("failed to scan row: %w", err)
		}

		// Load vulnerabilities
		vulns, err := s.loadVulnerabilities(ctx, scanRecordID)
		if err != nil {
			return nil, err
		}
		record.Vulnerabilities = vulns

		// Load tolerated CVEs
		tolerated, err := s.loadToleratedCVEs(ctx, scanRecordID)
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

// loadVulnerabilities loads all vulnerabilities for a scan record
func (s *SQLiteStore) loadVulnerabilities(ctx context.Context, scanRecordID int64) ([]types.VulnerabilityRecord, error) {
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

// loadToleratedCVEs loads all tolerated CVEs for a scan record
func (s *SQLiteStore) loadToleratedCVEs(ctx context.Context, scanRecordID int64) ([]types.ToleratedCVE, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT cve_id, statement, tolerated_at, expires_at
		FROM tolerated_cves
		WHERE scan_record_id = ?
		ORDER BY cve_id
	`, scanRecordID)
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
		SELECT id, digest, repository, tag, scanned_at,
			critical_vuln_count, high_vuln_count, medium_vuln_count, low_vuln_count,
			policy_passed, sbom_attested, vuln_attested, error_message
		FROM scan_records
		WHERE 1=1
	`
	args := []interface{}{}

	if filter.Repository != "" {
		query += " AND repository = ?"
		args = append(args, filter.Repository)
	}

	if filter.PolicyPassed != nil {
		query += " AND policy_passed = ?"
		args = append(args, *filter.PolicyPassed)
	}

	query += " ORDER BY scanned_at DESC"

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
		var scanRecordID int64

		err := rows.Scan(
			&scanRecordID, &record.Digest, &record.Repository, &record.Tag, &record.ScannedAt,
			&record.CriticalVulnCount, &record.HighVulnCount, &record.MediumVulnCount, &record.LowVulnCount,
			&record.PolicyPassed, &record.SBOMAttested, &record.VulnAttested, &record.ErrorMessage,
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
			MIN(tc.tolerated_at) as tolerated_at,
			tc.expires_at,
			sr.repository
		FROM tolerated_cves tc
		JOIN scan_records sr ON tc.scan_record_id = sr.id
		WHERE 1=1
	`
	args := []interface{}{}

	if filter.CVEID != "" {
		query += " AND tc.cve_id = ?"
		args = append(args, filter.CVEID)
	}

	if filter.Repository != "" {
		query += " AND sr.repository = ?"
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

	// Group by repository and CVE ID to get unique tolerations
	query += " GROUP BY sr.repository, tc.cve_id, tc.statement, tc.expires_at"
	query += " ORDER BY tc.expires_at, tc.cve_id, sr.repository"

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
		var toleratedAtStr string
		var expiresAt sql.NullTime

		err := rows.Scan(
			&info.CVEID,
			&info.Statement,
			&toleratedAtStr,
			&expiresAt,
			&info.Repository,
		)
		if err != nil {
			return nil, errors.NewTransientf("failed to scan toleration: %w", err)
		}

		// Parse tolerated_at from string (MIN() returns string in SQLite)
		// SQLite datetime format: "2006-01-02 15:04:05.999999999-07:00"
		toleratedAt, err := time.Parse("2006-01-02 15:04:05.999999999-07:00", toleratedAtStr)
		if err != nil {
			// Try RFC3339 format as fallback
			toleratedAt, err = time.Parse(time.RFC3339Nano, toleratedAtStr)
			if err != nil {
				return nil, errors.NewTransientf("failed to parse tolerated_at: %w", err)
			}
		}
		info.ToleratedAt = toleratedAt

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
