package statestore

import (
	"context"
	"database/sql"
	"strings"

	"github.com/daimoniac/suppline/internal/errors"
	"github.com/daimoniac/suppline/internal/types"
)

func (s *SQLiteStore) GetUniqueVulnerabilityCounts(ctx context.Context) (map[string]int, error) {
	// Use a subquery to first collect the set of active scan IDs from artifacts, then
	// filter vulnerabilities by that set. This avoids a full JOIN + sort and allows
	// SQLite to use idx_artifacts_last_scan + idx_vulnerabilities_scan_severity_cve.
	// The inner SELECT DISTINCT also ensures each CVE is counted only once even when
	// the same scan_record_id is referenced by multiple artifact rows (multi-tag digests).
	query := `
		SELECT severity, COUNT(DISTINCT cve_id)
		FROM vulnerabilities
		WHERE scan_record_id IN (
			SELECT last_scan_id FROM artifacts WHERE last_scan_id IS NOT NULL
		)
		GROUP BY severity
	`

	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, errors.NewTransientf("failed to query unique vulnerability counts: %w", err)
	}
	defer rows.Close()

	counts := map[string]int{
		"CRITICAL": 0,
		"HIGH":     0,
		"MEDIUM":   0,
		"LOW":      0,
	}

	for rows.Next() {
		var severity string
		var count int
		if err := rows.Scan(&severity, &count); err != nil {
			return nil, errors.NewTransientf("failed to scan vulnerability count: %w", err)
		}
		counts[severity] = count
	}

	if err := rows.Err(); err != nil {
		return nil, errors.NewTransientf("error iterating vulnerability count rows: %w", err)
	}

	return counts, nil
}

// QueryVulnerabilities searches vulnerabilities across all scans
func (s *SQLiteStore) QueryVulnerabilities(ctx context.Context, filter VulnFilter) ([]*types.VulnerabilityRecord, error) {
	query := `
		WITH first_seen AS (
			SELECT sr2.artifact_id, v2.cve_id, MIN(sr2.created_at) AS first_seen_at
			FROM scan_records sr2
			JOIN vulnerabilities v2 ON v2.scan_record_id = sr2.id
			GROUP BY sr2.artifact_id, v2.cve_id
		)
		SELECT v.cve_id, v.severity, v.package_name,
			v.installed_version, v.fixed_version, v.title, v.description, v.primary_url,
			r.name, a.tag, a.digest, sr.created_at,
			COALESCE(fs.first_seen_at, sr.created_at) AS first_seen_at
		FROM vulnerabilities v
		JOIN scan_records sr ON v.scan_record_id = sr.id
		JOIN artifacts a ON sr.artifact_id = a.id
		JOIN repositories r ON a.repository_id = r.id
		LEFT JOIN first_seen fs ON fs.artifact_id = a.id AND fs.cve_id = v.cve_id
		WHERE sr.id = a.last_scan_id
	`
	args := []interface{}{}

	if filter.CVEID != "" {
		query += " AND v.cve_id LIKE ?"
		args = append(args, "%"+filter.CVEID+"%")
	}

	if filter.Severity != "" {
		query += " AND v.severity = ?"
		args = append(args, filter.Severity)
	}

	if filter.PackageName != "" {
		query += " AND v.package_name LIKE ?"
		args = append(args, "%"+filter.PackageName+"%")
	}

	if filter.Repository != "" {
		query += " AND r.name LIKE ?"
		args = append(args, "%"+filter.Repository+"%")
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
			&vuln.Repository, &vuln.Tag, &vuln.Digest, &vuln.ScannedAt, &vuln.FirstSeenAt,
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

// ListVulnerabilityCVEPage returns paginated distinct CVE IDs with SQL-level grouping/sorting.
func (s *SQLiteStore) ListVulnerabilityCVEPage(ctx context.Context, filter VulnFilter, sortBy, sortDir string, limit, offset int) ([]string, int, error) {
	if limit <= 0 {
		limit = 10
	}
	if offset < 0 {
		offset = 0
	}

	base := `
		FROM (
			SELECT DISTINCT last_scan_id AS scan_record_id, repository_id, digest
			FROM artifacts
			WHERE last_scan_id IS NOT NULL
		) la
		JOIN vulnerabilities v ON v.scan_record_id = la.scan_record_id
		JOIN repositories r ON la.repository_id = r.id
		WHERE 1 = 1
	`
	args := []interface{}{}

	if filter.CVEID != "" {
		base += " AND v.cve_id LIKE ?"
		args = append(args, "%"+filter.CVEID+"%")
	}

	if filter.Severity != "" {
		base += " AND v.severity = ?"
		args = append(args, filter.Severity)
	}

	if filter.PackageName != "" {
		base += " AND v.package_name LIKE ?"
		args = append(args, "%"+filter.PackageName+"%")
	}

	if filter.Repository != "" {
		base += " AND r.name LIKE ?"
		args = append(args, "%"+filter.Repository+"%")
	}

	countQuery := "SELECT COUNT(*) FROM (SELECT v.cve_id " + base + " GROUP BY v.cve_id)"
	var total int
	if err := s.db.QueryRowContext(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, errors.NewTransientf("failed to count vulnerability groups: %w", err)
	}

	var orderBy string
	switch sortBy {
	case "cve_id":
		if sortDir == "asc" {
			orderBy = "cve_id ASC"
		} else {
			orderBy = "cve_id DESC"
		}
	case "severity":
		if sortDir == "asc" {
			orderBy = "severity_rank DESC, cve_id ASC"
		} else {
			orderBy = "severity_rank ASC, cve_id ASC"
		}
	default: // images
		if sortDir == "asc" {
			orderBy = "image_count ASC, cve_id ASC"
		} else {
			orderBy = "image_count DESC, cve_id ASC"
		}
	}

	pageQuery := `
		SELECT cve_id
		FROM (
			SELECT v.cve_id,
				MIN(CASE v.severity
					WHEN 'CRITICAL' THEN 0
					WHEN 'HIGH' THEN 1
					WHEN 'MEDIUM' THEN 2
					WHEN 'LOW' THEN 3
					ELSE 4
				END) AS severity_rank,
				COUNT(DISTINCT la.digest) AS image_count
			` + base + `
			GROUP BY v.cve_id
		)
		ORDER BY ` + orderBy + `
		LIMIT ? OFFSET ?
	`

	pageArgs := append(append([]interface{}{}, args...), limit, offset)
	rows, err := s.db.QueryContext(ctx, pageQuery, pageArgs...)
	if err != nil {
		return nil, 0, errors.NewTransientf("failed to query vulnerability groups: %w", err)
	}
	defer rows.Close()

	cveIDs := make([]string, 0, limit)
	for rows.Next() {
		var cveID string
		if err := rows.Scan(&cveID); err != nil {
			return nil, 0, errors.NewTransientf("failed to scan vulnerability group: %w", err)
		}
		cveIDs = append(cveIDs, cveID)
	}

	if err := rows.Err(); err != nil {
		return nil, 0, errors.NewTransientf("error iterating vulnerability groups: %w", err)
	}

	return cveIDs, total, nil
}

// QueryVulnerabilitiesByCVEIDs returns vulnerability records for the selected CVE IDs.
func (s *SQLiteStore) QueryVulnerabilitiesByCVEIDs(ctx context.Context, filter VulnFilter, cveIDs []string) ([]*types.VulnerabilityRecord, error) {
	if len(cveIDs) == 0 {
		return []*types.VulnerabilityRecord{}, nil
	}

	placeholders := strings.TrimSuffix(strings.Repeat("?,", len(cveIDs)), ",")
	query := `
		WITH first_seen AS (
			SELECT sr2.artifact_id, v2.cve_id, MIN(sr2.created_at) AS first_seen_at
			FROM scan_records sr2
			JOIN vulnerabilities v2 ON v2.scan_record_id = sr2.id
			WHERE v2.cve_id IN (` + placeholders + `)
			GROUP BY sr2.artifact_id, v2.cve_id
		)
		SELECT v.cve_id, v.severity, v.package_name,
			v.installed_version, v.fixed_version, v.title, v.description, v.primary_url,
			r.name, a.tag, a.digest, sr.created_at,
			COALESCE(fs.first_seen_at, sr.created_at) AS first_seen_at
		FROM vulnerabilities v
		JOIN scan_records sr ON v.scan_record_id = sr.id
		JOIN artifacts a ON sr.artifact_id = a.id
		JOIN repositories r ON a.repository_id = r.id
		LEFT JOIN first_seen fs ON fs.artifact_id = a.id AND fs.cve_id = v.cve_id
		WHERE sr.id = a.last_scan_id
			AND v.cve_id IN (` + placeholders + `)
	`

	args := make([]interface{}, 0, len(cveIDs)*2+4)
	for _, cveID := range cveIDs {
		args = append(args, cveID)
	}
	for _, cveID := range cveIDs {
		args = append(args, cveID)
	}

	if filter.Severity != "" {
		query += " AND v.severity = ?"
		args = append(args, filter.Severity)
	}

	if filter.PackageName != "" {
		query += " AND v.package_name LIKE ?"
		args = append(args, "%"+filter.PackageName+"%")
	}

	if filter.Repository != "" {
		query += " AND r.name LIKE ?"
		args = append(args, "%"+filter.Repository+"%")
	}

	// Keep result deterministic for downstream grouping.
	query += " ORDER BY v.cve_id, r.name, a.tag"

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, errors.NewTransientf("failed to query vulnerabilities by cve ids: %w", err)
	}
	defer rows.Close()

	vulnerabilities := make([]*types.VulnerabilityRecord, 0)
	for rows.Next() {
		var vuln types.VulnerabilityRecord
		err := rows.Scan(
			&vuln.CVEID, &vuln.Severity, &vuln.PackageName,
			&vuln.InstalledVersion, &vuln.FixedVersion, &vuln.Title, &vuln.Description, &vuln.PrimaryURL,
			&vuln.Repository, &vuln.Tag, &vuln.Digest, &vuln.ScannedAt, &vuln.FirstSeenAt,
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

// ListVulnerabilityGroupSummariesByCVEIDs returns grouped summaries for the selected CVE IDs.
// This avoids loading per-image rows when only counts/metadata are needed.
func (s *SQLiteStore) ListVulnerabilityGroupSummariesByCVEIDs(ctx context.Context, filter VulnFilter, cveIDs []string) ([]*types.VulnerabilityGroup, error) {
	if len(cveIDs) == 0 {
		return []*types.VulnerabilityGroup{}, nil
	}

	placeholders := strings.TrimSuffix(strings.Repeat("?,", len(cveIDs)), ",")
	query := `
		SELECT v.cve_id,
			CASE MIN(CASE v.severity
				WHEN 'CRITICAL' THEN 0
				WHEN 'HIGH' THEN 1
				WHEN 'MEDIUM' THEN 2
				WHEN 'LOW' THEN 3
				ELSE 4
			END)
				WHEN 0 THEN 'CRITICAL'
				WHEN 1 THEN 'HIGH'
				WHEN 2 THEN 'MEDIUM'
				WHEN 3 THEN 'LOW'
				ELSE 'UNKNOWN'
			END AS severity,
			MIN(v.package_name) AS package_name,
			MIN(v.installed_version) AS installed_version,
			MIN(v.fixed_version) AS fixed_version,
			MIN(v.title) AS title,
			MIN(v.description) AS description,
			MIN(v.primary_url) AS primary_url,
			COUNT(DISTINCT la.digest) AS affected_image_count
		FROM (
			SELECT DISTINCT last_scan_id AS scan_record_id, repository_id, digest
			FROM artifacts
			WHERE last_scan_id IS NOT NULL
		) la
		JOIN vulnerabilities v ON v.scan_record_id = la.scan_record_id
		JOIN repositories r ON la.repository_id = r.id
		WHERE 1 = 1
			AND v.cve_id IN (` + placeholders + `)
	`

	args := make([]interface{}, 0, len(cveIDs)+3)
	for _, cveID := range cveIDs {
		args = append(args, cveID)
	}

	if filter.Severity != "" {
		query += " AND v.severity = ?"
		args = append(args, filter.Severity)
	}

	if filter.PackageName != "" {
		query += " AND v.package_name LIKE ?"
		args = append(args, "%"+filter.PackageName+"%")
	}

	if filter.Repository != "" {
		query += " AND r.name LIKE ?"
		args = append(args, "%"+filter.Repository+"%")
	}

	query += " GROUP BY v.cve_id"

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, errors.NewTransientf("failed to query vulnerability group summaries by cve ids: %w", err)
	}
	defer rows.Close()

	groups := make([]*types.VulnerabilityGroup, 0, len(cveIDs))
	for rows.Next() {
		group := &types.VulnerabilityGroup{}
		err := rows.Scan(
			&group.CVEID,
			&group.Severity,
			&group.PackageName,
			&group.InstalledVersion,
			&group.FixedVersion,
			&group.Title,
			&group.Description,
			&group.PrimaryURL,
			&group.AffectedImageCount,
		)
		if err != nil {
			return nil, errors.NewTransientf("failed to scan vulnerability group summary: %w", err)
		}

		group.Affected = []types.AffectedRepository{}
		groups = append(groups, group)
	}

	if err := rows.Err(); err != nil {
		return nil, errors.NewTransientf("error iterating vulnerability group summary rows: %w", err)
	}

	return groups, nil
}

// GetImagesByCVE returns all images affected by a specific CVE
func (s *SQLiteStore) GetImagesByCVE(ctx context.Context, cveID string) ([]*ScanRecord, error) {
	query := `
		SELECT DISTINCT sr.id, sr.artifact_id, sr.scan_duration_ms,
			sr.critical_vuln_count, sr.high_vuln_count, sr.medium_vuln_count, sr.low_vuln_count,
			sr.policy_passed, sr.policy_status, sr.policy_reason, sr.release_age_seconds, sr.minimum_release_age_seconds, sr.release_age_source,
			sr.sbom_attested, sr.vuln_attested, sr.scai_attested, COALESCE(sr.vex_attested, 0), sr.error_message, sr.created_at,
			COALESCE(a.image_created_at, 0) as image_created_at,
			a.digest, a.tag, r.name,
			sr.vex_statements_json
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
		var vexJSON sql.NullString

		err := rows.Scan(
			&record.ID, &record.ArtifactID, &record.ScanDurationMs,
			&record.CriticalVulnCount, &record.HighVulnCount, &record.MediumVulnCount, &record.LowVulnCount,
			&record.PolicyPassed, &record.PolicyStatus, &record.PolicyReason, &record.ReleaseAgeSeconds, &record.MinimumReleaseAgeSeconds, &record.ReleaseAgeSource,
			&record.SBOMAttested, &record.VulnAttested, &record.SCAIAttested, &record.VEXAttested, &record.ErrorMessage, &record.CreatedAt,
			&record.ImageCreatedAt,
			&record.Digest, &record.Tag, &record.Repository,
			&vexJSON,
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

		if err := applyStoredExemptions(&record, vexJSON); err != nil {
			return nil, err
		}

		records = append(records, &record)
	}

	if err := rows.Err(); err != nil {
		return nil, errors.NewTransientf("error iterating rows: %w", err)
	}

	return records, nil
}

// loadVulnerabilitiesByScan loads all vulnerabilities for a specific scan record
