package statestore

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/daimoniac/suppline/internal/errors"
	"github.com/daimoniac/suppline/internal/types"
)

func (s *SQLiteStore) GetLastScan(ctx context.Context, digest string) (*ScanRecord, error) {
	var record ScanRecord
	var vexJSON sql.NullString
	var failureFindingsJSON sql.NullString

	err := s.db.QueryRowContext(ctx, `
		SELECT sr.id, sr.artifact_id, sr.scan_duration_ms,
			sr.critical_vuln_count, sr.high_vuln_count, sr.medium_vuln_count, sr.low_vuln_count,
			sr.policy_passed, sr.policy_status, sr.policy_reason, sr.policy_failure_findings_json, sr.release_age_seconds, sr.minimum_release_age_seconds, sr.release_age_source,
			sr.sbom_attested, sr.vuln_attested, sr.scai_attested, COALESCE(sr.vex_attested, 0), sr.error_message, sr.created_at,
			COALESCE(a.image_created_at, 0) as image_created_at,
			a.digest, a.tag, r.name,
			sr.vex_statements_json
		FROM scan_records sr
		JOIN artifacts a ON sr.artifact_id = a.id
		JOIN repositories r ON a.repository_id = r.id
		WHERE a.digest = ?
		ORDER BY sr.created_at DESC, sr.id DESC
		LIMIT 1
	`, digest).Scan(
		&record.ID, &record.ArtifactID, &record.ScanDurationMs,
		&record.CriticalVulnCount, &record.HighVulnCount, &record.MediumVulnCount, &record.LowVulnCount,
		&record.PolicyPassed, &record.PolicyStatus, &record.PolicyReason, &failureFindingsJSON, &record.ReleaseAgeSeconds, &record.MinimumReleaseAgeSeconds, &record.ReleaseAgeSource,
		&record.SBOMAttested, &record.VulnAttested, &record.SCAIAttested, &record.VEXAttested, &record.ErrorMessage, &record.CreatedAt,
		&record.ImageCreatedAt,
		&record.Digest, &record.Tag, &record.Repository,
		&vexJSON,
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

	if err := applyStoredExemptions(&record, vexJSON); err != nil {
		return nil, err
	}
	if err := applyStoredPolicyFailureFindings(&record, failureFindingsJSON); err != nil {
		return nil, err
	}

	return &record, nil
}

// GetArtifactFirstSeen returns when the artifact was first observed for the given repository and digest.
func (s *SQLiteStore) GetArtifactFirstSeen(ctx context.Context, digest, repository, tag string) (*time.Time, error) {
	var firstSeen sql.NullInt64

	err := s.db.QueryRowContext(ctx, `
		SELECT a.first_seen
		FROM artifacts a
		JOIN repositories r ON a.repository_id = r.id
		WHERE a.digest = ? AND r.name = ?
		ORDER BY a.first_seen ASC
		LIMIT 1
	`, digest, repository).Scan(&firstSeen)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, errors.NewTransientf("failed to query artifact first_seen: %w", err)
	}

	if !firstSeen.Valid || firstSeen.Int64 <= 0 {
		return nil, nil
	}

	ts := time.Unix(firstSeen.Int64, 0).UTC()
	return &ts, nil
}

// ListDueForRescan returns digests that need rescanning
// Returns artifacts where next_scan_at is in the past (due for rescan now)
// Uses DISTINCT to avoid scanning the same digest multiple times when multiple tags point to it
func (s *SQLiteStore) ListDueForRescan(ctx context.Context, interval time.Duration) ([]string, error) {
	nowUnix := time.Now().Unix()

	rows, err := s.db.QueryContext(ctx, `
		SELECT DISTINCT digest
		FROM artifacts
		WHERE last_scan_id IS NOT NULL AND next_scan_at < ?
		ORDER BY digest ASC
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

// GetFailedArtifacts returns all artifacts whose most recent scan failed policy evaluation
func (s *SQLiteStore) GetFailedArtifacts(ctx context.Context) ([]*ScanRecord, error) {
	query := `
		SELECT sr.id, sr.artifact_id, sr.scan_duration_ms,
			sr.critical_vuln_count, sr.high_vuln_count, sr.medium_vuln_count, sr.low_vuln_count,
			sr.policy_passed, sr.policy_status, sr.policy_reason, sr.policy_failure_findings_json, sr.release_age_seconds, sr.minimum_release_age_seconds, sr.release_age_source,
			sr.sbom_attested, sr.vuln_attested, sr.scai_attested, sr.error_message, sr.created_at,
			COALESCE(a.image_created_at, 0) as image_created_at,
			a.digest, a.tag, r.name
		FROM scan_records sr
		JOIN artifacts a ON sr.artifact_id = a.id
		JOIN repositories r ON a.repository_id = r.id
		WHERE sr.id = a.last_scan_id
			AND sr.policy_passed = 0
		ORDER BY sr.created_at DESC
	`

	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, errors.NewTransientf("failed to query failed artifacts: %w", err)
	}
	defer rows.Close()

	records := make([]*ScanRecord, 0)
	for rows.Next() {
		var record ScanRecord
		var failureFindingsJSON sql.NullString

		err := rows.Scan(
			&record.ID, &record.ArtifactID, &record.ScanDurationMs,
			&record.CriticalVulnCount, &record.HighVulnCount, &record.MediumVulnCount, &record.LowVulnCount,
			&record.PolicyPassed, &record.PolicyStatus, &record.PolicyReason, &failureFindingsJSON, &record.ReleaseAgeSeconds, &record.MinimumReleaseAgeSeconds, &record.ReleaseAgeSource,
			&record.SBOMAttested, &record.VulnAttested, &record.SCAIAttested, &record.ErrorMessage, &record.CreatedAt,
			&record.ImageCreatedAt,
			&record.Digest, &record.Tag, &record.Repository,
		)
		if err != nil {
			return nil, errors.NewTransientf("failed to scan row: %w", err)
		}
		if err := applyStoredPolicyFailureFindings(&record, failureFindingsJSON); err != nil {
			return nil, err
		}

		records = append(records, &record)
	}

	if err := rows.Err(); err != nil {
		return nil, errors.NewTransientf("error iterating rows: %w", err)
	}

	return records, nil
}

// GetScanHistory returns scan history for a digest with full details
func (s *SQLiteStore) GetScanHistory(ctx context.Context, digest string, limit int) ([]*ScanRecord, error) {
	query := `
		SELECT sr.id, sr.artifact_id, sr.scan_duration_ms,
			sr.critical_vuln_count, sr.high_vuln_count, sr.medium_vuln_count, sr.low_vuln_count,
			sr.policy_passed, sr.policy_status, sr.policy_reason, sr.policy_failure_findings_json, sr.release_age_seconds, sr.minimum_release_age_seconds, sr.release_age_source,
			sr.sbom_attested, sr.vuln_attested, sr.scai_attested, COALESCE(sr.vex_attested, 0), sr.error_message, sr.created_at,
			COALESCE(a.image_created_at, 0) as image_created_at,
			a.digest, a.tag, r.name,
			sr.vex_statements_json
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
		var vexJSON sql.NullString
		var failureFindingsJSON sql.NullString

		err := rows.Scan(
			&record.ID, &record.ArtifactID, &record.ScanDurationMs,
			&record.CriticalVulnCount, &record.HighVulnCount, &record.MediumVulnCount, &record.LowVulnCount,
			&record.PolicyPassed, &record.PolicyStatus, &record.PolicyReason, &failureFindingsJSON, &record.ReleaseAgeSeconds, &record.MinimumReleaseAgeSeconds, &record.ReleaseAgeSource,
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
		if err := applyStoredPolicyFailureFindings(&record, failureFindingsJSON); err != nil {
			return nil, err
		}

		records = append(records, &record)
	}

	if err := rows.Err(); err != nil {
		return nil, errors.NewTransientf("error iterating rows: %w", err)
	}

	return records, nil
}

// GetTagsForDigest returns all repository+tag combinations that point to the given digest
func (s *SQLiteStore) GetTagsForDigest(ctx context.Context, digest string) ([]TagRef, error) {
	query := `
		SELECT r.name, a.tag, a.last_seen
		FROM artifacts a
		JOIN repositories r ON a.repository_id = r.id
		WHERE a.digest = ?
		ORDER BY r.name ASC, a.tag ASC
	`

	rows, err := s.db.QueryContext(ctx, query, digest)
	if err != nil {
		return nil, errors.NewTransientf("failed to query tags for digest: %w", err)
	}
	defer rows.Close()

	var tags []TagRef
	for rows.Next() {
		var tag TagRef
		if err := rows.Scan(&tag.Repository, &tag.Tag, &tag.LastSeen); err != nil {
			return nil, errors.NewTransientf("failed to scan tag row: %w", err)
		}
		tags = append(tags, tag)
	}

	if err := rows.Err(); err != nil {
		return nil, errors.NewTransientf("error iterating tag rows: %w", err)
	}

	return tags, nil
}

// GetRuntimeUsageForScans returns runtime usage keyed by digest for scan list responses.

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

func buildScanFilterClause(filter ScanFilter) (string, []interface{}) {
	clause := ""
	args := []interface{}{}

	if filter.Repository != "" {
		clause += " AND r.name LIKE ?"
		args = append(args, "%"+filter.Repository+"%")
	}

	switch filter.PolicyStatus {
	case "pending":
		clause += " AND sr.policy_status = 'pending'"
	case "passed":
		clause += " AND sr.policy_passed = 1 AND sr.policy_status != 'pending'"
	case "failed":
		clause += " AND sr.policy_passed = 0 AND sr.policy_status != 'pending'"
	default:
		if filter.PolicyPassed != nil {
			clause += " AND sr.policy_passed = ?"
			args = append(args, *filter.PolicyPassed)
		}
	}

	if filter.MaxAge > 0 {
		clause += " AND sr.created_at >= strftime('%s', 'now', '-' || ? || ' seconds')"
		args = append(args, filter.MaxAge)
	}

	return clause, args
}

// ListScans returns scan records with optional filters.
// Only returns the current (latest) scan per artifact, i.e. those referenced by
// artifacts.last_scan_id. This keeps results consistent with GetRepository which
// also reads the current state via last_scan_id, and avoids surfacing stale
// historical records (e.g. an old failed scan after a subsequent passing scan).
func (s *SQLiteStore) ListScans(ctx context.Context, filter ScanFilter) ([]*ScanRecord, error) {
	originalLimit := filter.Limit
	originalOffset := filter.Offset
	if needsInUsePostFilter(filter.ImageUsage) {
		filter.Limit = 0
		filter.Offset = 0
	}

	query := `
		SELECT sr.id, sr.artifact_id, sr.scan_duration_ms,
			sr.critical_vuln_count, sr.high_vuln_count, sr.medium_vuln_count, sr.low_vuln_count,
			sr.policy_passed, sr.policy_status, sr.policy_reason, sr.policy_failure_findings_json, sr.release_age_seconds, sr.minimum_release_age_seconds, sr.release_age_source,
			sr.sbom_attested, sr.vuln_attested, sr.scai_attested, sr.error_message, sr.created_at,
			COALESCE(a.image_created_at, 0) as image_created_at,
			a.digest, a.tag, r.name
		FROM artifacts a
		JOIN repositories r ON a.repository_id = r.id
		JOIN scan_records sr ON a.last_scan_id = sr.id
		WHERE 1=1
	`
	filterClause, args := buildScanFilterClause(filter)
	query += filterClause

	// Add sorting for scans list views
	switch filter.SortBy {
	case "scanned_at_desc", "age_desc", "":
		query += " ORDER BY sr.created_at DESC"
	case "scanned_at_asc", "age_asc":
		query += " ORDER BY sr.created_at ASC"
	case "repository_asc":
		query += " ORDER BY r.name ASC, a.tag ASC, sr.created_at DESC"
	case "repository_desc":
		query += " ORDER BY r.name DESC, a.tag DESC, sr.created_at DESC"
	case "tag_asc":
		query += " ORDER BY a.tag ASC, r.name ASC, sr.created_at DESC"
	case "tag_desc":
		query += " ORDER BY a.tag DESC, r.name DESC, sr.created_at DESC"
	case "digest_asc":
		query += " ORDER BY a.digest ASC"
	case "digest_desc":
		query += " ORDER BY a.digest DESC"
	case "policy_passed_asc":
		query += " ORDER BY sr.policy_passed ASC, sr.created_at DESC"
	case "policy_passed_desc":
		query += " ORDER BY sr.policy_passed DESC, sr.created_at DESC"
	default:
		// Default to age_desc for any unrecognized sort option.
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
		var failureFindingsJSON sql.NullString

		err := rows.Scan(
			&record.ID, &record.ArtifactID, &record.ScanDurationMs,
			&record.CriticalVulnCount, &record.HighVulnCount, &record.MediumVulnCount, &record.LowVulnCount,
			&record.PolicyPassed, &record.PolicyStatus, &record.PolicyReason, &failureFindingsJSON, &record.ReleaseAgeSeconds, &record.MinimumReleaseAgeSeconds, &record.ReleaseAgeSource,
			&record.SBOMAttested, &record.VulnAttested, &record.SCAIAttested, &record.ErrorMessage, &record.CreatedAt,
			&record.ImageCreatedAt,
			&record.Digest, &record.Tag, &record.Repository,
		)
		if err != nil {
			return nil, errors.NewTransientf("failed to scan row: %w", err)
		}

		// Don't load vulnerabilities or applied VEX statements for list operations.
		// These are only needed for detail views, which use GetLastScan directly
		// This keeps list responses lightweight and fast
		if err := applyStoredPolicyFailureFindings(&record, failureFindingsJSON); err != nil {
			return nil, err
		}

		records = append(records, &record)
	}

	if err := rows.Err(); err != nil {
		return nil, errors.NewTransientf("error iterating rows: %w", err)
	}

	if needsInUsePostFilter(filter.ImageUsage) {
		lookups := make([]RuntimeLookupInput, 0, len(records))
		for _, record := range records {
			lookups = append(lookups, RuntimeLookupInput{
				Digest:     record.Digest,
				Repository: record.Repository,
				Tag:        record.Tag,
			})
		}

		runtimeUsageByDigest, err := s.GetRuntimeUsageForScans(ctx, lookups)
		if err != nil {
			return nil, err
		}

		inUseRows := make([]inUseTagRow, 0, len(records))
		for _, record := range records {
			usage, ok := runtimeUsageByDigest[record.Digest]
			used := ok && usage.RuntimeUsed
			inUseRows = append(inUseRows, inUseTagRow{
				repository: record.Repository,
				tag:        record.Tag,
				used:       used,
			})
		}
		maxTagByRepo := maxInUseImageTagByRepository(inUseRows)

		filtered := make([]*ScanRecord, 0, len(records))
		for _, record := range records {
			usage, ok := runtimeUsageByDigest[record.Digest]
			used := ok && usage.RuntimeUsed
			if !recordPassesImageUsage(used, record.Repository, record.Tag, filter.ImageUsage, maxTagByRepo) {
				continue
			}
			record.RuntimeUsed = used
			if used {
				record.Runtime = usage.Runtime
			}
			filtered = append(filtered, record)
		}

		start := originalOffset
		if start < 0 {
			start = 0
		}
		if start > len(filtered) {
			start = len(filtered)
		}

		end := len(filtered)
		if originalLimit > 0 {
			candidateEnd := start + originalLimit
			if candidateEnd < end {
				end = candidateEnd
			}
		}

		records = filtered[start:end]
	}

	return records, nil
}

// CountScans returns the total number of scan records that match the filters.
// Pagination fields (Limit/Offset) are intentionally ignored.
func (s *SQLiteStore) CountScans(ctx context.Context, filter ScanFilter) (int, error) {
	if needsInUsePostFilter(filter.ImageUsage) {
		fullFilter := filter
		fullFilter.Limit = 0
		fullFilter.Offset = 0

		records, err := s.ListScans(ctx, fullFilter)
		if err != nil {
			return 0, err
		}
		return len(records), nil
	}

	query := `
		SELECT COUNT(*)
		FROM artifacts a
		JOIN repositories r ON a.repository_id = r.id
		JOIN scan_records sr ON a.last_scan_id = sr.id
		WHERE 1=1
	`
	filterClause, args := buildScanFilterClause(filter)
	query += filterClause

	var total int
	err := s.db.QueryRowContext(ctx, query, args...).Scan(&total)
	if err != nil {
		return 0, errors.NewTransientf("failed to count scans: %w", err)
	}

	return total, nil
}

// ListVEXStatements returns unique VEX-exempted CVEs from scan history.
// Reads from vex_statements_json.
// Returns one entry per unique repository + CVE ID combination with the earliest applied timestamp.
