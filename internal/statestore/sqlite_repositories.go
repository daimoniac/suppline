package statestore

import (
	"context"
	"database/sql"
	"strings"
	"time"

	"github.com/daimoniac/suppline/internal/errors"
)

func (s *SQLiteStore) ListRepositories(ctx context.Context, filter RepositoryFilter) (*RepositoriesListResponse, error) {
	// Repository list "in use" is a boolean filter from the API. Semver-based "newer than
	// min in-use tag" applies only to per-repository tag lists (GetRepository), not here.

	if err := s.repairRepositorySummariesForList(ctx); err != nil {
		return nil, err
	}

	whereSQL := " WHERE 1=1"
	args := make([]interface{}, 0)

	if filter.Search != "" {
		whereSQL += " AND r.name LIKE ?"
		args = append(args, "%"+filter.Search+"%")
	}

	if filter.MaxAge > 0 {
		whereSQL += " AND rs.last_scan_time IS NOT NULL AND rs.last_scan_time >= ?"
		args = append(args, time.Now().Unix()-int64(filter.MaxAge))
	}

	if filter.PolicyStatus != "" {
		whereSQL += " AND rs.policy_status = ?"
		args = append(args, filter.PolicyStatus)
	}

	if filter.InUse != nil {
		if *filter.InUse {
			whereSQL += " AND (rs.runtime_used = 1 OR rs.whitelisted = 1)"
		} else {
			whereSQL += " AND (rs.runtime_used = 0 OR rs.whitelisted = 1)"
		}
	}

	countQuery := `SELECT COUNT(*) FROM repositories r INNER JOIN repository_summary rs ON r.id = rs.repository_id` + whereSQL
	var total int
	if err := s.db.QueryRowContext(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, errors.NewTransientf("failed to count repositories: %w", err)
	}

	query := `
		SELECT
			r.name,
			rs.artifact_count,
			rs.last_scan_time,
			rs.max_critical,
			rs.max_high,
			rs.max_medium,
			rs.max_low,
			rs.policy_passed,
			rs.policy_status,
			rs.runtime_used,
			rs.whitelisted
		FROM repositories r
		INNER JOIN repository_summary rs ON r.id = rs.repository_id
	` + whereSQL

	switch filter.SortBy {
	case "name_asc":
		query += " ORDER BY r.name ASC"
	case "name_desc":
		query += " ORDER BY r.name DESC"
	case "artifacts_asc":
		query += " ORDER BY rs.artifact_count ASC, r.name ASC"
	case "artifacts_desc":
		query += " ORDER BY rs.artifact_count DESC, r.name ASC"
	case "age_desc", "":
		query += " ORDER BY rs.last_scan_time DESC NULLS LAST, r.name ASC"
	case "age_asc":
		query += " ORDER BY rs.last_scan_time ASC NULLS FIRST, r.name ASC"
	case "status_asc":
		query += " ORDER BY rs.policy_passed ASC, r.name ASC"
	case "status_desc":
		query += " ORDER BY rs.policy_passed DESC, r.name ASC"
	default:
		query += " ORDER BY r.name ASC"
	}

	listArgs := append([]interface{}{}, args...)
	if filter.Limit > 0 {
		query += " LIMIT ?"
		listArgs = append(listArgs, filter.Limit)
	}
	if filter.Offset > 0 {
		query += " OFFSET ?"
		listArgs = append(listArgs, filter.Offset)
	}

	rows, err := s.db.QueryContext(ctx, query, listArgs...)
	if err != nil {
		return nil, errors.NewTransientf("failed to list repositories: %w", err)
	}
	defer rows.Close()

	var repositories []RepositoryInfo
	for rows.Next() {
		var repo RepositoryInfo
		var lastScanTimeUnix sql.NullInt64
		var policyPassed int
		var runtimeUsed int
		var whitelisted int

		if err := rows.Scan(
			&repo.Name,
			&repo.ArtifactCount,
			&lastScanTimeUnix,
			&repo.VulnerabilityCount.Critical,
			&repo.VulnerabilityCount.High,
			&repo.VulnerabilityCount.Medium,
			&repo.VulnerabilityCount.Low,
			&policyPassed,
			&repo.PolicyStatus,
			&runtimeUsed,
			&whitelisted,
		); err != nil {
			return nil, errors.NewTransientf("failed to scan repository row: %w", err)
		}

		if lastScanTimeUnix.Valid {
			repo.LastScanTime = &lastScanTimeUnix.Int64
		}

		repo.PolicyPassed = policyPassed == 1
		repo.RuntimeUsed = runtimeUsed == 1
		repo.Whitelisted = whitelisted == 1

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

func (s *SQLiteStore) repositoryRuntimeUsageByID(ctx context.Context, repoNamesByID map[int64]string) (map[int64]bool, error) {
	runtimeUsedByRepoID := make(map[int64]bool, len(repoNamesByID))
	if len(repoNamesByID) == 0 {
		return runtimeUsedByRepoID, nil
	}

	repoIDs := make([]int64, 0, len(repoNamesByID))
	for repoID := range repoNamesByID {
		repoIDs = append(repoIDs, repoID)
	}

	placeholders := strings.TrimSuffix(strings.Repeat("?,", len(repoIDs)), ",")
	query := `
		SELECT a.repository_id, COALESCE(a.digest, ''), COALESCE(a.tag, '')
		FROM artifacts a
		WHERE a.repository_id IN (` + placeholders + `)
	`

	args := make([]interface{}, 0, len(repoIDs))
	for _, repoID := range repoIDs {
		args = append(args, repoID)
	}

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, errors.NewTransientf("failed to query repository artifacts for runtime usage: %w", err)
	}
	defer rows.Close()

	type repoArtifact struct {
		repositoryID int64
		digest       string
	}

	lookups := make([]RuntimeLookupInput, 0)
	repoArtifacts := make([]repoArtifact, 0)
	for rows.Next() {
		var repositoryID int64
		var digest, tag string
		if err := rows.Scan(&repositoryID, &digest, &tag); err != nil {
			return nil, errors.NewTransientf("failed to scan repository artifact runtime lookup: %w", err)
		}

		repositoryName, ok := repoNamesByID[repositoryID]
		if !ok {
			continue
		}

		lookups = append(lookups, RuntimeLookupInput{
			Digest:     digest,
			Repository: repositoryName,
			Tag:        tag,
		})
		repoArtifacts = append(repoArtifacts, repoArtifact{repositoryID: repositoryID, digest: digest})
	}

	if err := rows.Err(); err != nil {
		return nil, errors.NewTransientf("error iterating repository artifacts for runtime usage: %w", err)
	}

	usageByDigest, err := s.GetRuntimeUsageForScans(ctx, lookups)
	if err != nil {
		return nil, err
	}

	for _, artifact := range repoArtifacts {
		usage, ok := usageByDigest[artifact.digest]
		if ok && usage.RuntimeUsed {
			runtimeUsedByRepoID[artifact.repositoryID] = true
		}
	}

	// Repository-level fallback: if any image of this repository was seen recently,
	// treat the repository as in use even when tag/digest do not match scanned artifacts.
	for repoID, repoName := range repoNamesByID {
		if runtimeUsedByRepoID[repoID] {
			continue
		}

		usage, err := s.queryRuntimeUsageByRepository(ctx, repoName)
		if err != nil {
			return nil, err
		}
		if usage.RuntimeUsed {
			runtimeUsedByRepoID[repoID] = true
		}
	}

	return runtimeUsedByRepoID, nil
}

// GetRepository returns a repository with all its tags
func (s *SQLiteStore) GetRepository(ctx context.Context, name string, filter RepositoryTagFilter) (*RepositoryDetail, error) {
	isWhitelisted, err := s.isRuntimeUnusedRepositoryWhitelisted(ctx, name)
	if err != nil {
		return nil, err
	}

	effectiveInUseOnly := filter.InUseOnly && !isWhitelisted

	// First, get total count of unique tags for this repository
	countQuery := `
		SELECT COUNT(DISTINCT a.tag)
		FROM artifacts a
		JOIN repositories r ON a.repository_id = r.id
		WHERE r.name = ?
	`
	countArgs := []interface{}{name}

	if filter.Search != "" {
		if filter.ExactMatch {
			countQuery += " AND a.tag = ?"
			countArgs = append(countArgs, filter.Search)
		} else {
			countQuery += " AND a.tag LIKE ?"
			countArgs = append(countArgs, filter.Search+"%")
		}
	}

	var total int
	err = s.db.QueryRowContext(ctx, countQuery, countArgs...).Scan(&total)
	if err != nil {
		return nil, errors.NewTransientf("failed to count tags: %w", err)
	}

	// Query tags with their scan data, selecting only the newest artifact per tag
	// Using a subquery to get the maximum artifact id (newest) for each tag, then joining back
	// to get the full artifact details for only the newest digest per tag.
	// We use MAX(id) instead of MAX(last_seen) because multiple scans of different digests
	// with the same tag can happen at the same timestamp, but id is always unique and sequential.
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
			COALESCE(sr.policy_passed, 1) as policy_passed,
			COALESCE(sr.policy_status, '') as policy_status,
			COALESCE(sr.policy_reason, '') as policy_reason,
			COALESCE(sr.release_age_seconds, 0) as release_age_seconds,
			COALESCE(sr.minimum_release_age_seconds, 0) as minimum_release_age_seconds,
			COALESCE(sr.release_age_source, '') as release_age_source,
			COALESCE(sr.error_message, '') as error_message
		FROM artifacts a
		JOIN repositories r ON a.repository_id = r.id
		LEFT JOIN scan_records sr ON a.last_scan_id = sr.id
		INNER JOIN (
			SELECT a2.tag, MAX(a2.id) as max_id
			FROM artifacts a2
			JOIN repositories r2 ON a2.repository_id = r2.id
			WHERE r2.name = ?
			GROUP BY a2.tag
		) latest ON a.tag = latest.tag AND a.id = latest.max_id
		WHERE r.name = ?
	`
	args := []interface{}{name, name}

	if filter.Search != "" {
		if filter.ExactMatch {
			query += " AND a.tag = ?"
			args = append(args, filter.Search)
		} else {
			query += " AND a.tag LIKE ?"
			args = append(args, filter.Search+"%")
		}
	}

	query += " ORDER BY a.tag ASC"

	if !effectiveInUseOnly && filter.Limit > 0 {
		query += " LIMIT ?"
		args = append(args, filter.Limit)
	}

	if !effectiveInUseOnly && filter.Offset > 0 {
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
			&tag.PolicyStatus,
			&tag.PolicyReason,
			&tag.ReleaseAgeSeconds,
			&tag.MinimumReleaseAgeSeconds,
			&tag.ReleaseAgeSource,
			&tag.ScanError,
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
		tag.Whitelisted = isWhitelisted
		if tag.PolicyStatus == "" {
			if tag.PolicyPassed {
				tag.PolicyStatus = "passed"
			} else {
				tag.PolicyStatus = "failed"
			}
		}

		detail.Tags = append(detail.Tags, tag)
	}

	if err := rows.Err(); err != nil {
		return nil, errors.NewTransientf("error iterating tag rows: %w", err)
	}

	if effectiveInUseOnly {
		lookups := make([]RuntimeLookupInput, 0, len(detail.Tags))
		for _, tag := range detail.Tags {
			lookups = append(lookups, RuntimeLookupInput{
				Digest:     tag.Digest,
				Repository: name,
				Tag:        tag.Name,
			})
		}

		runtimeUsageByDigest, err := s.GetRuntimeUsageForScans(ctx, lookups)
		if err != nil {
			return nil, err
		}

		filtered := make([]TagInfo, 0, len(detail.Tags))
		for _, tag := range detail.Tags {
			usage, ok := runtimeUsageByDigest[tag.Digest]
			if !ok || !usage.RuntimeUsed {
				continue
			}
			tag.RuntimeUsed = usage.RuntimeUsed
			tag.Runtime = usage.Runtime
			filtered = append(filtered, tag)
		}

		detail.Total = len(filtered)

		start := filter.Offset
		if start < 0 {
			start = 0
		}
		if start > len(filtered) {
			start = len(filtered)
		}

		end := len(filtered)
		if filter.Limit > 0 {
			candidateEnd := start + filter.Limit
			if candidateEnd < end {
				end = candidateEnd
			}
		}

		detail.Tags = filtered[start:end]
	}

	return detail, nil
}

// CleanupArtifactScans removes all scan records for all artifacts with the given digest (MANIFEST_UNKNOWN case).
// Also removes the artifacts and repositories if they become empty.
// This is used when a manifest is no longer available in the registry.
// Note: Multiple tags may point to the same digest, so we clean up all of them.
