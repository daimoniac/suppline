package statestore

import (
	"context"
	"database/sql"
	"strings"
	"time"

	"github.com/daimoniac/suppline/internal/errors"
)

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
			COUNT(DISTINCT a.id) as artifact_count,
			(SELECT MAX(sr2.created_at) FROM scan_records sr2 
			 JOIN artifacts a2 ON sr2.artifact_id = a2.id 
			 WHERE a2.repository_id = r.id) as last_scan_time,
			MAX(sr.critical_vuln_count) as max_critical,
			MAX(sr.high_vuln_count) as max_high,
			MAX(sr.medium_vuln_count) as max_medium,
			MAX(sr.low_vuln_count) as max_low,
			CASE WHEN COUNT(CASE WHEN sr.policy_passed = 0 THEN 1 END) > 0 THEN 0 ELSE 1 END as policy_passed,
			CASE
				WHEN COUNT(CASE WHEN sr.policy_status = 'failed' THEN 1 END) > 0 THEN 'failed'
				WHEN COUNT(CASE WHEN sr.policy_status = 'pending' THEN 1 END) > 0 THEN 'pending'
				WHEN COUNT(CASE WHEN sr.policy_passed = 0 THEN 1 END) > 0 THEN 'failed'
				ELSE 'passed'
			END as policy_status,
			CASE WHEN EXISTS (SELECT 1 FROM artifacts ai JOIN cluster_images ci ON ci.digest = ai.digest WHERE ai.repository_id = r.id) THEN 1 ELSE 0 END as runtime_used
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
	case "artifacts_asc":
		query += " ORDER BY artifact_count ASC, r.name ASC"
	case "artifacts_desc":
		query += " ORDER BY artifact_count DESC, r.name ASC"
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

	needsPostFilter := filter.ImageUsage != ImageUsageAll || filter.PolicyStatus != ""

	if !needsPostFilter && filter.Limit > 0 {
		query += " LIMIT ?"
		args = append(args, filter.Limit)
	}

	if !needsPostFilter && filter.Offset > 0 {
		query += " OFFSET ?"
		args = append(args, filter.Offset)
	}

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, errors.NewTransientf("failed to list repositories: %w", err)
	}
	defer rows.Close()

	var repositories []RepositoryInfo
	repoNamesByID := make(map[int64]string)
	repoIDs := make([]int64, 0)
	for rows.Next() {
		var repo RepositoryInfo
		var repoID int64 // repository id (not needed in response, but must scan into something)
		var lastScanTimeUnix sql.NullInt64
		var maxCritical sql.NullInt64
		var maxHigh sql.NullInt64
		var maxMedium sql.NullInt64
		var maxLow sql.NullInt64
		var policyPassed int
		var policyStatus string
		var runtimeUsed int

		err := rows.Scan(
			&repoID, // repository id (not needed in response)
			&repo.Name,
			&repo.ArtifactCount,
			&lastScanTimeUnix,
			&maxCritical,
			&maxHigh,
			&maxMedium,
			&maxLow,
			&policyPassed,
			&policyStatus,
			&runtimeUsed,
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
		repo.PolicyStatus = policyStatus
		repo.RuntimeUsed = runtimeUsed == 1

		repositories = append(repositories, repo)
		repoNamesByID[repoID] = repo.Name
		repoIDs = append(repoIDs, repoID)
	}

	if err := rows.Err(); err != nil {
		return nil, errors.NewTransientf("error iterating repository rows: %w", err)
	}

	runtimeUsedByRepoID, err := s.repositoryRuntimeUsageByID(ctx, repoNamesByID)
	if err != nil {
		return nil, err
	}

	whitelistSet, err := s.runtimeUnusedRepositoryWhitelistSet(ctx)
	if err != nil {
		return nil, err
	}

	for i, repoID := range repoIDs {
		repositories[i].RuntimeUsed = runtimeUsedByRepoID[repoID]
		_, repositories[i].Whitelisted = whitelistSet[repositories[i].Name]
	}

	if filter.ImageUsage != ImageUsageAll || filter.PolicyStatus != "" {
		filtered := repositories

		if filter.PolicyStatus != "" {
			result := make([]RepositoryInfo, 0, len(filtered))
			for _, repo := range filtered {
				if repo.PolicyStatus == filter.PolicyStatus {
					result = append(result, repo)
				}
			}
			filtered = result
		}

		switch filter.ImageUsage {
		case ImageUsageInUse:
			result := make([]RepositoryInfo, 0, len(filtered))
			for _, repo := range filtered {
				matchesInUse := repo.RuntimeUsed || repo.Whitelisted
				// Whitelisted repositories should appear in both in-use and not-in-use
				// filtered views so operators can always discover and manage them.
				if repo.Whitelisted || matchesInUse {
					result = append(result, repo)
				}
			}
			filtered = result
		case ImageUsageNotInUse:
			result := make([]RepositoryInfo, 0, len(filtered))
			for _, repo := range filtered {
				matchesInUse := repo.RuntimeUsed || repo.Whitelisted
				if repo.Whitelisted || !matchesInUse {
					result = append(result, repo)
				}
			}
			filtered = result
		case ImageUsageInUseOrNewerSemver:
			repoHasVisible, err := s.repositoryNamesWithInUseOrNewerSemver(ctx)
			if err != nil {
				return nil, err
			}
			result := make([]RepositoryInfo, 0, len(filtered))
			for _, repo := range filtered {
				matchesInUse := repo.RuntimeUsed || repo.Whitelisted
				if matchesInUse || repoHasVisible[repo.Name] {
					result = append(result, repo)
				}
			}
			filtered = result
		case ImageUsageAll:
			// policy-only filter already applied
		}

		total = len(filtered)

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

		repositories = filtered[start:end]
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

	effectiveTagFilter := (filter.ImageUsage == ImageUsageInUse || filter.ImageUsage == ImageUsageInUseOrNewerSemver) && !isWhitelisted

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

	if !effectiveTagFilter && filter.Limit > 0 {
		query += " LIMIT ?"
		args = append(args, filter.Limit)
	}

	if !effectiveTagFilter && filter.Offset > 0 {
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

	if effectiveTagFilter {
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

		inUseRows := make([]inUseTagRow, 0, len(detail.Tags))
		for _, tag := range detail.Tags {
			usage, ok := runtimeUsageByDigest[tag.Digest]
			used := ok && usage.RuntimeUsed
			inUseRows = append(inUseRows, inUseTagRow{repository: name, tag: tag.Name, used: used})
		}
		maxTagByRepo := maxInUseImageTagByRepository(inUseRows)

		filtered := make([]TagInfo, 0, len(detail.Tags))
		for _, tag := range detail.Tags {
			usage, ok := runtimeUsageByDigest[tag.Digest]
			used := ok && usage.RuntimeUsed
			if !recordPassesImageUsage(used, name, tag.Name, filter.ImageUsage, maxTagByRepo) {
				continue
			}
			tag.RuntimeUsed = used
			if used {
				tag.Runtime = usage.Runtime
			}
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

// allLatestArtifactTagRows returns the newest artifact per (repository, tag) across the database.
func (s *SQLiteStore) allLatestArtifactTagRows(ctx context.Context) ([]struct{ repo, tag, digest string }, error) {
	query := `
		SELECT r.name, a.tag, a.digest
		FROM artifacts a
		JOIN repositories r ON a.repository_id = r.id
		INNER JOIN (
			SELECT a2.repository_id, a2.tag, MAX(a2.id) AS max_id
			FROM artifacts a2
			GROUP BY a2.repository_id, a2.tag
		) latest ON a.repository_id = latest.repository_id AND a.tag = latest.tag AND a.id = latest.max_id
		ORDER BY r.name, a.tag
	`
	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, errors.NewTransientf("failed to list latest artifact tag rows: %w", err)
	}
	defer rows.Close()

	var out []struct{ repo, tag, digest string }
	for rows.Next() {
		var row struct{ repo, tag, digest string }
		if err := rows.Scan(&row.repo, &row.tag, &row.digest); err != nil {
			return nil, errors.NewTransientf("failed to scan artifact tag row: %w", err)
		}
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		return nil, errors.NewTransientf("error iterating artifact tag rows: %w", err)
	}
	return out, nil
}

// repositoryNamesWithInUseOrNewerSemver maps repository name -> true if that repo should appear
// in the "in use or newer semver" repository list (any tag passes the scan list predicate for that mode).
func (s *SQLiteStore) repositoryNamesWithInUseOrNewerSemver(ctx context.Context) (map[string]bool, error) {
	rows, err := s.allLatestArtifactTagRows(ctx)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return map[string]bool{}, nil
	}
	lookups := make([]RuntimeLookupInput, 0, len(rows))
	for _, row := range rows {
		lookups = append(lookups, RuntimeLookupInput{
			Digest:     row.digest,
			Repository: row.repo,
			Tag:        row.tag,
		})
	}
	usageByDigest, err := s.GetRuntimeUsageForScans(ctx, lookups)
	if err != nil {
		return nil, err
	}
	inUseRows := make([]inUseTagRow, 0, len(rows))
	for _, row := range rows {
		u, ok := usageByDigest[row.digest]
		used := ok && u.RuntimeUsed
		inUseRows = append(inUseRows, inUseTagRow{repository: row.repo, tag: row.tag, used: used})
	}
	maxTagByRepo := maxInUseImageTagByRepository(inUseRows)

	visible := make(map[string]bool)
	for _, row := range rows {
		u, ok := usageByDigest[row.digest]
		used := ok && u.RuntimeUsed
		if recordPassesImageUsage(used, row.repo, row.tag, ImageUsageInUseOrNewerSemver, maxTagByRepo) {
			visible[row.repo] = true
		}
	}
	return visible, nil
}

// CleanupArtifactScans removes all scan records for all artifacts with the given digest (MANIFEST_UNKNOWN case).
// Also removes the artifacts and repositories if they become empty.
// This is used when a manifest is no longer available in the registry.
// Note: Multiple tags may point to the same digest, so we clean up all of them.
