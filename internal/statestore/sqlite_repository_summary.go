package statestore

import (
	"context"
	"database/sql"
	"log/slog"
	"time"

	"github.com/daimoniac/suppline/internal/errors"
)

// ensureRepositorySummaries inserts missing summary rows and backfills when the table
// is new, incomplete, or never populated (updated_at = 0).
func (s *SQLiteStore) ensureRepositorySummaries(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, `
		INSERT OR IGNORE INTO repository_summary (repository_id)
		SELECT id FROM repositories
	`); err != nil {
		return errors.NewTransientf("failed to seed repository_summary rows: %w", err)
	}

	var repoCount, summaryCount, staleCount, missingJoin int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM repositories`).Scan(&repoCount); err != nil {
		return errors.NewTransientf("failed to count repositories: %w", err)
	}
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM repository_summary`).Scan(&summaryCount); err != nil {
		return errors.NewTransientf("failed to count repository_summary: %w", err)
	}
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM repository_summary WHERE updated_at = 0`).Scan(&staleCount); err != nil {
		return errors.NewTransientf("failed to count stale repository_summary rows: %w", err)
	}
	if err := s.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM repositories r
		LEFT JOIN repository_summary rs ON rs.repository_id = r.id
		WHERE rs.repository_id IS NULL
	`).Scan(&missingJoin); err != nil {
		return errors.NewTransientf("failed to count repositories missing summary: %w", err)
	}

	if missingJoin == 0 && staleCount == 0 && repoCount == summaryCount {
		return nil
	}

	slog.Info("repository_summary backfill starting",
		"repositories", repoCount,
		"summaries", summaryCount,
		"stale_rows", staleCount,
		"missing_summary_rows", missingJoin,
	)

	rows, err := s.db.QueryContext(ctx, `SELECT id FROM repositories ORDER BY id`)
	if err != nil {
		return errors.NewTransientf("failed to list repositories for summary backfill: %w", err)
	}
	defer rows.Close()

	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return errors.NewTransientf("failed to scan repository id: %w", err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return errors.NewTransientf("error iterating repositories for summary backfill: %w", err)
	}

	for _, id := range ids {
		if err := s.refreshRepositorySummary(ctx, id); err != nil {
			return err
		}
	}

	slog.Info("repository_summary backfill complete", "repositories", len(ids))
	return nil
}

// repairRepositorySummariesForList ensures rows inserted outside RecordScan (e.g. tests) are populated.
func (s *SQLiteStore) repairRepositorySummariesForList(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, `
		INSERT OR IGNORE INTO repository_summary (repository_id)
		SELECT id FROM repositories
	`); err != nil {
		return errors.NewTransientf("failed to seed repository_summary for list: %w", err)
	}

	var stale int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM repository_summary WHERE updated_at = 0`).Scan(&stale); err != nil {
		return errors.NewTransientf("failed to count uninitialized repository_summary rows: %w", err)
	}
	if stale == 0 {
		return nil
	}

	rows, err := s.db.QueryContext(ctx, `SELECT repository_id FROM repository_summary WHERE updated_at = 0`)
	if err != nil {
		return errors.NewTransientf("failed to query stale repository_summary rows: %w", err)
	}
	defer rows.Close()

	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return errors.NewTransientf("failed to scan stale repository_summary id: %w", err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return errors.NewTransientf("error iterating stale repository_summary: %w", err)
	}

	for _, id := range ids {
		if err := s.refreshRepositorySummary(ctx, id); err != nil {
			return err
		}
	}
	return nil
}

// refreshRepositorySummary recomputes denormalized list fields for one repository.
func (s *SQLiteStore) refreshRepositorySummary(ctx context.Context, repositoryID int64) error {
	var repoName string
	err := s.db.QueryRowContext(ctx, `SELECT name FROM repositories WHERE id = ?`, repositoryID).Scan(&repoName)
	if err == sql.ErrNoRows {
		return nil
	}
	if err != nil {
		return errors.NewTransientf("failed to load repository name for summary: %w", err)
	}

	var artifactCount int
	var lastScanTime sql.NullInt64
	var maxCritical, maxHigh, maxMedium, maxLow int64
	var policyPassed int
	var policyStatus string

	err = s.db.QueryRowContext(ctx, `
		SELECT
			COUNT(DISTINCT a.id),
			(SELECT MAX(sr2.created_at) FROM scan_records sr2
			 JOIN artifacts a2 ON sr2.artifact_id = a2.id
			 WHERE a2.repository_id = r.id),
			COALESCE(MAX(sr.critical_vuln_count), 0),
			COALESCE(MAX(sr.high_vuln_count), 0),
			COALESCE(MAX(sr.medium_vuln_count), 0),
			COALESCE(MAX(sr.low_vuln_count), 0),
			CASE WHEN COUNT(CASE WHEN sr.policy_passed = 0 THEN 1 END) > 0 THEN 0 ELSE 1 END,
			CASE
				WHEN COUNT(CASE WHEN sr.policy_status = 'failed' THEN 1 END) > 0 THEN 'failed'
				WHEN COUNT(CASE WHEN sr.policy_status = 'pending' THEN 1 END) > 0 THEN 'pending'
				WHEN COUNT(CASE WHEN sr.policy_passed = 0 THEN 1 END) > 0 THEN 'failed'
				ELSE 'passed'
			END
		FROM repositories r
		LEFT JOIN artifacts a ON a.repository_id = r.id
		LEFT JOIN scan_records sr ON a.last_scan_id = sr.id
		WHERE r.id = ?
		GROUP BY r.id
	`, repositoryID).Scan(
		&artifactCount,
		&lastScanTime,
		&maxCritical,
		&maxHigh,
		&maxMedium,
		&maxLow,
		&policyPassed,
		&policyStatus,
	)
	if err != nil {
		return errors.NewTransientf("failed to aggregate repository summary: %w", err)
	}

	runtimeByID, err := s.repositoryRuntimeUsageByID(ctx, map[int64]string{repositoryID: repoName})
	if err != nil {
		return err
	}
	runtimeUsed := 0
	if runtimeByID[repositoryID] {
		runtimeUsed = 1
	}

	whitelisted := 0
	if err := s.db.QueryRowContext(ctx, `
		SELECT EXISTS(SELECT 1 FROM runtime_unused_repository_whitelist WHERE repository = ?)
	`, repoName).Scan(&whitelisted); err != nil {
		return errors.NewTransientf("failed to query whitelist for repository summary: %w", err)
	}

	now := time.Now().Unix()
	var lastScanArg interface{}
	if lastScanTime.Valid {
		lastScanArg = lastScanTime.Int64
	} else {
		lastScanArg = nil
	}

	if _, err := s.db.ExecContext(ctx, `
		INSERT INTO repository_summary (
			repository_id, artifact_count, last_scan_time,
			max_critical, max_high, max_medium, max_low,
			policy_passed, policy_status, runtime_used, whitelisted, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(repository_id) DO UPDATE SET
			artifact_count = excluded.artifact_count,
			last_scan_time = excluded.last_scan_time,
			max_critical = excluded.max_critical,
			max_high = excluded.max_high,
			max_medium = excluded.max_medium,
			max_low = excluded.max_low,
			policy_passed = excluded.policy_passed,
			policy_status = excluded.policy_status,
			runtime_used = excluded.runtime_used,
			whitelisted = excluded.whitelisted,
			updated_at = excluded.updated_at
	`,
		repositoryID,
		artifactCount,
		lastScanArg,
		maxCritical,
		maxHigh,
		maxMedium,
		maxLow,
		policyPassed,
		policyStatus,
		runtimeUsed,
		whitelisted,
		now,
	); err != nil {
		return errors.NewTransientf("failed to upsert repository_summary: %w", err)
	}

	return nil
}

// refreshRuntimeUsedAllRepositories updates runtime_used for every repository (after cluster inventory changes).
func (s *SQLiteStore) refreshRuntimeUsedAllRepositories(ctx context.Context) error {
	rows, err := s.db.QueryContext(ctx, `SELECT id, name FROM repositories ORDER BY id`)
	if err != nil {
		return errors.NewTransientf("failed to list repositories for runtime summary refresh: %w", err)
	}
	defer rows.Close()

	namesByID := make(map[int64]string)
	for rows.Next() {
		var id int64
		var name string
		if err := rows.Scan(&id, &name); err != nil {
			return errors.NewTransientf("failed to scan repository row: %w", err)
		}
		namesByID[id] = name
	}
	if err := rows.Err(); err != nil {
		return errors.NewTransientf("error iterating repositories: %w", err)
	}

	if len(namesByID) == 0 {
		return nil
	}

	if _, err := s.db.ExecContext(ctx, `
		INSERT OR IGNORE INTO repository_summary (repository_id) SELECT id FROM repositories
	`); err != nil {
		return errors.NewTransientf("failed to ensure repository_summary rows before runtime refresh: %w", err)
	}

	runtimeByID, err := s.repositoryRuntimeUsageByID(ctx, namesByID)
	if err != nil {
		return err
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return errors.NewTransientf("failed to begin transaction for runtime summary refresh: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	now := time.Now().Unix()
	for id := range namesByID {
		runtimeUsed := 0
		if runtimeByID[id] {
			runtimeUsed = 1
		}
		if _, err := tx.ExecContext(ctx, `
			UPDATE repository_summary SET runtime_used = ?, updated_at = ? WHERE repository_id = ?
		`, runtimeUsed, now, id); err != nil {
			return errors.NewTransientf("failed to update runtime_used in repository_summary: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return errors.NewTransientf("failed to commit runtime summary refresh: %w", err)
	}

	return nil
}

// refreshRepositorySummaryByName runs refreshRepositorySummary when the repository exists.
func (s *SQLiteStore) refreshRepositorySummaryByName(ctx context.Context, repositoryName string) error {
	var repoID int64
	err := s.db.QueryRowContext(ctx, `SELECT id FROM repositories WHERE name = ?`, repositoryName).Scan(&repoID)
	if err == sql.ErrNoRows {
		return nil
	}
	if err != nil {
		return errors.NewTransientf("failed to resolve repository for summary refresh: %w", err)
	}
	return s.refreshRepositorySummary(ctx, repoID)
}
