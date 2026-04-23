package statestore

import (
	"context"
	"database/sql"
	"strings"

	"github.com/daimoniac/suppline/internal/errors"
)

func (s *SQLiteStore) ListRuntimeUnusedRepositoryWhitelist(ctx context.Context) ([]RuntimeUnusedRepositoryWhitelistEntry, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT repository, created_at
		FROM runtime_unused_repository_whitelist
		ORDER BY repository ASC
	`)
	if err != nil {
		return nil, errors.NewTransientf("failed to list runtime-unused repository whitelist: %w", err)
	}
	defer rows.Close()

	entries := make([]RuntimeUnusedRepositoryWhitelistEntry, 0)
	for rows.Next() {
		var entry RuntimeUnusedRepositoryWhitelistEntry
		if err := rows.Scan(&entry.Repository, &entry.CreatedAt); err != nil {
			return nil, errors.NewTransientf("failed to scan runtime-unused repository whitelist row: %w", err)
		}
		entries = append(entries, entry)
	}

	if err := rows.Err(); err != nil {
		return nil, errors.NewTransientf("failed iterating runtime-unused repository whitelist rows: %w", err)
	}

	return entries, nil
}

func (s *SQLiteStore) AddRuntimeUnusedRepositoryWhitelist(ctx context.Context, repository string) error {
	repository = strings.TrimSpace(repository)
	if repository == "" {
		return errors.NewPermanentf("repository is required")
	}

	if _, err := s.db.ExecContext(ctx, `
		INSERT INTO runtime_unused_repository_whitelist (repository)
		VALUES (?)
		ON CONFLICT(repository) DO NOTHING
	`, repository); err != nil {
		return errors.NewTransientf("failed to add runtime-unused repository whitelist entry: %w", err)
	}

	if err := s.refreshRepositorySummaryByName(ctx, repository); err != nil {
		return err
	}

	return nil
}

func (s *SQLiteStore) RemoveRuntimeUnusedRepositoryWhitelist(ctx context.Context, repository string) error {
	repository = strings.TrimSpace(repository)
	if repository == "" {
		return errors.NewPermanentf("repository is required")
	}

	if _, err := s.db.ExecContext(ctx, `
		DELETE FROM runtime_unused_repository_whitelist
		WHERE repository = ?
	`, repository); err != nil {
		return errors.NewTransientf("failed to remove runtime-unused repository whitelist entry: %w", err)
	}

	if err := s.refreshRepositorySummaryByName(ctx, repository); err != nil {
		return err
	}

	return nil
}

func (s *SQLiteStore) runtimeUnusedRepositoryWhitelistSet(ctx context.Context) (map[string]struct{}, error) {
	entries, err := s.ListRuntimeUnusedRepositoryWhitelist(ctx)
	if err != nil {
		return nil, err
	}

	whitelist := make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		repository := strings.TrimSpace(entry.Repository)
		if repository == "" {
			continue
		}
		whitelist[repository] = struct{}{}
	}

	return whitelist, nil
}

func (s *SQLiteStore) isRuntimeUnusedRepositoryWhitelisted(ctx context.Context, repository string) (bool, error) {
	repository = strings.TrimSpace(repository)
	if repository == "" {
		return false, nil
	}

	var marker int
	err := s.db.QueryRowContext(ctx, `
		SELECT 1
		FROM runtime_unused_repository_whitelist
		WHERE repository = ?
		LIMIT 1
	`, repository).Scan(&marker)
	if err == nil {
		return true, nil
	}
	if err == sql.ErrNoRows {
		return false, nil
	}

	return false, errors.NewTransientf("failed to query runtime-unused repository whitelist membership: %w", err)
}
