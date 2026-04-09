package statestore

import (
	"context"
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

	return nil
}
