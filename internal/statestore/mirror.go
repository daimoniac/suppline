package statestore

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"
)

const (
	mirrorDeletionTag = "tag"
	mirrorDeletionHub = "hub_repo"
)

func (s *SQLiteStore) pruneExpiredMirrorDeletions(ctx context.Context, now time.Time) error {
	cutoff := now.Add(-MirrorDeletionRetention).Unix()
	_, err := s.db.ExecContext(ctx, `DELETE FROM mirror_deletions WHERE deleted_at < ?`, cutoff)
	if err != nil {
		return fmt.Errorf("prune mirror deletions: %w", err)
	}
	return nil
}

// ReplaceMirrorSyncs upserts the current config and drops syncs that left it.
// Tag deletions for a removed sync are dropped. Hub repository deletions stay.
func (s *SQLiteStore) ReplaceMirrorSyncs(ctx context.Context, syncs []MirrorSync) error {
	if err := s.pruneExpiredMirrorDeletions(ctx, time.Now()); err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin mirror sync replace: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	for _, sync := range syncs {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO mirror_syncs (sync_key, source, target, sync_type, schedule, position, status, error)
			VALUES (?, ?, ?, ?, ?, ?, 'never', '')
			ON CONFLICT(sync_key) DO UPDATE SET
				source = excluded.source,
				target = excluded.target,
				sync_type = excluded.sync_type,
				schedule = excluded.schedule,
				position = excluded.position
		`, sync.Key, sync.Source, sync.Target, sync.Type, sync.Schedule, sync.Position); err != nil {
			return fmt.Errorf("upsert mirror sync %s: %w", sync.Key, err)
		}
	}

	keys := make([]string, len(syncs))
	args := make([]any, len(syncs))
	for i, sync := range syncs {
		keys[i] = "?"
		args[i] = sync.Key
	}
	notIn := "SELECT sync_key FROM mirror_syncs WHERE 1 = 0"
	if len(args) > 0 {
		notIn = strings.Join(keys, ",")
	}
	for _, stmt := range []string{
		`DELETE FROM mirror_images WHERE sync_key NOT IN (` + notIn + `)`,
		`DELETE FROM mirror_deletions WHERE kind = '` + mirrorDeletionTag + `' AND sync_key NOT IN (` + notIn + `)`,
		`DELETE FROM mirror_syncs WHERE sync_key NOT IN (` + notIn + `)`,
	} {
		if _, err := tx.ExecContext(ctx, stmt, args...); err != nil {
			return fmt.Errorf("prune mirror syncs: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit mirror sync replace: %w", err)
	}
	return nil
}

// FinishMirrorSync records the last finished run. Running is not stored.
func (s *SQLiteStore) FinishMirrorSync(ctx context.Context, key, status, errMsg string, finishedAt time.Time) error {
	res, err := s.db.ExecContext(ctx, `
		UPDATE mirror_syncs SET status = ?, finished_at = ?, error = ? WHERE sync_key = ?
	`, status, finishedAt.Unix(), errMsg, key)
	if err != nil {
		return fmt.Errorf("finish mirror sync %s: %w", key, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("finish mirror sync %s: %w", key, err)
	}
	if n == 0 {
		return fmt.Errorf("finish mirror sync %s: sync not found", key)
	}
	return nil
}

// ObserveMirrorImage records a wanted tag that is present and clears a matching deletion.
func (s *SQLiteStore) ObserveMirrorImage(ctx context.Context, syncKey, repository, tag string, seenAt time.Time) error {
	if err := s.pruneExpiredMirrorDeletions(ctx, seenAt); err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin observe mirror image: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, `
		INSERT INTO mirror_images (sync_key, repository, tag, last_seen)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(sync_key, repository, tag) DO UPDATE SET last_seen = excluded.last_seen
	`, syncKey, repository, tag, seenAt.Unix()); err != nil {
		return fmt.Errorf("observe mirror image: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		DELETE FROM mirror_deletions
		WHERE kind = ? AND sync_key = ? AND repository = ? AND tag = ?
	`, mirrorDeletionTag, syncKey, repository, tag); err != nil {
		return fmt.Errorf("clear restored tag deletion: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		DELETE FROM mirror_deletions
		WHERE kind = ? AND (
			repository = ? OR
			? LIKE '%/' || repository OR
			repository LIKE '%/' || ?
		)
	`, mirrorDeletionHub, repository, repository, repository); err != nil {
		return fmt.Errorf("clear restored hub deletion: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit observe mirror image: %w", err)
	}
	return nil
}

// PruneMirrorImages drops current images for one sync that this run did not observe.
func (s *SQLiteStore) PruneMirrorImages(ctx context.Context, syncKey string, keep []MirrorImage) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin prune mirror images: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, `DROP TABLE IF EXISTS mirror_keep`); err != nil {
		return fmt.Errorf("drop mirror keep: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		CREATE TEMP TABLE mirror_keep (
			repository TEXT NOT NULL,
			tag TEXT NOT NULL,
			PRIMARY KEY (repository, tag)
		)
	`); err != nil {
		return fmt.Errorf("create mirror keep: %w", err)
	}
	for _, image := range keep {
		if _, err := tx.ExecContext(ctx, `INSERT INTO mirror_keep (repository, tag) VALUES (?, ?) ON CONFLICT DO NOTHING`, image.Repository, image.Tag); err != nil {
			return fmt.Errorf("insert mirror keep: %w", err)
		}
	}
	if _, err := tx.ExecContext(ctx, `
		DELETE FROM mirror_images
		WHERE sync_key = ?
		  AND NOT EXISTS (
			SELECT 1 FROM mirror_keep k
			WHERE k.repository = mirror_images.repository AND k.tag = mirror_images.tag
		  )
	`, syncKey); err != nil {
		return fmt.Errorf("prune mirror images: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `DROP TABLE IF EXISTS mirror_keep`); err != nil {
		return fmt.Errorf("drop mirror keep: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit prune mirror images: %w", err)
	}
	return nil
}

// RecordMirrorTagDeletion removes the tag from the current set and lists the deletion.
func (s *SQLiteStore) RecordMirrorTagDeletion(ctx context.Context, syncKey, repository, tag string, deletedAt time.Time) error {
	if err := s.pruneExpiredMirrorDeletions(ctx, deletedAt); err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tag deletion: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `
		DELETE FROM mirror_images WHERE sync_key = ? AND repository = ? AND tag = ?
	`, syncKey, repository, tag); err != nil {
		return fmt.Errorf("remove deleted mirror image: %w", err)
	}
	if err := upsertMirrorDeletion(ctx, tx, syncKey, mirrorDeletionTag, repository, tag, deletedAt); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tag deletion: %w", err)
	}
	return nil
}

// RecordMirrorHubDeletion lists one Docker Hub repository cleanup and drops current images of that repository.
func (s *SQLiteStore) RecordMirrorHubDeletion(ctx context.Context, repository string, deletedAt time.Time) error {
	if err := s.pruneExpiredMirrorDeletions(ctx, deletedAt); err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin hub deletion: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `
		DELETE FROM mirror_images
		WHERE repository = ? OR repository LIKE '%/' || ? OR ? LIKE '%/' || repository
	`, repository, repository, repository); err != nil {
		return fmt.Errorf("remove hub repository images: %w", err)
	}
	if err := upsertMirrorDeletion(ctx, tx, "", mirrorDeletionHub, repository, "", deletedAt); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit hub deletion: %w", err)
	}
	return nil
}

func upsertMirrorDeletion(ctx context.Context, tx *Tx, syncKey, kind, repository, tag string, deletedAt time.Time) error {
	_, err := tx.ExecContext(ctx, `
		INSERT INTO mirror_deletions (sync_key, kind, repository, tag, deleted_at)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(sync_key, kind, repository, tag) DO UPDATE SET deleted_at = excluded.deleted_at
	`, syncKey, kind, repository, tag, deletedAt.Unix())
	if err != nil {
		return fmt.Errorf("upsert mirror deletion: %w", err)
	}
	return nil
}

// SetMirrorHubError stores the last cleanupRepos error. An empty message clears it.
func (s *SQLiteStore) SetMirrorHubError(ctx context.Context, message string) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO mirror_hub_status (id, last_error) VALUES (1, ?)
		ON CONFLICT(id) DO UPDATE SET last_error = excluded.last_error
	`, message)
	if err != nil {
		return fmt.Errorf("set mirror hub error: %w", err)
	}
	return nil
}

// ListMirrorSyncs returns syncs in config order with image and tag-deletion counts.
func (s *SQLiteStore) ListMirrorSyncs(ctx context.Context) ([]MirrorSyncSummary, error) {
	now := time.Now()
	if err := s.pruneExpiredMirrorDeletions(ctx, now); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT sync_key, source, target, sync_type, schedule, position, status, finished_at, error,
			(SELECT COUNT(*) FROM mirror_images i WHERE i.sync_key = mirror_syncs.sync_key),
			(SELECT COUNT(*) FROM mirror_deletions d WHERE d.kind = ? AND d.sync_key = mirror_syncs.sync_key)
		FROM mirror_syncs
		ORDER BY position ASC, sync_key ASC
	`, mirrorDeletionTag)
	if err != nil {
		return nil, fmt.Errorf("list mirror syncs: %w", err)
	}
	defer rows.Close()

	out := []MirrorSyncSummary{}
	for rows.Next() {
		var item MirrorSyncSummary
		var finished sql.NullInt64
		if err := rows.Scan(
			&item.Key, &item.Source, &item.Target, &item.Type, &item.Schedule, &item.Position,
			&item.Status, &finished, &item.Error, &item.ImageCount, &item.TagDeletionCount,
		); err != nil {
			return nil, fmt.Errorf("scan mirror sync: %w", err)
		}
		if finished.Valid {
			unix := finished.Int64
			item.FinishedAt = &unix
		}
		out = append(out, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list mirror syncs: %w", err)
	}
	return out, nil
}

// ListMirrorImages returns a page of current images for one sync.
func (s *SQLiteStore) ListMirrorImages(ctx context.Context, syncKey string, limit, offset int) ([]MirrorImage, int, error) {
	return listMirrorImages(ctx, s, syncKey, limit, offset)
}

func listMirrorImages(ctx context.Context, s *SQLiteStore, syncKey string, limit, offset int) ([]MirrorImage, int, error) {
	var total int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM mirror_images WHERE sync_key = ?`, syncKey).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count mirror images: %w", err)
	}
	if limit <= 0 {
		limit = total
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT repository, tag, last_seen
		FROM mirror_images
		WHERE sync_key = ?
		ORDER BY repository ASC, tag ASC
		LIMIT ? OFFSET ?
	`, syncKey, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("list mirror images: %w", err)
	}
	defer rows.Close()
	out := []MirrorImage{}
	for rows.Next() {
		var item MirrorImage
		if err := rows.Scan(&item.Repository, &item.Tag, &item.LastSeen); err != nil {
			return nil, 0, fmt.Errorf("scan mirror image: %w", err)
		}
		out = append(out, item)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("list mirror images: %w", err)
	}
	return out, total, nil
}

// ListMirrorTagDeletions returns a page of tag deletions for one sync.
func (s *SQLiteStore) ListMirrorTagDeletions(ctx context.Context, syncKey string, limit, offset int) ([]MirrorDeletion, int, error) {
	if err := s.pruneExpiredMirrorDeletions(ctx, time.Now()); err != nil {
		return nil, 0, err
	}
	return listMirrorDeletions(ctx, s, mirrorDeletionTag, syncKey, limit, offset)
}

// ListMirrorHubDeletions returns a page of Docker Hub repository deletions.
func (s *SQLiteStore) ListMirrorHubDeletions(ctx context.Context, limit, offset int) ([]MirrorDeletion, int, error) {
	if err := s.pruneExpiredMirrorDeletions(ctx, time.Now()); err != nil {
		return nil, 0, err
	}
	return listMirrorDeletions(ctx, s, mirrorDeletionHub, "", limit, offset)
}

func listMirrorDeletions(ctx context.Context, s *SQLiteStore, kind, syncKey string, limit, offset int) ([]MirrorDeletion, int, error) {
	var total int
	if err := s.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM mirror_deletions WHERE kind = ? AND sync_key = ?
	`, kind, syncKey).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count mirror deletions: %w", err)
	}
	if limit <= 0 {
		limit = total
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT repository, tag, deleted_at
		FROM mirror_deletions
		WHERE kind = ? AND sync_key = ?
		ORDER BY deleted_at DESC, repository ASC, tag ASC
		LIMIT ? OFFSET ?
	`, kind, syncKey, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("list mirror deletions: %w", err)
	}
	defer rows.Close()
	out := []MirrorDeletion{}
	for rows.Next() {
		var item MirrorDeletion
		if err := rows.Scan(&item.Repository, &item.Tag, &item.DeletedAt); err != nil {
			return nil, 0, fmt.Errorf("scan mirror deletion: %w", err)
		}
		out = append(out, item)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("list mirror deletions: %w", err)
	}
	return out, total, nil
}

// MirrorHubError returns the last cleanupRepos error, or empty when the last run succeeded.
func (s *SQLiteStore) MirrorHubError(ctx context.Context) (string, error) {
	var message string
	err := s.db.QueryRowContext(ctx, `SELECT last_error FROM mirror_hub_status WHERE id = 1`).Scan(&message)
	if err == sql.ErrNoRows {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("read mirror hub error: %w", err)
	}
	return message, nil
}
