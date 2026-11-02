package statestore

import (
	"context"
	"errors"
	"sort"
	"strings"
	"time"

	domainerrors "github.com/daimoniac/suppline/internal/errors"
)

// ReconcileSupersededDigests drops retained digest bindings this repository no
// longer needs and returns the in-use digests that are not a current tag
// resolution and are due for another attestation.
//
// currentDigests are the digests the registry tags resolve to in this
// discovery cycle. Those are already on the watcher's scan path.
func (s *SQLiteStore) ReconcileSupersededDigests(ctx context.Context, repository string, currentDigests []string, rescanInterval time.Duration) ([]DigestRenewal, error) {
	repository = strings.TrimSpace(repository)
	if repository == "" {
		return nil, domainerrors.NewPermanentf("repository is required")
	}
	if rescanInterval <= 0 {
		rescanInterval = 7 * 24 * time.Hour
	}

	current := make(map[string]struct{}, len(currentDigests))
	for _, digest := range currentDigests {
		digest = strings.TrimSpace(digest)
		if digest == "" {
			continue
		}
		current[digest] = struct{}{}
	}

	inUse, err := s.inUseDigestTags(ctx, repository)
	if err != nil {
		return nil, err
	}
	if err := s.releaseUnusedSuperseded(ctx, repository, current, inUse); err != nil {
		return nil, err
	}

	cutoff := time.Now().UTC().Add(-rescanInterval).Unix()
	renewals := make([]DigestRenewal, 0)
	for digest, tag := range inUse {
		if _, isCurrent := current[digest]; isCurrent {
			continue
		}
		last, err := s.GetLastRepositoryScan(ctx, repository, digest)
		if err != nil && !errors.Is(err, ErrScanNotFound) {
			return nil, err
		}
		if err == nil && last.CreatedAt >= cutoff {
			continue
		}
		if stored := s.storedTagForDigest(ctx, repository, digest); stored != "" {
			tag = stored
		}
		if tag == "" {
			continue
		}
		renewals = append(renewals, DigestRenewal{
			Repository: repository,
			Digest:     digest,
			Tag:        tag,
		})
	}
	sort.Slice(renewals, func(i, j int) bool {
		return renewals[i].Digest < renewals[j].Digest
	})
	return renewals, nil
}

// inUseDigestTags returns digests cluster inventory currently reports for this
// repository, with one tag to record the renewal under. Tag-only observations
// are omitted: those follow the mutable tag the watcher already resolves.
func (s *SQLiteStore) inUseDigestTags(ctx context.Context, repository string) (map[string]string, error) {
	usage, err := s.queryRuntimeUsageByRepository(ctx, repository)
	if err != nil {
		return nil, err
	}
	out := make(map[string]string)
	if !usage.RuntimeUsed {
		return out, nil
	}
	for _, namespaces := range usage.Runtime {
		for _, images := range namespaces {
			for _, image := range images {
				digest := strings.TrimSpace(image.Digest)
				if digest == "" {
					continue
				}
				tag := strings.TrimSpace(image.Tag)
				existing, ok := out[digest]
				if !ok || (existing == "" && tag != "") {
					out[digest] = tag
				}
			}
		}
	}
	return out, nil
}

func (s *SQLiteStore) storedTagForDigest(ctx context.Context, repository, digest string) string {
	var tag string
	err := s.db.QueryRowContext(ctx, `
		SELECT COALESCE(a.tag, '')
		FROM artifacts a
		JOIN repositories r ON r.id = a.repository_id
		WHERE r.name = ? AND a.digest = ? AND COALESCE(a.tag, '') != ''
		ORDER BY a.superseded ASC, a.id DESC
		LIMIT 1
	`, repository, digest).Scan(&tag)
	if err != nil {
		return ""
	}
	return tag
}

func (s *SQLiteStore) releaseUnusedSuperseded(ctx context.Context, repository string, current map[string]struct{}, inUse map[string]string) error {
	rows, err := s.db.QueryContext(ctx, `
		SELECT a.id, a.digest
		FROM artifacts a
		JOIN repositories r ON r.id = a.repository_id
		WHERE r.name = ? AND a.superseded = 1
	`, repository)
	if err != nil {
		return domainerrors.NewTransientf("failed to query superseded digests: %w", err)
	}
	defer rows.Close()

	type doomed struct {
		id     int64
		digest string
	}
	var drop []doomed
	for rows.Next() {
		var item doomed
		if err := rows.Scan(&item.id, &item.digest); err != nil {
			return domainerrors.NewTransientf("failed to scan superseded digest: %w", err)
		}
		if _, ok := current[item.digest]; ok {
			continue
		}
		if _, ok := inUse[item.digest]; ok {
			continue
		}
		drop = append(drop, item)
	}
	if err := rows.Err(); err != nil {
		return domainerrors.NewTransientf("error iterating superseded digests: %w", err)
	}
	if len(drop) == 0 {
		return nil
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return domainerrors.NewTransientf("failed to begin superseded cleanup: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	for _, item := range drop {
		if err := deleteArtifactPreservingSharedScansTx(ctx, tx, item.id); err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return domainerrors.NewTransientf("failed to commit superseded cleanup: %w", err)
	}
	return nil
}
