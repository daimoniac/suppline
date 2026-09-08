package main

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/daimoniac/suppline/internal/scanenqueue"
	"github.com/daimoniac/suppline/internal/statestore"
)

// dueArtifactLister reports artifacts whose last scan has aged past the rescan interval.
type dueArtifactLister interface {
	ListDueForRescanArtifacts(ctx context.Context, olderThan time.Duration) ([]*statestore.ScanRecord, error)
}

// enqueueDueArtifacts seeds the queue with artifacts whose last scan has aged past the
// rescan interval. Registry discovery eventually finds the same work, but only after
// walking every configured repository, so without this a restart leaves the workers idle
// for minutes and silently drops whatever the previous process had already queued.
//
// In-use artifacts go in ahead of the rest, and both go in at regular priority so the
// startup rescan of failed in-use artifacts stays ahead of them.
func enqueueDueArtifacts(
	ctx context.Context,
	store dueArtifactLister,
	scanEnqueuer *scanenqueue.Enqueuer,
	rescanInterval time.Duration,
	logger *slog.Logger,
) error {
	dueArtifacts, err := store.ListDueForRescanArtifacts(ctx, rescanInterval)
	if err != nil {
		return fmt.Errorf("failed to list artifacts due for rescan: %w", err)
	}

	if len(dueArtifacts) == 0 {
		logger.Info("no artifacts due for rescan on startup")
		return nil
	}

	inUse, notInUse := partitionArtifactsByRuntimeUsage(dueArtifacts)
	logger.Info("seeding queue with artifacts due for rescan",
		"total", len(dueArtifacts),
		"in_use", len(inUse),
		"not_in_use", len(notInUse))

	ordered := make([]*statestore.ScanRecord, 0, len(inUse)+len(notInUse))
	ordered = append(ordered, inUse...)
	ordered = append(ordered, notInUse...)

	enqueuedCount := 0
	for _, artifact := range ordered {
		if _, err := scanEnqueuer.EnqueueRescan(ctx, scanenqueue.Image{
			Repository: artifact.Repository,
			Digest:     artifact.Digest,
			Tag:        artifact.Tag,
		}); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			logger.Error("failed to enqueue artifact due for rescan",
				"repository", artifact.Repository,
				"digest", artifact.Digest,
				"tag", artifact.Tag,
				"error", err)
			continue
		}
		enqueuedCount++
	}

	logger.Info("finished seeding artifacts due for rescan",
		"enqueued", enqueuedCount,
		"in_use", len(inUse),
		"not_in_use", len(notInUse),
		"total", len(dueArtifacts))

	return nil
}
