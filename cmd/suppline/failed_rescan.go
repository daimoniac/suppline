package main

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/daimoniac/suppline/internal/scanenqueue"
	"github.com/daimoniac/suppline/internal/statestore"
)

// partitionArtifactsByRuntimeUsage splits artifacts into in-use and not-in-use
// buckets. Relative order within each bucket is preserved.
func partitionArtifactsByRuntimeUsage(
	artifacts []*statestore.ScanRecord,
) (inUse, notInUse []*statestore.ScanRecord) {
	inUse = make([]*statestore.ScanRecord, 0, len(artifacts))
	notInUse = make([]*statestore.ScanRecord, 0, len(artifacts))
	for _, artifact := range artifacts {
		if artifact == nil {
			continue
		}
		if artifact.RuntimeUsed {
			inUse = append(inUse, artifact)
		} else {
			notInUse = append(notInUse, artifact)
		}
	}
	return inUse, notInUse
}

// enqueueFailedArtifacts retrieves failed artifacts from the state store and
// enqueues in-use ones for immediate high-priority rescanning on startup.
// Unused policy-failed digests are skipped so they are not prioritized over
// regular watcher scans; they continue via normal interval/rescan scheduling.
func enqueueFailedArtifacts(ctx context.Context, store statestore.StateStoreQuery, scanEnqueuer *scanenqueue.Enqueuer, logger *slog.Logger) error {
	failedArtifacts, err := store.GetFailedArtifacts(ctx)
	if err != nil {
		return fmt.Errorf("failed to get failed artifacts: %w", err)
	}

	if len(failedArtifacts) == 0 {
		logger.Info("no failed artifacts found to rescan")
		return nil
	}

	logger.Info("found failed artifacts to consider for startup rescan", "count", len(failedArtifacts))

	inUse, notInUse := partitionArtifactsByRuntimeUsage(failedArtifacts)
	if len(inUse) == 0 {
		logger.Info("no in-use failed artifacts to rescan on startup",
			"skipped_not_in_use", len(notInUse),
			"total", len(failedArtifacts))
		return nil
	}

	enqueuedCount := 0
	for _, artifact := range inUse {
		if _, err := scanEnqueuer.EnqueueUrgentRescan(ctx, scanenqueue.Image{
			Repository: artifact.Repository,
			Digest:     artifact.Digest,
			Tag:        artifact.Tag,
		}); err != nil {
			logger.Error("failed to enqueue failed artifact",
				"repository", artifact.Repository,
				"digest", artifact.Digest,
				"tag", artifact.Tag,
				"error", err)
			continue
		}

		logger.Info("enqueued in-use failed artifact for rescan",
			"repository", artifact.Repository,
			"digest", artifact.Digest,
			"tag", artifact.Tag,
			"critical_vulns", artifact.CriticalVulnCount)
		enqueuedCount++
	}

	logger.Info("finished enqueueing in-use failed artifacts",
		"enqueued", enqueuedCount,
		"in_use", len(inUse),
		"skipped_not_in_use", len(notInUse),
		"total", len(failedArtifacts))

	return nil
}
