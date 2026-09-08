package main

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/daimoniac/suppline/internal/config"
	"github.com/daimoniac/suppline/internal/queue"
	"github.com/daimoniac/suppline/internal/statestore"
)

// partitionFailedArtifactsByRuntimeUsage splits failed artifacts into in-use and
// not-in-use buckets. Relative order within each bucket is preserved.
func partitionFailedArtifactsByRuntimeUsage(
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
func enqueueFailedArtifacts(ctx context.Context, store statestore.StateStoreQuery, taskQueue queue.TaskQueue, regsyncCfg *config.RegsyncConfig, logger *slog.Logger) error {
	failedArtifacts, err := store.GetFailedArtifacts(ctx)
	if err != nil {
		return fmt.Errorf("failed to get failed artifacts: %w", err)
	}

	if len(failedArtifacts) == 0 {
		logger.Info("no failed artifacts found to rescan")
		return nil
	}

	logger.Info("found failed artifacts to consider for startup rescan", "count", len(failedArtifacts))

	inUse, notInUse := partitionFailedArtifactsByRuntimeUsage(failedArtifacts)
	if len(inUse) == 0 {
		logger.Info("no in-use failed artifacts to rescan on startup",
			"skipped_not_in_use", len(notInUse),
			"total", len(failedArtifacts))
		return nil
	}

	enqueuedCount := 0
	for _, artifact := range inUse {
		vexStatements := regsyncCfg.GetVEXStatementsForTarget(artifact.Repository)

		task := &queue.ScanTask{
			ID:            fmt.Sprintf("%s-%d", artifact.Digest, time.Now().Unix()),
			Repository:    artifact.Repository,
			Digest:        artifact.Digest,
			Tag:           artifact.Tag,
			EnqueuedAt:    time.Now(),
			IsRescan:      true,
			IsFirstScan:   false,
			Priority:      queue.PriorityHigh,
			VEXStatements: vexStatements,
			UseVEXRepo:    regsyncCfg.GetVEXRepoForTarget(artifact.Repository),
		}

		if err := taskQueue.Enqueue(ctx, task); err != nil {
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
