package watcher

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/suppline/suppline/internal/observability"
	"github.com/suppline/suppline/internal/queue"
	"github.com/suppline/suppline/internal/registry"
	"github.com/suppline/suppline/internal/regsync"
	"github.com/suppline/suppline/internal/statestore"
)

// Watcher continuously monitors the container registry for new and updated images
type Watcher interface {
	// Start begins the continuous discovery loop
	Start(ctx context.Context) error

	// Discover performs a single discovery cycle
	Discover(ctx context.Context) error
}

// watcherImpl implements the Watcher interface
type watcherImpl struct {
	registryClient registry.Client
	regsyncConfig  *regsync.Config
	stateStore     statestore.StateStore
	taskQueue      queue.TaskQueue
	pollInterval   time.Duration
	rescanInterval time.Duration
	logger         *slog.Logger
}

// Config contains configuration for the watcher
type Config struct {
	PollInterval   time.Duration
	RescanInterval time.Duration
}

// NewWatcher creates a new registry watcher
func NewWatcher(
	registryClient registry.Client,
	regsyncConfig  *regsync.Config,
	stateStore     statestore.StateStore,
	taskQueue      queue.TaskQueue,
	config Config,
	logger *slog.Logger,
) Watcher {
	return &watcherImpl{
		registryClient: registryClient,
		regsyncConfig:  regsyncConfig,
		stateStore:     stateStore,
		taskQueue:      taskQueue,
		pollInterval:   config.PollInterval,
		rescanInterval: config.RescanInterval,
		logger:         logger,
	}
}

// Start begins the continuous discovery loop
func (w *watcherImpl) Start(ctx context.Context) error {
	w.logger.Info("starting registry watcher",
		"poll_interval", w.pollInterval.String(),
		"rescan_interval", w.rescanInterval.String())

	// Perform initial discovery
	if err := w.Discover(ctx); err != nil {
		w.logger.Error("initial discovery failed",
			"error", err.Error())
	}

	// Start polling loop - wait for poll interval after each discovery completes
	for {
		select {
		case <-ctx.Done():
			w.logger.Info("registry watcher shutting down")
			return ctx.Err()
		case <-time.After(w.pollInterval):
			if err := w.Discover(ctx); err != nil {
				w.logger.Error("discovery cycle failed",
					"error", err.Error())
			}
		}
	}
}

// Discover performs a single discovery cycle
func (w *watcherImpl) Discover(ctx context.Context) error {
	w.logger.Info("starting discovery cycle")

	// Get target repositories from regsync config (already filtered)
	repositories, err := w.registryClient.ListRepositories(ctx)
	if err != nil {
		return fmt.Errorf("failed to list repositories: %w", err)
	}

	w.logger.Info("discovered target repositories",
		"count", len(repositories))

	// Process each repository
	// Note: Rescan interval checking is handled within processTag's shouldScanImage logic
	for _, repo := range repositories {
		if err := w.processRepository(ctx, repo); err != nil {
			w.logger.Error("failed to process repository",
				"repo", repo,
				"error", err.Error())
			continue
		}
	}

	w.logger.Info("discovery cycle completed")
	return nil
}

// processRepository discovers and enqueues images from a single repository
func (w *watcherImpl) processRepository(ctx context.Context, repo string) error {
	// Get CVE tolerations for this target repository
	tolerations := w.regsyncConfig.GetTolerationsForTarget(repo)

	// Convert regsync tolerations to queue tolerations
	queueTolerations := make([]queue.CVEToleration, len(tolerations))
	for i, t := range tolerations {
		queueTolerations[i] = queue.CVEToleration{
			ID:        t.ID,
			Statement: t.Statement,
			ExpiresAt: t.ExpiresAt,
		}
	}

	// Check for expiring tolerations and log warnings
	w.checkExpiringTolerations(repo, tolerations)

	// List all tags for the repository
	tags, err := w.registryClient.ListTags(ctx, repo)
	if err != nil {
		return fmt.Errorf("failed to list tags: %w", err)
	}

	w.logger.Debug("repository tags discovered",
		"repo", repo,
		"tag_count", len(tags))

	// Process each tag
	for _, tag := range tags {
		if err := w.processTag(ctx, repo, tag, queueTolerations); err != nil {
			w.logger.Error("failed to process tag",
				"repo", repo,
				"tag", tag,
				"error", err.Error())
			continue
		}
	}

	return nil
}

// shouldScanImage determines if an image should be scanned based on digest comparison and scan history
func (w *watcherImpl) shouldScanImage(
	ctx context.Context,
	repo string,
	tag string,
	currentDigest string,
	rescanInterval time.Duration,
) (shouldScan bool, reason string, isRescan bool, err error) {
	// Step 1: Check scan history
	lastScan, err := w.stateStore.GetLastScan(ctx, currentDigest)
	if err != nil {
		if errors.Is(err, statestore.ErrScanNotFound) {
			return true, "never scanned before", false, nil
		}
		return false, "", false, fmt.Errorf("failed to check scan history: %w", err)
	}

	// Step 2: Check if digest in scan record matches current digest
	if lastScan.Digest != currentDigest {
		return true, "digest changed since last scan", false, nil
	}

	// Step 3: Check rescan interval
	timeSinceLastScan := time.Since(lastScan.ScannedAt)
	if timeSinceLastScan >= rescanInterval {
		return true, fmt.Sprintf("rescan interval elapsed (%v since last scan)", timeSinceLastScan), true, nil
	}

	// Step 4: Skip - already scanned and up to date
	return false, fmt.Sprintf("already scanned %v ago, no changes", timeSinceLastScan), false, nil
}

// processTag processes a single image tag
func (w *watcherImpl) processTag(ctx context.Context, repo, tag string, tolerations []queue.CVEToleration) error {
	// Get current digest from registry
	currentDigest, err := w.registryClient.GetDigest(ctx, repo, tag)
	if err != nil {
		return fmt.Errorf("failed to get current digest: %w", err)
	}

	// Get rescan interval from regsync config (with fallback)
	rescanInterval, err := w.regsyncConfig.GetRescanInterval(repo)
	if err != nil {
		w.logger.Warn("failed to parse rescan interval, using default 7d",
			"repo", repo,
			"error", err.Error())
		rescanInterval = 7 * 24 * time.Hour
	}

	// Determine if scanning is needed
	shouldScan, reason, isRescan, err := w.shouldScanImage(ctx, repo, tag, currentDigest, rescanInterval)
	if err != nil {
		w.logger.Error("failed to determine scan necessity, enqueuing to be safe",
			"repo", repo,
			"tag", tag,
			"error", err.Error())
		shouldScan = true
		reason = "error checking scan state"
		isRescan = false
	}

	// Get metrics instance
	metrics := observability.GetMetrics()

	// Log decision with structured fields and record metrics
	if shouldScan {
		// Get last scan info for additional context in logs
		lastScan, scanErr := w.stateStore.GetLastScan(ctx, currentDigest)
		
		// Build log attributes
		attrs := []any{
			"repo", repo,
			"tag", tag,
			"digest", currentDigest,
			"reason", reason,
			"is_rescan", isRescan,
		}
		
		// Add additional context based on reason
		if scanErr == nil && lastScan != nil {
			if lastScan.Digest != currentDigest {
				attrs = append(attrs, "old_digest", lastScan.Digest, "new_digest", currentDigest)
			}
			if isRescan {
				timeSinceLastScan := time.Since(lastScan.ScannedAt)
				attrs = append(attrs,
					"last_scan_time", lastScan.ScannedAt.Format(time.RFC3339),
					"time_since_scan", timeSinceLastScan.String(),
					"rescan_interval", rescanInterval.String())
			}
		}
		
		w.logger.Info("enqueuing scan task", attrs...)

		// Record metrics for enqueue decision
		metrics.ConditionalScanDecisionsTotal.WithLabelValues("enqueue", reason).Inc()
		metrics.ConditionalScanEnqueuedTotal.WithLabelValues(repo, reason).Inc()
	} else {
		// For skip decisions, get last scan info to include in logs
		lastScan, scanErr := w.stateStore.GetLastScan(ctx, currentDigest)
		
		// Build log attributes
		attrs := []any{
			"repo", repo,
			"tag", tag,
			"digest", currentDigest,
			"reason", reason,
		}
		
		var timeSinceLastScan time.Duration
		if scanErr == nil && lastScan != nil {
			timeSinceLastScan = time.Since(lastScan.ScannedAt)
			attrs = append(attrs,
				"last_scan_time", lastScan.ScannedAt.Format(time.RFC3339),
				"time_since_scan", timeSinceLastScan.String(),
				"rescan_interval", rescanInterval.String())
		}
		
		w.logger.Debug("skipping scan", attrs...)

		// Record metrics for skip decision
		metrics.ConditionalScanDecisionsTotal.WithLabelValues("skip", reason).Inc()
		metrics.ConditionalScanSkippedTotal.WithLabelValues(repo).Inc()
		
		// Record time since last scan in histogram (if available)
		if scanErr == nil && lastScan != nil {
			metrics.ConditionalScanSkipAgeSeconds.WithLabelValues(repo).Observe(timeSinceLastScan.Seconds())
		}
		
		return nil
	}

	// Enqueue task
	task := &queue.ScanTask{
		ID:          fmt.Sprintf("%s-%d", currentDigest, time.Now().Unix()),
		Repository:  repo,
		Digest:      currentDigest,
		Tag:         tag,
		EnqueuedAt:  time.Now(),
		Attempts:    0,
		IsRescan:    isRescan,
		Tolerations: tolerations,
	}

	if err := w.taskQueue.Enqueue(ctx, task); err != nil {
		return fmt.Errorf("failed to enqueue task: %w", err)
	}

	return nil
}

// checkExpiringTolerations logs warnings for tolerations expiring soon
func (w *watcherImpl) checkExpiringTolerations(repo string, tolerations []regsync.CVEToleration) {
	now := time.Now()
	warningThreshold := 7 * 24 * time.Hour // 7 days

	for _, toleration := range tolerations {
		if toleration.ExpiresAt == nil {
			continue // No expiry, skip
		}

		timeUntilExpiry := toleration.ExpiresAt.Sub(now)
		if timeUntilExpiry > 0 && timeUntilExpiry <= warningThreshold {
			w.logger.Warn("CVE toleration expiring soon",
				"repo", repo,
				"cve_id", toleration.ID,
				"time_until_expiry", timeUntilExpiry.String(),
				"statement", toleration.Statement)
		}
	}
}
