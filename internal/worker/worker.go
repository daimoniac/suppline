package worker

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/daimoniac/suppline/internal/attestation"
	"github.com/daimoniac/suppline/internal/config"
	"github.com/daimoniac/suppline/internal/errors"
	"github.com/daimoniac/suppline/internal/observability"
	"github.com/daimoniac/suppline/internal/policy"
	"github.com/daimoniac/suppline/internal/policy/catalog"
	"github.com/daimoniac/suppline/internal/queue"
	"github.com/daimoniac/suppline/internal/registry"
	"github.com/daimoniac/suppline/internal/scanner"
	"github.com/daimoniac/suppline/internal/statestore"
	"github.com/daimoniac/suppline/internal/types"
)

// PolicyFailureNotifier is told when a scan's CEL gate fails.
type PolicyFailureNotifier interface {
	NotifyPolicyFailure(ctx context.Context, notice PolicyFailureNotice)
}

// PolicyFailureNotice is one failed gate, with the findings that caused it.
type PolicyFailureNotice struct {
	Repository      string
	Digest          string
	Tag             string
	Findings        []types.PolicyFailureFinding
	Vulnerabilities []types.Vulnerability
}

// Worker defines the interface for processing scan tasks
type Worker interface {
	// Start begins processing tasks from the queue
	Start(ctx context.Context) error

	// ProcessTask executes the complete workflow for one image
	ProcessTask(ctx context.Context, task *queue.ScanTask) error
}

// Config contains configuration for the worker
type Config struct {
	RetryAttempts int
	RetryBackoff  time.Duration
	Concurrency   int // Number of concurrent workers
	// UrgentConcurrency workers take only urgent tasks, on top of Concurrency.
	UrgentConcurrency int
}

// urgentQueue is a queue that can hand out urgent tasks only.
type urgentQueue interface {
	DequeueUrgent(ctx context.Context) (*queue.ScanTask, error)
}

// DefaultConfig returns default worker configuration
func DefaultConfig() Config {
	return Config{
		RetryAttempts: 3,
		RetryBackoff:  10 * time.Second,
		Concurrency:   3, // Default to 3 concurrent workers
	}
}

// ImageWorker implements the Worker interface
type ImageWorker struct {
	queue           queue.TaskQueue
	scanner         scanner.Scanner
	policy          policy.PolicyEngine
	attestor        attestation.Attestor
	registry        registry.Client
	stateStore      statestore.StateStore
	config          Config
	logger          *slog.Logger
	wg              sync.WaitGroup
	currentConfig   config.Source
	policyCatalog   catalog.Catalog
	scaiGenerator   *attestation.SCAIGenerator
	pipeline        *Pipeline
	failureNotifier PolicyFailureNotifier
	scanObserver    ScanObserver
	taskObserver    TaskObserver
	malicious       MaliciousChecker
	maliciousGate   bool
	cooldownClock   CooldownClock
	heldDigests     func(repository string) []string
}

// MaliciousChecker matches an image's SBOM against known-malicious package
// advisories. It returns the check outcome and the image's language packages.
type MaliciousChecker interface {
	Check(sbom []byte) (*types.MaliciousCheck, []types.PackageRef, error)
}

// packageInventoryStore records an image's language packages so new
// malicious-package advisories can be matched without a rescan.
type packageInventoryStore interface {
	ReplacePackageInventory(ctx context.Context, digest string, packages []types.PackageRef) error
}

// SetMaliciousChecker enables the malicious-package check for every scan.
// block is whether a finding fails policy regardless of the expression.
func (w *ImageWorker) SetMaliciousChecker(checker MaliciousChecker, block bool) {
	if w != nil {
		w.malicious = checker
		w.maliciousGate = block
	}
}

// SetHeldDigests lists the digests the tag runway holds. A held digest of a
// new tag is scanned under a tag the registry does not have yet.
func (w *ImageWorker) SetHeldDigests(held func(repository string) []string) {
	if w != nil {
		w.heldDigests = held
	}
}

// CooldownClock tells when suppline first saw a digest upstream. A nil time
// means no Cooldown clock runs for the digest. The tag runway is the clock of
// mirrored repositories.
type CooldownClock interface {
	FirstSeen(ctx context.Context, repository, digest string) (*time.Time, error)
}

// SetCooldownClock replaces the artifact first-seen clock. Without one, a
// repository's cooldown counts from the artifact's first scan.
func (w *ImageWorker) SetCooldownClock(clock CooldownClock) {
	if w != nil {
		w.cooldownClock = clock
	}
}

// ScanObserver hears about each scan after it is persisted, whatever its
// outcome. The tag runway uses it to publish a held digest once attested.
type ScanObserver interface {
	Scanned(ctx context.Context, repository, digest string)
}

// SetScanObserver registers the observer of persisted scans.
func (w *ImageWorker) SetScanObserver(observer ScanObserver) {
	if w != nil {
		w.scanObserver = observer
	}
}

// TaskObserver hears about every task once it is finished, after its last
// retry, whatever happened: persisted, failed, or dropped. err is nil when
// the task succeeded. A scan request waiting on a digest uses it, because
// several failure paths never persist a scan record.
type TaskObserver interface {
	Finished(ctx context.Context, task *queue.ScanTask, err error)
}

// SetTaskObserver registers the observer of finished tasks.
func (w *ImageWorker) SetTaskObserver(observer TaskObserver) {
	if w != nil {
		w.taskObserver = observer
	}
}

// SetPolicyFailureNotifier receives CEL failures after they are persisted.
// The notifier must return quickly; triage work is queued, not run inline.
func (w *ImageWorker) SetPolicyFailureNotifier(notifier PolicyFailureNotifier) {
	if w != nil {
		w.failureNotifier = notifier
	}
}

// NewImageWorker creates a new worker instance
func NewImageWorker(
	queue queue.TaskQueue,
	scanner scanner.Scanner,
	policy policy.PolicyEngine,
	attestor attestation.Attestor,
	registry registry.Client,
	stateStore statestore.StateStore,
	config Config,
	logger *slog.Logger,
	regsyncCfg *config.RegsyncConfig,
) *ImageWorker {
	running := catalog.NewConfigCatalog(regsyncCfg)
	currentConfig := running.Current
	if regsyncCfg == nil {
		currentConfig = nil
	}
	return NewImageWorkerWithCatalog(
		queue, scanner, policy, attestor, registry, stateStore, config, logger,
		currentConfig, running,
	)
}

// NewImageWorkerWithCatalog creates a worker using a shared repository-policy catalog.
func NewImageWorkerWithCatalog(
	queue queue.TaskQueue,
	scanner scanner.Scanner,
	policy policy.PolicyEngine,
	attestor attestation.Attestor,
	registry registry.Client,
	stateStore statestore.StateStore,
	config Config,
	logger *slog.Logger,
	currentConfig config.Source,
	policyCatalog catalog.Catalog,
) *ImageWorker {
	if logger == nil {
		logger = slog.Default()
	}

	var scaiGenerator *attestation.SCAIGenerator
	if currentConfig != nil {
		scaiGenerator = attestation.NewSCAIGeneratorWithCatalog(currentConfig, policyCatalog, logger)
	}

	worker := &ImageWorker{
		queue:         queue,
		scanner:       scanner,
		policy:        policy,
		attestor:      attestor,
		registry:      registry,
		stateStore:    stateStore,
		config:        config,
		logger:        logger,
		currentConfig: currentConfig,
		policyCatalog: policyCatalog,
		scaiGenerator: scaiGenerator,
	}

	// Initialize pipeline
	worker.pipeline = NewPipeline(worker, logger)

	return worker
}

// Start begins processing tasks from the queue
func (w *ImageWorker) Start(ctx context.Context) error {
	concurrency := w.config.Concurrency
	if concurrency <= 0 {
		concurrency = 1
	}

	urgent := max(w.config.UrgentConcurrency, 0)
	urgentSource, canReserve := w.queue.(urgentQueue)
	if !canReserve {
		urgent = 0
	}

	w.logger.Info("worker starting", "concurrency", concurrency, "urgent_concurrency", urgent)

	// Register metrics collectors (once across all worker instances)
	observability.RegisterConfigCollectorWithCatalog(w.policyCatalog, w.stateStore, w.logger)
	observability.RegisterDatabaseCollector(w.stateStore, w.logger)

	// Create a cancellable context for the worker
	workerCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Start multiple processing loops for concurrent processing
	for i := 0; i < concurrency; i++ {
		w.wg.Add(1)
		go func(workerID int) {
			defer w.wg.Done()
			w.processLoop(workerCtx, workerID, w.queue.Dequeue)
		}(i)
	}
	// Reserved workers: a CI job waiting on its scan never waits for a
	// discovery scan or rescan to finish first.
	for i := 0; i < urgent; i++ {
		w.wg.Add(1)
		go func(workerID int) {
			defer w.wg.Done()
			w.processLoop(workerCtx, workerID, urgentSource.DequeueUrgent)
		}(concurrency + i)
	}

	// Wait for context cancellation
	<-workerCtx.Done()

	w.logger.Info("worker shutting down, waiting for in-flight tasks to complete")

	// Wait for in-flight tasks to complete with timeout
	done := make(chan struct{})
	go func() {
		w.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		w.logger.Info("worker shutdown complete")
		return nil
	case <-time.After(30 * time.Second):
		w.logger.Warn("worker shutdown timeout, some tasks may not have completed")
		return fmt.Errorf("shutdown timeout")
	}
}

// processLoop is the main task processing loop
func (w *ImageWorker) processLoop(ctx context.Context, workerID int, dequeue func(context.Context) (*queue.ScanTask, error)) {
	w.logger.Info("worker processing loop started", "worker_id", workerID)

	for {
		select {
		case <-ctx.Done():
			w.logger.Info("worker processing loop stopping", "worker_id", workerID)
			return
		default:
			// Dequeue a task (blocking with context)
			task, err := dequeue(ctx)
			if err != nil {
				if ctx.Err() != nil {
					// Context cancelled, exit gracefully
					w.logger.Info("worker dequeue cancelled", "worker_id", workerID, "error", err)
					return
				}
				w.logger.Error("failed to dequeue task", "worker_id", workerID, "error", err)
				// Brief sleep to avoid tight loop on persistent errors
				time.Sleep(time.Second)
				continue
			}

			// Process the task
			w.logger.Info("processing task",
				"worker_id", workerID,
				"task_id", task.ID,
				"digest", task.Digest,
				"repository", task.Repository,
				"tag", task.Tag,
				"is_rescan", task.IsRescan)

			err = w.ProcessTask(ctx, task)
			if w.taskObserver != nil {
				w.taskObserver.Finished(ctx, task, err)
			}
			if err != nil {
				// Log once here with full context
				w.logger.Error("task processing failed",
					"worker_id", workerID,
					"task_id", task.ID,
					"digest", task.Digest,
					"repository", task.Repository,
					"error", err)
				metrics := observability.GetMetrics()
				metrics.WorkerErrors.Inc()
				_ = w.queue.Fail(ctx, task.ID, err)
			} else {
				w.logger.Debug("task processing completed",
					"worker_id", workerID,
					"task_id", task.ID,
					"digest", task.Digest,
					"repository", task.Repository)
				metrics := observability.GetMetrics()
				metrics.WorkerTasksProcessed.Inc()
				_ = w.queue.Complete(ctx, task.ID)
			}
		}
	}
}

// ErrorHandlerAction determines what action to take for a given error
type ErrorHandlerAction int

const (
	// ActionRetry indicates the error is transient and should be retried
	ActionRetry ErrorHandlerAction = iota
	// ActionFail indicates the error is permanent and should not be retried
	ActionFail
	// ActionSpecialHandling indicates the error requires special handling (e.g., manifest not found)
	ActionSpecialHandling
)

// handleTaskError classifies an error and determines the appropriate action.
// This centralizes error classification logic and reduces cognitive load in the retry loop.
func (w *ImageWorker) handleTaskError(err error, attempt int, task *queue.ScanTask) (ErrorHandlerAction, time.Duration) {
	if err == nil {
		return ActionRetry, 0
	}

	// Use single-pass error classification
	errorClass := errors.ClassifyError(err)

	switch errorClass {
	case errors.ErrorClassManifestNotFound:
		// Manifest not found is a special case that needs cleanup but still fails
		w.logger.Info("manifest not found error during task processing",
			"task_id", task.ID,
			"digest", task.Digest)
		return ActionSpecialHandling, 0

	case errors.ErrorClassPermanent:
		// Permanent errors should not be retried
		return ActionFail, 0

	case errors.ErrorClassTransient:
		// Transient errors should be retried with exponential backoff
		if attempt >= w.config.RetryAttempts {
			// No more retries available
			return ActionFail, 0
		}

		// Calculate backoff delay with exponential backoff
		backoff := w.config.RetryBackoff * time.Duration(attempt)
		w.logger.Warn("transient error, retrying",
			"task_id", task.ID,
			"digest", task.Digest,
			"attempt", attempt,
			"max_attempts", w.config.RetryAttempts,
			"backoff", backoff,
			"error", err)

		return ActionRetry, backoff

	case errors.ErrorClassUnknown:
		// Unknown errors default to permanent (safe default - don't retry)
		return ActionFail, 0

	default:
		// Unexpected error class - treat as permanent
		return ActionFail, 0
	}
}

// ProcessTask executes the complete workflow for one image with retry logic
func (w *ImageWorker) ProcessTask(ctx context.Context, task *queue.ScanTask) error {
	if task == nil {
		return errors.NewPermanentf("task is nil")
	}

	// Execute the workflow with retry logic
	var lastErr error
	for attempt := 1; attempt <= w.config.RetryAttempts; attempt++ {
		err := w.pipeline.Execute(ctx, task)
		if err == nil {
			// Success
			return nil
		}

		lastErr = err

		// Handle the error and determine what action to take
		action, backoff := w.handleTaskError(err, attempt, task)

		switch action {
		case ActionFail:
			// Permanent error or retries exhausted - don't retry
			return err

		case ActionSpecialHandling:
			// Special case like manifest not found - don't retry but return the error
			return err

		case ActionRetry:
			// Transient error - retry with backoff
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(backoff):
				// Continue to next attempt
			}
		}
	}

	// All retries exhausted - return as permanent error
	return errors.NewPermanentf("max retries exceeded: %w", lastErr)
}

// runningConfig returns the configuration snapshot for one decision, or nil.
func (w *ImageWorker) runningConfig() *config.RegsyncConfig {
	if w.currentConfig == nil {
		return nil
	}
	return w.currentConfig()
}
