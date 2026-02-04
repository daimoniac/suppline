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
	"github.com/daimoniac/suppline/internal/queue"
	"github.com/daimoniac/suppline/internal/registry"
	"github.com/daimoniac/suppline/internal/scanner"
	"github.com/daimoniac/suppline/internal/statestore"
)

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
	queue         queue.TaskQueue
	scanner       scanner.Scanner
	policy        policy.PolicyEngine
	attestor      attestation.Attestor
	registry      registry.Client
	stateStore    statestore.StateStore
	config        Config
	logger        *slog.Logger
	wg            sync.WaitGroup
	regsyncCfg    *config.RegsyncConfig
	scaiGenerator *attestation.SCAIGenerator
	pipeline      *Pipeline
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
	if logger == nil {
		logger = slog.Default()
	}

	var scaiGenerator *attestation.SCAIGenerator
	if regsyncCfg != nil {
		scaiGenerator = attestation.NewSCAIGenerator(regsyncCfg, logger)
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
		regsyncCfg:    regsyncCfg,
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

	w.logger.Info("worker starting", "concurrency", concurrency)

	// Register database metrics collector (once across all worker instances)
	observability.RegisterDatabaseCollector(w.stateStore, w.regsyncCfg, w.logger)

	// Create a cancellable context for the worker
	workerCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Start multiple processing loops for concurrent processing
	for i := 0; i < concurrency; i++ {
		w.wg.Add(1)
		go func(workerID int) {
			defer w.wg.Done()
			w.processLoop(workerCtx, workerID)
		}(i)
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
func (w *ImageWorker) processLoop(ctx context.Context, workerID int) {
	w.logger.Info("worker processing loop started", "worker_id", workerID)

	for {
		select {
		case <-ctx.Done():
			w.logger.Info("worker processing loop stopping", "worker_id", workerID)
			return
		default:
			// Dequeue a task (blocking with context)
			task, err := w.queue.Dequeue(ctx)
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

			if err := w.ProcessTask(ctx, task); err != nil {
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
				w.logger.Info("task processing completed",
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
