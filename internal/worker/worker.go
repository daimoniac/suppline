package worker

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/suppline/suppline/internal/attestation"
	"github.com/suppline/suppline/internal/config"
	"github.com/suppline/suppline/internal/policy"
	"github.com/suppline/suppline/internal/queue"
	"github.com/suppline/suppline/internal/registry"
	"github.com/suppline/suppline/internal/scanner"
	"github.com/suppline/suppline/internal/statestore"
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
}

// DefaultConfig returns default worker configuration
func DefaultConfig() Config {
	return Config{
		RetryAttempts: 3,
		RetryBackoff:  10 * time.Second,
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
	w.logger.Info("worker starting")

	// Create a cancellable context for the worker
	workerCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Start the main processing loop
	w.wg.Add(1)
	go func() {
		defer w.wg.Done()
		w.processLoop(workerCtx)
	}()

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
func (w *ImageWorker) processLoop(ctx context.Context) {
	w.logger.Info("worker processing loop started")

	for {
		select {
		case <-ctx.Done():
			w.logger.Info("worker processing loop stopping")
			return
		default:
			// Dequeue a task (blocking with context)
			task, err := w.queue.Dequeue(ctx)
			if err != nil {
				if ctx.Err() != nil {
					// Context cancelled, exit gracefully
					w.logger.Info("worker dequeue cancelled", "error", err)
					return
				}
				w.logger.Error("failed to dequeue task", "error", err)
				// Brief sleep to avoid tight loop on persistent errors
				time.Sleep(time.Second)
				continue
			}

			// Process the task
			w.logger.Info("processing task",
				"task_id", task.ID,
				"digest", task.Digest,
				"repository", task.Repository,
				"tag", task.Tag,
				"is_rescan", task.IsRescan)

			if err := w.ProcessTask(ctx, task); err != nil {
				w.logger.Error("task processing failed",
					"task_id", task.ID,
					"digest", task.Digest,
					"repository", task.Repository,
					"error", err)
				_ = w.queue.Fail(ctx, task.ID, err)
			} else {
				w.logger.Info("task processing completed",
					"task_id", task.ID,
					"digest", task.Digest,
					"repository", task.Repository)
				_ = w.queue.Complete(ctx, task.ID)
			}
		}
	}
}

// ProcessTask executes the complete workflow for one image with retry logic
func (w *ImageWorker) ProcessTask(ctx context.Context, task *queue.ScanTask) error {
	if task == nil {
		return fmt.Errorf("task is nil")
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

		// Check if error is transient and should be retried
		if !isTransientError(err) {
			w.logger.Error("permanent error, not retrying",
				"task_id", task.ID,
				"digest", task.Digest,
				"error", err)
			return err
		}

		// Don't retry if this was the last attempt
		if attempt >= w.config.RetryAttempts {
			break
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

		// Wait before retrying
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff):
			// Continue to next attempt
		}
	}

	// All retries exhausted
	w.logger.Error("all retry attempts exhausted",
		"task_id", task.ID,
		"digest", task.Digest,
		"attempts", w.config.RetryAttempts,
		"error", lastErr)
	return fmt.Errorf("max retries exceeded: %w", lastErr)
}
