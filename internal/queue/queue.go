package queue

import (
	"context"
	"sync"
	"time"

	"github.com/suppline/suppline/internal/errors"
	"github.com/suppline/suppline/internal/types"
)

// TaskQueue manages a queue of scan tasks for container images
type TaskQueue interface {
	// Enqueue adds a task to the queue
	Enqueue(ctx context.Context, task *ScanTask) error

	// Dequeue retrieves a task for processing (blocking)
	Dequeue(ctx context.Context) (*ScanTask, error)

	// Complete marks a task as successfully processed (for metrics/logging)
	Complete(ctx context.Context, taskID string) error

	// Fail marks a task as failed (for metrics/logging)
	Fail(ctx context.Context, taskID string, err error) error

	// GetQueueDepth returns current queue size
	GetQueueDepth(ctx context.Context) (int, error)

	// Close shuts down the queue gracefully
	Close() error
}

// ScanTask represents a container image scanning task
type ScanTask struct {
	ID          string
	Repository  string
	Digest      string
	Tag         string
	EnqueuedAt  time.Time
	Attempts    int
	IsRescan    bool
	Tolerations []types.CVEToleration // Using canonical type from internal/types
}

// InMemoryQueue implements TaskQueue using Go channels
type InMemoryQueue struct {
	tasks       chan *ScanTask
	pending     map[string]bool // Deduplication map: digest -> exists
	pendingMu   sync.RWMutex
	metrics     *QueueMetrics
	metricsMu   sync.RWMutex
	closed      bool
	closedMu    sync.RWMutex
	bufferSize  int
}

// QueueMetrics tracks queue operation statistics
type QueueMetrics struct {
	Enqueued  int64
	Dequeued  int64
	Completed int64
	Failed    int64
	Dropped   int64 // Dropped due to deduplication
}

// NewInMemoryQueue creates a new in-memory task queue
func NewInMemoryQueue(bufferSize int) *InMemoryQueue {
	return &InMemoryQueue{
		tasks:      make(chan *ScanTask, bufferSize),
		pending:    make(map[string]bool),
		metrics:    &QueueMetrics{},
		bufferSize: bufferSize,
	}
}

// Enqueue adds a task to the queue with deduplication
func (q *InMemoryQueue) Enqueue(ctx context.Context, task *ScanTask) error {
	q.closedMu.RLock()
	if q.closed {
		q.closedMu.RUnlock()
		return errors.NewPermanentf("queue is closed")
	}
	q.closedMu.RUnlock()

	if task == nil {
		return errors.NewPermanentf("task cannot be nil")
	}

	if task.Digest == "" {
		return errors.NewPermanentf("task digest cannot be empty")
	}

	// Check for duplicate
	q.pendingMu.Lock()
	if q.pending[task.Digest] {
		q.pendingMu.Unlock()
		q.incrementMetric("dropped")
		return nil // Silently drop duplicate
	}
	q.pending[task.Digest] = true
	q.pendingMu.Unlock()

	// Try to enqueue with context cancellation support
	select {
	case q.tasks <- task:
		q.incrementMetric("enqueued")
		return nil
	case <-ctx.Done():
		// Remove from pending if we couldn't enqueue
		q.pendingMu.Lock()
		delete(q.pending, task.Digest)
		q.pendingMu.Unlock()
		return ctx.Err()
	}
}

// Dequeue retrieves a task for processing (blocking)
func (q *InMemoryQueue) Dequeue(ctx context.Context) (*ScanTask, error) {
	q.closedMu.RLock()
	if q.closed {
		q.closedMu.RUnlock()
		return nil, errors.NewPermanentf("queue is closed")
	}
	q.closedMu.RUnlock()

	select {
	case task, ok := <-q.tasks:
		if !ok {
			return nil, errors.NewPermanentf("queue is closed")
		}

		// Remove from pending map when dequeued
		q.pendingMu.Lock()
		delete(q.pending, task.Digest)
		q.pendingMu.Unlock()

		q.incrementMetric("dequeued")
		return task, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// Complete marks a task as successfully processed
func (q *InMemoryQueue) Complete(ctx context.Context, taskID string) error {
	q.incrementMetric("completed")
	return nil
}

// Fail marks a task as failed
func (q *InMemoryQueue) Fail(ctx context.Context, taskID string, err error) error {
	q.incrementMetric("failed")
	return nil
}

// GetQueueDepth returns current queue size
func (q *InMemoryQueue) GetQueueDepth(ctx context.Context) (int, error) {
	return len(q.tasks), nil
}

// Close shuts down the queue gracefully
func (q *InMemoryQueue) Close() error {
	q.closedMu.Lock()
	defer q.closedMu.Unlock()

	if q.closed {
		return errors.NewPermanentf("queue already closed")
	}

	q.closed = true
	close(q.tasks)
	return nil
}

// GetMetrics returns a copy of current metrics
func (q *InMemoryQueue) GetMetrics() QueueMetrics {
	q.metricsMu.RLock()
	defer q.metricsMu.RUnlock()
	return *q.metrics
}

// incrementMetric safely increments a metric counter
func (q *InMemoryQueue) incrementMetric(metric string) {
	q.metricsMu.Lock()
	defer q.metricsMu.Unlock()

	switch metric {
	case "enqueued":
		q.metrics.Enqueued++
	case "dequeued":
		q.metrics.Dequeued++
	case "completed":
		q.metrics.Completed++
	case "failed":
		q.metrics.Failed++
	case "dropped":
		q.metrics.Dropped++
	}
}
