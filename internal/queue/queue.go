package queue

import (
	"context"
	"sync"
	"time"

	"github.com/daimoniac/suppline/internal/errors"
	"github.com/daimoniac/suppline/internal/types"
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

	// HasPendingTask checks if there's a pending task for the given digest
	HasPendingTask(ctx context.Context, digest string) (bool, error)

	// Close shuts down the queue gracefully
	Close() error
}

// TaskPriority defines task priority levels
type TaskPriority int

const (
	PriorityNormal TaskPriority = iota
	PriorityHigh   // For rescans and urgent tasks
)

// ScanTask represents a container image scanning task
type ScanTask struct {
	ID          string
	Repository  string
	Digest      string
	Tag         string
	EnqueuedAt  time.Time
	Attempts    int
	IsRescan    bool
	Priority    TaskPriority
	Tolerations []types.CVEToleration // Using canonical type from internal/types
}

// InMemoryQueue implements TaskQueue using priority queues
type InMemoryQueue struct {
	highPriorityTasks chan *ScanTask // For rescans and urgent tasks
	normalTasks       chan *ScanTask // For regular scans
	pending           map[string]bool // Deduplication map: digest -> exists
	pendingMu         sync.RWMutex
	metrics           *QueueMetrics
	metricsMu         sync.RWMutex
	closed            bool
	closedMu          sync.RWMutex
	bufferSize        int
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
	// Ensure minimum buffer size of 1 for each queue
	highPriorityBuffer := bufferSize / 2
	normalBuffer := bufferSize / 2
	if highPriorityBuffer < 1 {
		highPriorityBuffer = 1
	}
	if normalBuffer < 1 {
		normalBuffer = 1
	}
	
	return &InMemoryQueue{
		highPriorityTasks: make(chan *ScanTask, highPriorityBuffer),
		normalTasks:       make(chan *ScanTask, normalBuffer),
		pending:           make(map[string]bool),
		metrics:           &QueueMetrics{},
		bufferSize:        bufferSize,
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

	q.pendingMu.Lock()
	if q.pending[task.Digest] {
		q.pendingMu.Unlock()
		q.incrementMetric("dropped")
		return nil
	}
	q.pending[task.Digest] = true
	q.pendingMu.Unlock()

	// Set priority based on task type
	if task.IsRescan {
		task.Priority = PriorityHigh
	} else {
		task.Priority = PriorityNormal
	}

	// Enqueue to appropriate priority queue
	var targetQueue chan *ScanTask
	if task.Priority == PriorityHigh {
		targetQueue = q.highPriorityTasks
	} else {
		targetQueue = q.normalTasks
	}

	select {
	case targetQueue <- task:
		q.incrementMetric("enqueued")
		return nil
	case <-ctx.Done():
		q.pendingMu.Lock()
		delete(q.pending, task.Digest)
		q.pendingMu.Unlock()
		return ctx.Err()
	}
}

// Dequeue retrieves a task for processing (blocking)
// High priority tasks are always processed first
func (q *InMemoryQueue) Dequeue(ctx context.Context) (*ScanTask, error) {
	q.closedMu.RLock()
	if q.closed {
		q.closedMu.RUnlock()
		return nil, errors.NewPermanentf("queue is closed")
	}
	q.closedMu.RUnlock()

	for {
		// Always check high priority queue first
		select {
		case task, ok := <-q.highPriorityTasks:
			if !ok {
				// High priority channel closed, fall through to normal tasks
				break
			}
			q.pendingMu.Lock()
			delete(q.pending, task.Digest)
			q.pendingMu.Unlock()
			q.incrementMetric("dequeued")
			return task, nil
		default:
			// No high priority tasks available, check normal tasks
		}

		// If no high priority tasks, check normal tasks
		select {
		case task, ok := <-q.highPriorityTasks:
			if !ok {
				// High priority channel closed, continue to normal tasks
			} else {
				q.pendingMu.Lock()
				delete(q.pending, task.Digest)
				q.pendingMu.Unlock()
				q.incrementMetric("dequeued")
				return task, nil
			}
		case task, ok := <-q.normalTasks:
			if !ok {
				return nil, errors.NewPermanentf("queue is closed")
			}
			q.pendingMu.Lock()
			delete(q.pending, task.Digest)
			q.pendingMu.Unlock()
			q.incrementMetric("dequeued")
			return task, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
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
	return len(q.highPriorityTasks) + len(q.normalTasks), nil
}

// HasPendingTask checks if there's a pending task for the given digest
func (q *InMemoryQueue) HasPendingTask(ctx context.Context, digest string) (bool, error) {
	if digest == "" {
		return false, errors.NewPermanentf("digest cannot be empty")
	}

	q.pendingMu.RLock()
	defer q.pendingMu.RUnlock()
	
	return q.pending[digest], nil
}

// Close shuts down the queue gracefully
func (q *InMemoryQueue) Close() error {
	q.closedMu.Lock()
	defer q.closedMu.Unlock()

	if q.closed {
		return errors.NewPermanentf("queue already closed")
	}

	q.closed = true
	close(q.highPriorityTasks)
	close(q.normalTasks)
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
