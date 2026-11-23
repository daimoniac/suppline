package queue

import (
	"context"
	"sync"
	"time"

	"github.com/daimoniac/suppline/internal/errors"
	"github.com/daimoniac/suppline/internal/observability"
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

	// HasPendingTask checks if there's a pending task for the given repository and digest.
	HasPendingTask(ctx context.Context, repository, digest string) (bool, error)

	// Close shuts down the queue gracefully
	Close() error
}

// TaskPriority defines task priority levels
type TaskPriority int

const (
	// PriorityUnspecified is the zero value and lets Enqueue derive the priority
	// from the task flags. Callers that care about ordering set one explicitly.
	PriorityUnspecified TaskPriority = iota
	PriorityNormal
	PriorityHigh // For rescans and first scans found by discovery
	// PriorityUrgent is for a caller waiting on the result, such as a CI scan
	// request or an operator rescan of one digest. It runs before discovery.
	PriorityUrgent
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
	IsFirstScan bool // True when image has never been scanned before
	Priority    TaskPriority
}

// InMemoryQueue implements TaskQueue using priority queues
type InMemoryQueue struct {
	urgentTasks       chan *ScanTask // For callers waiting on the result
	highPriorityTasks chan *ScanTask // For rescans and first scans
	normalTasks       chan *ScanTask // For regular scans
	// pending deduplicates queued tasks: repository+digest -> the highest
	// priority queued for it.
	pending    map[string]TaskPriority
	pendingMu  sync.RWMutex
	metrics    *QueueMetrics
	metricsMu  sync.RWMutex
	closed     bool
	closedMu   sync.RWMutex
	bufferSize int
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

	urgentBuffer := bufferSize / 10
	if urgentBuffer < 1 {
		urgentBuffer = 1
	}

	return &InMemoryQueue{
		urgentTasks:       make(chan *ScanTask, urgentBuffer),
		highPriorityTasks: make(chan *ScanTask, highPriorityBuffer),
		normalTasks:       make(chan *ScanTask, normalBuffer),
		pending:           make(map[string]TaskPriority),
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

	// An explicit priority from the caller wins. Only fall back to task-type
	// routing when the caller left it unspecified.
	// High priority for: rescans and first-time scans of new repositories
	if task.Priority == PriorityUnspecified {
		if task.IsRescan || task.IsFirstScan {
			task.Priority = PriorityHigh
		} else {
			task.Priority = PriorityNormal
		}
	}

	// Identical digests in different repositories are different admission targets.
	// Attestations are stored in the repository, so both must be queued.
	// A task already queued at the same or a higher priority covers this one.
	// A higher priority is queued anyway, so a waiting caller does not sit
	// behind the backlog; the earlier task then only repeats the scan later.
	key := taskPendingKey(task.Repository, task.Digest)
	q.pendingMu.Lock()
	previous, hadPrevious := q.pending[key]
	if hadPrevious && previous >= task.Priority {
		q.pendingMu.Unlock()
		q.incrementMetric("dropped")
		return nil
	}
	q.pending[key] = task.Priority
	q.pendingMu.Unlock()

	var targetQueue chan *ScanTask
	switch task.Priority {
	case PriorityUrgent:
		targetQueue = q.urgentTasks
	case PriorityHigh:
		targetQueue = q.highPriorityTasks
	default:
		targetQueue = q.normalTasks
	}

	select {
	case targetQueue <- task:
		q.incrementMetric("enqueued")
		observability.GetMetrics().QueueEnqueued.Inc()
		return nil
	case <-ctx.Done():
		q.pendingMu.Lock()
		if hadPrevious {
			q.pending[key] = previous
		} else {
			delete(q.pending, key)
		}
		q.pendingMu.Unlock()
		return ctx.Err()
	}
}

// Dequeue retrieves a task for processing (blocking).
// Urgent tasks come first, then high priority, then normal.
func (q *InMemoryQueue) Dequeue(ctx context.Context) (*ScanTask, error) {
	q.closedMu.RLock()
	if q.closed {
		q.closedMu.RUnlock()
		return nil, errors.NewPermanentf("queue is closed")
	}
	q.closedMu.RUnlock()

	for _, ch := range []chan *ScanTask{q.urgentTasks, q.highPriorityTasks} {
		select {
		case task, ok := <-ch:
			return q.taken(task, ok)
		default:
		}
	}

	select {
	case task, ok := <-q.urgentTasks:
		return q.taken(task, ok)
	case task, ok := <-q.highPriorityTasks:
		return q.taken(task, ok)
	case task, ok := <-q.normalTasks:
		return q.taken(task, ok)
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// taken finishes a receive: it clears the dedup entry the task held and
// counts the dequeue. A closed channel means the queue is closed.
func (q *InMemoryQueue) taken(task *ScanTask, ok bool) (*ScanTask, error) {
	if !ok {
		return nil, errors.NewPermanentf("queue is closed")
	}
	key := taskPendingKey(task.Repository, task.Digest)
	q.pendingMu.Lock()
	if queued, pending := q.pending[key]; pending && queued == task.Priority {
		delete(q.pending, key)
	}
	q.pendingMu.Unlock()
	q.incrementMetric("dequeued")
	observability.GetMetrics().QueueDequeued.Inc()
	return task, nil
}

// Complete marks a task as successfully processed
func (q *InMemoryQueue) Complete(ctx context.Context, taskID string) error {
	q.incrementMetric("completed")
	observability.GetMetrics().QueueCompleted.Inc()
	return nil
}

// Fail marks a task as failed
func (q *InMemoryQueue) Fail(ctx context.Context, taskID string, err error) error {
	q.incrementMetric("failed")
	observability.GetMetrics().QueueFailed.Inc()
	return nil
}

// GetQueueDepth returns current queue size
func (q *InMemoryQueue) GetQueueDepth(ctx context.Context) (int, error) {
	depth := len(q.urgentTasks) + len(q.highPriorityTasks) + len(q.normalTasks)
	observability.GetMetrics().QueueDepth.Set(float64(depth))
	return depth, nil
}

// HasPendingTask checks if there's a pending task for the given repository and digest.
func (q *InMemoryQueue) HasPendingTask(ctx context.Context, repository, digest string) (bool, error) {
	if repository == "" {
		return false, errors.NewPermanentf("repository cannot be empty")
	}
	if digest == "" {
		return false, errors.NewPermanentf("digest cannot be empty")
	}

	q.pendingMu.RLock()
	defer q.pendingMu.RUnlock()

	_, ok := q.pending[taskPendingKey(repository, digest)]
	return ok, nil
}

func taskPendingKey(repository, digest string) string {
	return repository + "\n" + digest
}

// Close shuts down the queue gracefully
func (q *InMemoryQueue) Close() error {
	q.closedMu.Lock()
	defer q.closedMu.Unlock()

	if q.closed {
		return errors.NewPermanentf("queue already closed")
	}

	q.closed = true
	close(q.urgentTasks)
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
