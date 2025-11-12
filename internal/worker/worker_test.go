package worker

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/suppline/suppline/internal/queue"
)

// mockQueue implements queue.TaskQueue for testing
type mockQueue struct {
	tasks       chan *queue.ScanTask
	dequeueErr  error
	completeErr error
	failErr     error
	closed      bool
}

func newMockQueue(bufferSize int) *mockQueue {
	return &mockQueue{
		tasks: make(chan *queue.ScanTask, bufferSize),
	}
}

func (m *mockQueue) Enqueue(ctx context.Context, task *queue.ScanTask) error {
	if m.closed {
		return errors.New("queue closed")
	}
	select {
	case m.tasks <- task:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (m *mockQueue) Dequeue(ctx context.Context) (*queue.ScanTask, error) {
	if m.dequeueErr != nil {
		return nil, m.dequeueErr
	}
	select {
	case task, ok := <-m.tasks:
		if !ok {
			return nil, errors.New("queue closed")
		}
		return task, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (m *mockQueue) Complete(ctx context.Context, taskID string) error {
	return m.completeErr
}

func (m *mockQueue) Fail(ctx context.Context, taskID string, err error) error {
	return m.failErr
}

func (m *mockQueue) GetQueueDepth(ctx context.Context) (int, error) {
	return len(m.tasks), nil
}

func (m *mockQueue) Close() error {
	if m.closed {
		return errors.New("already closed")
	}
	m.closed = true
	close(m.tasks)
	return nil
}

func TestNewImageWorker(t *testing.T) {
	mockQ := newMockQueue(10)
	logger := slog.Default()
	config := DefaultConfig()

	worker := NewImageWorker(mockQ, nil, nil, nil, nil, nil, config, logger, nil)

	if worker == nil {
		t.Fatal("expected worker to be created")
	}

	if worker.queue != mockQ {
		t.Error("expected queue to be set")
	}

	if worker.logger == nil {
		t.Error("expected logger to be set")
	}

	if worker.config.RetryAttempts != config.RetryAttempts {
		t.Errorf("expected retry attempts %d, got %d", config.RetryAttempts, worker.config.RetryAttempts)
	}
}

func TestWorkerStart_GracefulShutdown(t *testing.T) {
	mockQ := newMockQueue(10)
	logger := slog.Default()
	config := DefaultConfig()

	worker := NewImageWorker(mockQ, nil, nil, nil, nil, nil, config, logger, nil)

	ctx, cancel := context.WithCancel(context.Background())

	// Start worker in goroutine
	errChan := make(chan error, 1)
	go func() {
		errChan <- worker.Start(ctx)
	}()

	// Give worker time to start
	time.Sleep(100 * time.Millisecond)

	// Cancel context to trigger shutdown
	cancel()

	// Wait for worker to stop
	select {
	case err := <-errChan:
		if err != nil {
			t.Errorf("expected no error on graceful shutdown, got: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("worker did not shut down within timeout")
	}
}

func TestWorkerStart_ProcessesTask(t *testing.T) {
	mockQ := newMockQueue(10)
	logger := slog.Default()
	config := DefaultConfig()

	worker := NewImageWorker(mockQ, nil, nil, nil, nil, nil, config, logger, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	// Enqueue a test task
	testTask := &queue.ScanTask{
		ID:         "test-1",
		Repository: "test/repo",
		Digest:     "sha256:abc123",
		Tag:        "latest",
		EnqueuedAt: time.Now(),
	}

	if err := mockQ.Enqueue(ctx, testTask); err != nil {
		t.Fatalf("failed to enqueue task: %v", err)
	}

	// Start worker in goroutine
	errChan := make(chan error, 1)
	go func() {
		errChan <- worker.Start(ctx)
	}()

	// Wait for context timeout or completion
	select {
	case <-errChan:
		// Worker stopped
	case <-ctx.Done():
		// Timeout - this is expected since we're testing processing
	}

	// Verify queue is empty (task was dequeued)
	// Note: Task will fail to process due to nil dependencies, but it should be dequeued
	depth, err := mockQ.GetQueueDepth(context.Background())
	if err != nil {
		t.Fatalf("failed to get queue depth: %v", err)
	}

	if depth != 0 {
		t.Errorf("expected queue to be empty after dequeue, got depth: %d", depth)
	}
}

func TestWorkerStart_ContextCancellation(t *testing.T) {
	mockQ := newMockQueue(10)
	logger := slog.Default()
	config := DefaultConfig()

	worker := NewImageWorker(mockQ, nil, nil, nil, nil, nil, config, logger, nil)

	ctx, cancel := context.WithCancel(context.Background())

	// Start worker
	errChan := make(chan error, 1)
	go func() {
		errChan <- worker.Start(ctx)
	}()

	// Immediately cancel
	cancel()

	// Worker should stop quickly
	select {
	case err := <-errChan:
		if err != nil {
			t.Errorf("expected no error, got: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("worker did not respond to context cancellation")
	}
}

func TestWorkerStart_DequeueError(t *testing.T) {
	mockQ := newMockQueue(10)
	mockQ.dequeueErr = errors.New("dequeue error")

	logger := slog.Default()
	config := DefaultConfig()

	worker := NewImageWorker(mockQ, nil, nil, nil, nil, nil, config, logger, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Start worker
	errChan := make(chan error, 1)
	go func() {
		errChan <- worker.Start(ctx)
	}()

	// Wait for timeout
	<-ctx.Done()

	// Worker should handle dequeue errors gracefully and continue
	// No assertion needed - just verify it doesn't panic
}

func TestProcessTask_NilTask(t *testing.T) {
	mockQ := newMockQueue(10)
	logger := slog.Default()
	config := DefaultConfig()

	worker := NewImageWorker(mockQ, nil, nil, nil, nil, nil, config, logger, nil)

	err := worker.ProcessTask(context.Background(), nil)
	if err == nil {
		t.Error("expected error for nil task")
	}

	if err.Error() != "task is nil" {
		t.Errorf("expected 'task is nil' error, got: %v", err)
	}
}

func TestProcessTask_WithNilDependencies(t *testing.T) {
	mockQ := newMockQueue(10)
	logger := slog.Default()
	config := DefaultConfig()

	// Create worker with nil dependencies to test error handling
	worker := NewImageWorker(mockQ, nil, nil, nil, nil, nil, config, logger, nil)

	task := &queue.ScanTask{
		ID:         "test-1",
		Repository: "test/repo",
		Digest:     "sha256:abc123",
		Tag:        "latest",
		EnqueuedAt: time.Now(),
	}

	err := worker.ProcessTask(context.Background(), task)
	if err == nil {
		t.Error("expected error when dependencies are nil")
	}
}

func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()

	if config.RetryAttempts != 3 {
		t.Errorf("expected retry attempts 3, got %d", config.RetryAttempts)
	}

	if config.RetryBackoff != 10*time.Second {
		t.Errorf("expected retry backoff 10s, got %v", config.RetryBackoff)
	}
}
