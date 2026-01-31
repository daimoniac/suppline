package queue

import (
	"context"
	"testing"
	"time"

	"github.com/daimoniac/suppline/internal/types"
)

func TestNewInMemoryQueue(t *testing.T) {
	q := NewInMemoryQueue(100)
	if q == nil {
		t.Fatal("expected non-nil queue")
	}

	if q.bufferSize != 100 {
		t.Errorf("expected buffer size 100, got %d", q.bufferSize)
	}

	if q.highPriorityTasks == nil {
		t.Error("expected non-nil high priority tasks channel")
	}

	if q.normalTasks == nil {
		t.Error("expected non-nil normal tasks channel")
	}

	if q.pending == nil {
		t.Error("expected non-nil pending map")
	}

	if q.metrics == nil {
		t.Error("expected non-nil metrics")
	}
}

func TestEnqueueDequeue(t *testing.T) {
	q := NewInMemoryQueue(10)
	defer q.Close()

	ctx := context.Background()
	task := &ScanTask{
		ID:         "task-1",
		Repository: "test/repo",
		Digest:     "sha256:abc123",
		Tag:        "v1.0.0",
		EnqueuedAt: time.Now(),
	}

	// Enqueue task
	err := q.Enqueue(ctx, task)
	if err != nil {
		t.Fatalf("failed to enqueue task: %v", err)
	}

	// Check metrics
	metrics := q.GetMetrics()
	if metrics.Enqueued != 1 {
		t.Errorf("expected 1 enqueued, got %d", metrics.Enqueued)
	}

	// Dequeue task
	dequeued, err := q.Dequeue(ctx)
	if err != nil {
		t.Fatalf("failed to dequeue task: %v", err)
	}

	if dequeued.ID != task.ID {
		t.Errorf("expected task ID %s, got %s", task.ID, dequeued.ID)
	}

	if dequeued.Digest != task.Digest {
		t.Errorf("expected digest %s, got %s", task.Digest, dequeued.Digest)
	}

	// Check metrics
	metrics = q.GetMetrics()
	if metrics.Dequeued != 1 {
		t.Errorf("expected 1 dequeued, got %d", metrics.Dequeued)
	}
}

func TestDeduplication(t *testing.T) {
	q := NewInMemoryQueue(10)
	defer q.Close()

	ctx := context.Background()
	digest := "sha256:duplicate"

	task1 := &ScanTask{
		ID:         "task-1",
		Repository: "test/repo",
		Digest:     digest,
		Tag:        "v1.0.0",
		EnqueuedAt: time.Now(),
	}

	task2 := &ScanTask{
		ID:         "task-2",
		Repository: "test/repo",
		Digest:     digest,
		Tag:        "v1.0.1",
		EnqueuedAt: time.Now(),
	}

	// Enqueue first task
	err := q.Enqueue(ctx, task1)
	if err != nil {
		t.Fatalf("failed to enqueue first task: %v", err)
	}

	// Enqueue duplicate task (should be dropped)
	err = q.Enqueue(ctx, task2)
	if err != nil {
		t.Fatalf("failed to enqueue duplicate task: %v", err)
	}

	// Check metrics
	metrics := q.GetMetrics()
	if metrics.Enqueued != 1 {
		t.Errorf("expected 1 enqueued, got %d", metrics.Enqueued)
	}
	if metrics.Dropped != 1 {
		t.Errorf("expected 1 dropped, got %d", metrics.Dropped)
	}

	// Should only dequeue one task
	dequeued, err := q.Dequeue(ctx)
	if err != nil {
		t.Fatalf("failed to dequeue task: %v", err)
	}

	if dequeued.ID != task1.ID {
		t.Errorf("expected first task ID %s, got %s", task1.ID, dequeued.ID)
	}

	// Queue should be empty now
	depth, _ := q.GetQueueDepth(ctx)
	if depth != 0 {
		t.Errorf("expected queue depth 0, got %d", depth)
	}
}

func TestDeduplicationAfterDequeue(t *testing.T) {
	q := NewInMemoryQueue(10)
	defer q.Close()

	ctx := context.Background()
	digest := "sha256:requeue"

	task1 := &ScanTask{
		ID:         "task-1",
		Repository: "test/repo",
		Digest:     digest,
		Tag:        "v1.0.0",
		EnqueuedAt: time.Now(),
	}

	// Enqueue and dequeue
	_ = q.Enqueue(ctx, task1)
	_, _ = q.Dequeue(ctx)

	// Should be able to enqueue again after dequeue
	task2 := &ScanTask{
		ID:         "task-2",
		Repository: "test/repo",
		Digest:     digest,
		Tag:        "v1.0.1",
		EnqueuedAt: time.Now(),
	}

	err := q.Enqueue(ctx, task2)
	if err != nil {
		t.Fatalf("failed to re-enqueue task: %v", err)
	}

	metrics := q.GetMetrics()
	if metrics.Enqueued != 2 {
		t.Errorf("expected 2 enqueued, got %d", metrics.Enqueued)
	}
	if metrics.Dropped != 0 {
		t.Errorf("expected 0 dropped, got %d", metrics.Dropped)
	}
}

func TestGetQueueDepth(t *testing.T) {
	q := NewInMemoryQueue(10)
	defer q.Close()

	ctx := context.Background()

	// Empty queue
	depth, err := q.GetQueueDepth(ctx)
	if err != nil {
		t.Fatalf("failed to get queue depth: %v", err)
	}
	if depth != 0 {
		t.Errorf("expected depth 0, got %d", depth)
	}

	// Add tasks
	for i := 0; i < 5; i++ {
		task := &ScanTask{
			ID:         string(rune(i)),
			Repository: "test/repo",
			Digest:     string(rune(i)),
			EnqueuedAt: time.Now(),
		}
		_ = q.Enqueue(ctx, task)
	}

	depth, err = q.GetQueueDepth(ctx)
	if err != nil {
		t.Fatalf("failed to get queue depth: %v", err)
	}
	if depth != 5 {
		t.Errorf("expected depth 5, got %d", depth)
	}
}

func TestCompleteAndFail(t *testing.T) {
	q := NewInMemoryQueue(10)
	defer q.Close()

	ctx := context.Background()

	// Complete
	err := q.Complete(ctx, "task-1")
	if err != nil {
		t.Fatalf("failed to complete task: %v", err)
	}

	metrics := q.GetMetrics()
	if metrics.Completed != 1 {
		t.Errorf("expected 1 completed, got %d", metrics.Completed)
	}

	// Fail
	err = q.Fail(ctx, "task-2", nil)
	if err != nil {
		t.Fatalf("failed to fail task: %v", err)
	}

	metrics = q.GetMetrics()
	if metrics.Failed != 1 {
		t.Errorf("expected 1 failed, got %d", metrics.Failed)
	}
}

func TestContextCancellation(t *testing.T) {
	q := NewInMemoryQueue(1)
	defer q.Close()

	// Fill the queue
	ctx := context.Background()
	task1 := &ScanTask{
		ID:         "task-1",
		Repository: "test/repo",
		Digest:     "sha256:first",
		EnqueuedAt: time.Now(),
	}
	_ = q.Enqueue(ctx, task1)

	// Try to enqueue with cancelled context
	cancelCtx, cancel := context.WithCancel(context.Background())
	cancel()

	task2 := &ScanTask{
		ID:         "task-2",
		Repository: "test/repo",
		Digest:     "sha256:second",
		EnqueuedAt: time.Now(),
	}

	err := q.Enqueue(cancelCtx, task2)
	if err != context.Canceled {
		t.Errorf("expected context.Canceled error, got %v", err)
	}

	// Verify task2 was not added to pending map
	q.pendingMu.RLock()
	if q.pending["sha256:second"] {
		t.Error("expected task2 to not be in pending map")
	}
	q.pendingMu.RUnlock()
}

func TestDequeueWithTimeout(t *testing.T) {
	q := NewInMemoryQueue(10)
	defer q.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	// Try to dequeue from empty queue with timeout
	_, err := q.Dequeue(ctx)
	if err != context.DeadlineExceeded {
		t.Errorf("expected context.DeadlineExceeded, got %v", err)
	}
}

func TestCloseQueue(t *testing.T) {
	q := NewInMemoryQueue(10)

	ctx := context.Background()
	task := &ScanTask{
		ID:         "task-1",
		Repository: "test/repo",
		Digest:     "sha256:test",
		EnqueuedAt: time.Now(),
	}

	// Enqueue before close
	err := q.Enqueue(ctx, task)
	if err != nil {
		t.Fatalf("failed to enqueue: %v", err)
	}

	// Close queue
	err = q.Close()
	if err != nil {
		t.Fatalf("failed to close queue: %v", err)
	}

	// Try to enqueue after close
	err = q.Enqueue(ctx, task)
	if err == nil {
		t.Error("expected error when enqueuing to closed queue")
	}

	// Try to dequeue after close
	_, err = q.Dequeue(ctx)
	if err == nil {
		t.Error("expected error when dequeuing from closed queue")
	}

	// Double close should error
	err = q.Close()
	if err == nil {
		t.Error("expected error on double close")
	}
}

func TestEnqueueNilTask(t *testing.T) {
	q := NewInMemoryQueue(10)
	defer q.Close()

	ctx := context.Background()
	err := q.Enqueue(ctx, nil)
	if err == nil {
		t.Error("expected error when enqueuing nil task")
	}
}

func TestEnqueueEmptyDigest(t *testing.T) {
	q := NewInMemoryQueue(10)
	defer q.Close()

	ctx := context.Background()
	task := &ScanTask{
		ID:         "task-1",
		Repository: "test/repo",
		Digest:     "",
		EnqueuedAt: time.Now(),
	}

	err := q.Enqueue(ctx, task)
	if err == nil {
		t.Error("expected error when enqueuing task with empty digest")
	}
}

func TestCVETolerations(t *testing.T) {
	q := NewInMemoryQueue(10)
	defer q.Close()

	ctx := context.Background()
	expiresAt := time.Now().Add(24 * time.Hour).Unix()

	task := &ScanTask{
		ID:         "task-1",
		Repository: "test/repo",
		Digest:     "sha256:test",
		Tag:        "v1.0.0",
		EnqueuedAt: time.Now(),
		Tolerations: []types.CVEToleration{
			{
				ID:        "CVE-2024-12345",
				Statement: "Accepted risk",
				ExpiresAt: &expiresAt,
			},
			{
				ID:        "CVE-2024-67890",
				Statement: "No fix available",
				ExpiresAt: nil,
			},
		},
	}

	err := q.Enqueue(ctx, task)
	if err != nil {
		t.Fatalf("failed to enqueue task with tolerations: %v", err)
	}

	dequeued, err := q.Dequeue(ctx)
	if err != nil {
		t.Fatalf("failed to dequeue task: %v", err)
	}

	if len(dequeued.Tolerations) != 2 {
		t.Errorf("expected 2 tolerations, got %d", len(dequeued.Tolerations))
	}

	if dequeued.Tolerations[0].ID != "CVE-2024-12345" {
		t.Errorf("expected CVE-2024-12345, got %s", dequeued.Tolerations[0].ID)
	}

	if dequeued.Tolerations[1].ExpiresAt != nil {
		t.Error("expected nil expiry for second toleration")
	}
}

func TestMetricsAccuracy(t *testing.T) {
	q := NewInMemoryQueue(100)
	defer q.Close()

	ctx := context.Background()

	// Enqueue 10 tasks
	for i := 0; i < 10; i++ {
		task := &ScanTask{
			ID:         string(rune(i)),
			Repository: "test/repo",
			Digest:     string(rune(i)),
			EnqueuedAt: time.Now(),
		}
		_ = q.Enqueue(ctx, task)
	}

	// Try to enqueue 5 duplicates
	for i := 0; i < 5; i++ {
		task := &ScanTask{
			ID:         "dup",
			Repository: "test/repo",
			Digest:     string(rune(i)),
			EnqueuedAt: time.Now(),
		}
		_ = q.Enqueue(ctx, task)
	}

	// Dequeue 7 tasks
	for i := 0; i < 7; i++ {
		_, _ = q.Dequeue(ctx)
	}

	// Complete 3, fail 2
	for i := 0; i < 3; i++ {
		_ = q.Complete(ctx, "task")
	}
	for i := 0; i < 2; i++ {
		_ = q.Fail(ctx, "task", nil)
	}

	metrics := q.GetMetrics()

	if metrics.Enqueued != 10 {
		t.Errorf("expected 10 enqueued, got %d", metrics.Enqueued)
	}
	if metrics.Dropped != 5 {
		t.Errorf("expected 5 dropped, got %d", metrics.Dropped)
	}
	if metrics.Dequeued != 7 {
		t.Errorf("expected 7 dequeued, got %d", metrics.Dequeued)
	}
	if metrics.Completed != 3 {
		t.Errorf("expected 3 completed, got %d", metrics.Completed)
	}
	if metrics.Failed != 2 {
		t.Errorf("expected 2 failed, got %d", metrics.Failed)
	}
}
func TestHasPendingTask(t *testing.T) {
	q := NewInMemoryQueue(10)
	defer q.Close()

	ctx := context.Background()
	digest := "sha256:abc123"

	// Test with empty digest
	_, err := q.HasPendingTask(ctx, "")
	if err == nil {
		t.Error("expected error for empty digest")
	}

	// Test with no pending tasks
	hasPending, err := q.HasPendingTask(ctx, digest)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hasPending {
		t.Error("expected no pending task")
	}

	// Enqueue a task
	task := &ScanTask{
		ID:         "task-1",
		Repository: "test/repo",
		Digest:     digest,
		Tag:        "v1.0.0",
		EnqueuedAt: time.Now(),
	}

	err = q.Enqueue(ctx, task)
	if err != nil {
		t.Fatalf("failed to enqueue task: %v", err)
	}

	// Test with pending task
	hasPending, err = q.HasPendingTask(ctx, digest)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasPending {
		t.Error("expected pending task")
	}

	// Dequeue the task
	_, err = q.Dequeue(ctx)
	if err != nil {
		t.Fatalf("failed to dequeue task: %v", err)
	}

	// Test after dequeue - should not be pending anymore
	hasPending, err = q.HasPendingTask(ctx, digest)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hasPending {
		t.Error("expected no pending task after dequeue")
	}
}
func TestRescanPriority(t *testing.T) {
	q := NewInMemoryQueue(10)
	defer q.Close()

	ctx := context.Background()

	// Enqueue a normal task first
	normalTask := &ScanTask{
		ID:         "normal-1",
		Repository: "test/repo",
		Digest:     "sha256:normal",
		EnqueuedAt: time.Now(),
		IsRescan:   false,
	}
	err := q.Enqueue(ctx, normalTask)
	if err != nil {
		t.Fatalf("failed to enqueue normal task: %v", err)
	}

	// Enqueue a rescan task after the normal task
	rescanTask := &ScanTask{
		ID:         "rescan-1",
		Repository: "test/repo",
		Digest:     "sha256:rescan",
		EnqueuedAt: time.Now(),
		IsRescan:   true,
	}
	err = q.Enqueue(ctx, rescanTask)
	if err != nil {
		t.Fatalf("failed to enqueue rescan task: %v", err)
	}

	// Dequeue should return the rescan task first (higher priority)
	task1, err := q.Dequeue(ctx)
	if err != nil {
		t.Fatalf("failed to dequeue first task: %v", err)
	}
	if task1.ID != "rescan-1" {
		t.Errorf("expected rescan task first, got %s", task1.ID)
	}
	if task1.Priority != PriorityHigh {
		t.Errorf("expected high priority for rescan task, got %v", task1.Priority)
	}

	// Dequeue should return the normal task second
	task2, err := q.Dequeue(ctx)
	if err != nil {
		t.Fatalf("failed to dequeue second task: %v", err)
	}
	if task2.ID != "normal-1" {
		t.Errorf("expected normal task second, got %s", task2.ID)
	}
	if task2.Priority != PriorityNormal {
		t.Errorf("expected normal priority for regular task, got %v", task2.Priority)
	}
}

func TestFirstScanPriority(t *testing.T) {
	q := NewInMemoryQueue(10)
	defer q.Close()

	ctx := context.Background()

	// Enqueue a normal task (digest changed, not a first scan)
	normalTask := &ScanTask{
		ID:          "normal-1",
		Repository:  "test/repo",
		Digest:      "sha256:normal",
		EnqueuedAt:  time.Now(),
		IsRescan:    false,
		IsFirstScan: false,
	}
	err := q.Enqueue(ctx, normalTask)
	if err != nil {
		t.Fatalf("failed to enqueue normal task: %v", err)
	}

	// Enqueue a first-scan task after the normal task
	firstScanTask := &ScanTask{
		ID:          "first-1",
		Repository:  "test/newrepo",
		Digest:      "sha256:newfirst",
		EnqueuedAt:  time.Now(),
		IsRescan:    false,
		IsFirstScan: true,
	}
	err = q.Enqueue(ctx, firstScanTask)
	if err != nil {
		t.Fatalf("failed to enqueue first-scan task: %v", err)
	}

	// Dequeue should return the first-scan task first (higher priority)
	task1, err := q.Dequeue(ctx)
	if err != nil {
		t.Fatalf("failed to dequeue first task: %v", err)
	}
	if task1.ID != "first-1" {
		t.Errorf("expected first-scan task first, got %s", task1.ID)
	}
	if task1.Priority != PriorityHigh {
		t.Errorf("expected high priority for first-scan task, got %v", task1.Priority)
	}

	// Dequeue should return the normal task second
	task2, err := q.Dequeue(ctx)
	if err != nil {
		t.Fatalf("failed to dequeue second task: %v", err)
	}
	if task2.ID != "normal-1" {
		t.Errorf("expected normal task second, got %s", task2.ID)
	}
	if task2.Priority != PriorityNormal {
		t.Errorf("expected normal priority for regular task, got %v", task2.Priority)
	}
}

func TestHighPriorityOrdering(t *testing.T) {
	q := NewInMemoryQueue(10)
	defer q.Close()

	ctx := context.Background()

	// Enqueue multiple high-priority tasks (rescan and first-scan)
	// They should be processed in FIFO order among themselves
	rescanTask := &ScanTask{
		ID:          "rescan-1",
		Repository:  "test/repo",
		Digest:      "sha256:rescan",
		EnqueuedAt:  time.Now(),
		IsRescan:    true,
		IsFirstScan: false,
	}
	err := q.Enqueue(ctx, rescanTask)
	if err != nil {
		t.Fatalf("failed to enqueue rescan task: %v", err)
	}

	firstScanTask := &ScanTask{
		ID:          "first-1",
		Repository:  "test/newrepo",
		Digest:      "sha256:newfirst",
		EnqueuedAt:  time.Now(),
		IsRescan:    false,
		IsFirstScan: true,
	}
	err = q.Enqueue(ctx, firstScanTask)
	if err != nil {
		t.Fatalf("failed to enqueue first-scan task: %v", err)
	}

	normalTask := &ScanTask{
		ID:          "normal-1",
		Repository:  "test/repo",
		Digest:      "sha256:normal",
		EnqueuedAt:  time.Now(),
		IsRescan:    false,
		IsFirstScan: false,
	}
	err = q.Enqueue(ctx, normalTask)
	if err != nil {
		t.Fatalf("failed to enqueue normal task: %v", err)
	}

	// First two dequeued should be high priority (rescan first, then first-scan)
	task1, err := q.Dequeue(ctx)
	if err != nil {
		t.Fatalf("failed to dequeue first task: %v", err)
	}
	if task1.Priority != PriorityHigh {
		t.Errorf("expected high priority task first, got %v", task1.Priority)
	}
	if task1.ID != "rescan-1" {
		t.Errorf("expected rescan-1 first, got %s", task1.ID)
	}

	task2, err := q.Dequeue(ctx)
	if err != nil {
		t.Fatalf("failed to dequeue second task: %v", err)
	}
	if task2.Priority != PriorityHigh {
		t.Errorf("expected high priority task second, got %v", task2.Priority)
	}
	if task2.ID != "first-1" {
		t.Errorf("expected first-1 second, got %s", task2.ID)
	}

	// Last should be normal priority
	task3, err := q.Dequeue(ctx)
	if err != nil {
		t.Fatalf("failed to dequeue third task: %v", err)
	}
	if task3.Priority != PriorityNormal {
		t.Errorf("expected normal priority task last, got %v", task3.Priority)
	}
	if task3.ID != "normal-1" {
		t.Errorf("expected normal-1 last, got %s", task3.ID)
	}
}
