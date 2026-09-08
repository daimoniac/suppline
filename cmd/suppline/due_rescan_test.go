package main

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/daimoniac/suppline/internal/queue"
	"github.com/daimoniac/suppline/internal/scanenqueue"
	"github.com/daimoniac/suppline/internal/statestore"
)

type stubDueArtifactLister struct {
	records []*statestore.ScanRecord
	err     error
}

func (s *stubDueArtifactLister) ListDueForRescanArtifacts(ctx context.Context, olderThan time.Duration) ([]*statestore.ScanRecord, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.records, nil
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func drainDigests(t *testing.T, taskQueue *queue.InMemoryQueue, count int) []string {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	out := make([]string, 0, count)
	for i := 0; i < count; i++ {
		task, err := taskQueue.Dequeue(ctx)
		if err != nil {
			t.Fatalf("dequeue %d: %v", i, err)
		}
		out = append(out, task.Digest)
	}
	return out
}

// Seeding must drain in-use artifacts before the rest, since a vulnerable image that is
// actually running matters more than one sitting unused in the registry.
func TestEnqueueDueArtifacts_InUseBeforeNotInUse(t *testing.T) {
	store := &stubDueArtifactLister{records: []*statestore.ScanRecord{
		{Digest: "sha256:idle-1", Repository: "repo/idle", Tag: "1"},
		{Digest: "sha256:live-1", Repository: "repo/live", Tag: "1", RuntimeUsed: true},
		{Digest: "sha256:idle-2", Repository: "repo/idle", Tag: "2"},
		{Digest: "sha256:live-2", Repository: "repo/live", Tag: "2", RuntimeUsed: true},
	}}

	taskQueue := queue.NewInMemoryQueue(100)
	enqueuer := scanenqueue.New(taskQueue, nil)

	if err := enqueueDueArtifacts(context.Background(), store, enqueuer, time.Hour, discardLogger()); err != nil {
		t.Fatalf("enqueueDueArtifacts: %v", err)
	}

	got := drainDigests(t, taskQueue, 4)
	want := []string{"sha256:live-1", "sha256:live-2", "sha256:idle-1", "sha256:idle-2"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("dequeue order = %v, want %v", got, want)
		}
	}
}

// The startup rescan of previously failed in-use artifacts must stay ahead of the seeded
// backlog, even though seeding enqueues far more tasks.
func TestStartupEnqueueOrder_FailedInUseBeforeDue(t *testing.T) {
	taskQueue := queue.NewInMemoryQueue(100)
	enqueuer := scanenqueue.New(taskQueue, nil)
	ctx := context.Background()

	if _, err := enqueuer.EnqueueUrgentRescan(ctx, scanenqueue.Image{
		Repository: "repo/failed", Digest: "sha256:failed-in-use", Tag: "1",
	}); err != nil {
		t.Fatalf("EnqueueUrgentRescan: %v", err)
	}

	store := &stubDueArtifactLister{records: []*statestore.ScanRecord{
		{Digest: "sha256:live-1", Repository: "repo/live", Tag: "1", RuntimeUsed: true},
		{Digest: "sha256:idle-1", Repository: "repo/idle", Tag: "1"},
	}}
	if err := enqueueDueArtifacts(ctx, store, enqueuer, time.Hour, discardLogger()); err != nil {
		t.Fatalf("enqueueDueArtifacts: %v", err)
	}

	got := drainDigests(t, taskQueue, 3)
	want := []string{"sha256:failed-in-use", "sha256:live-1", "sha256:idle-1"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("dequeue order = %v, want %v", got, want)
		}
	}
}

func TestEnqueueDueArtifacts_NoneDue(t *testing.T) {
	taskQueue := queue.NewInMemoryQueue(100)
	enqueuer := scanenqueue.New(taskQueue, nil)

	if err := enqueueDueArtifacts(context.Background(), &stubDueArtifactLister{}, enqueuer, time.Hour, discardLogger()); err != nil {
		t.Fatalf("enqueueDueArtifacts: %v", err)
	}

	depth, err := taskQueue.GetQueueDepth(context.Background())
	if err != nil {
		t.Fatalf("GetQueueDepth: %v", err)
	}
	if depth != 0 {
		t.Fatalf("queue depth = %d, want 0", depth)
	}
}
