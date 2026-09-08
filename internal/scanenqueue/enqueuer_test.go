package scanenqueue

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/daimoniac/suppline/internal/config"
	"github.com/daimoniac/suppline/internal/policy/catalog"
	"github.com/daimoniac/suppline/internal/queue"
	"github.com/daimoniac/suppline/internal/types"
)

// capturingQueue records tasks as they are submitted. The in-memory queue
// rewrites Priority during Enqueue, so assertions on the task the module
// builds have to observe it here.
type capturingQueue struct {
	submitted []queue.ScanTask
	err       error
}

func (q *capturingQueue) Enqueue(ctx context.Context, task *queue.ScanTask) error {
	if q.err != nil {
		return q.err
	}
	q.submitted = append(q.submitted, *task)
	return nil
}

func (q *capturingQueue) Dequeue(ctx context.Context) (*queue.ScanTask, error) { return nil, nil }
func (q *capturingQueue) Complete(ctx context.Context, taskID string) error    { return nil }
func (q *capturingQueue) Fail(ctx context.Context, taskID string, err error) error {
	return nil
}
func (q *capturingQueue) GetQueueDepth(ctx context.Context) (int, error) { return 0, nil }
func (q *capturingQueue) HasPendingTask(ctx context.Context, digest string) (bool, error) {
	return false, nil
}
func (q *capturingQueue) Close() error { return nil }

func testConfig() *config.RegsyncConfig {
	vexRepo := true
	return &config.RegsyncConfig{
		Defaults: config.Defaults{
			VEX: []types.VEXStatement{{ID: "CVE-default"}},
		},
		Sync: []config.SyncEntry{{
			Target:  "registry.example/team/app",
			Type:    "repository",
			VEX:     []types.VEXStatement{{ID: "CVE-repository"}},
			VEXRepo: &vexRepo,
		}},
	}
}

func testImage() Image {
	return Image{
		Repository: "registry.example/team/app",
		Digest:     "sha256:abc",
		Tag:        "1.2.3",
	}
}

func testCatalog() catalog.Catalog {
	return catalog.NewMemoryCatalog(catalog.MemoryEntry{}, map[string]catalog.MemoryEntry{
		"registry.example/team/app": {
			Evidence: catalog.Evidence{
				VEXStatements: []types.VEXStatement{
					{ID: "CVE-default"},
					{ID: "CVE-repository"},
				},
				UseVEXRepo: true,
			},
		},
	})
}

// fixedClock makes the task ID and EnqueuedAt deterministic.
func fixedClock(e *Enqueuer, idTime, enqueuedAt time.Time) {
	times := []time.Time{idTime, enqueuedAt}
	e.now = func() time.Time {
		now := times[0]
		times = times[1:]
		return now
	}
}

func TestEnqueueDiscoveryConstructsTask(t *testing.T) {
	taskQueue := &capturingQueue{}
	enqueuer := NewWithCatalog(taskQueue, testCatalog())
	idTime := time.Unix(1234, 0)
	enqueuedAt := time.Unix(1235, 42)
	fixedClock(enqueuer, idTime, enqueuedAt)

	task, err := enqueuer.EnqueueDiscovery(context.Background(), testImage(), DiscoveryScan)
	if err != nil {
		t.Fatalf("EnqueueDiscovery() error = %v", err)
	}

	if task.ID != "sha256:abc-1234" {
		t.Errorf("task ID = %q, want %q", task.ID, "sha256:abc-1234")
	}
	if task.Repository != "registry.example/team/app" || task.Digest != "sha256:abc" || task.Tag != "1.2.3" {
		t.Errorf("task image = %s@%s (%s), want requested image", task.Repository, task.Digest, task.Tag)
	}
	if !task.EnqueuedAt.Equal(enqueuedAt) {
		t.Errorf("EnqueuedAt = %v, want %v", task.EnqueuedAt, enqueuedAt)
	}
	if task.Attempts != 0 {
		t.Errorf("Attempts = %d, want 0", task.Attempts)
	}
	if !task.UseVEXRepo {
		t.Error("UseVEXRepo = false, want true")
	}
	if len(task.VEXStatements) != 2 || task.VEXStatements[0].ID != "CVE-default" || task.VEXStatements[1].ID != "CVE-repository" {
		t.Errorf("VEXStatements = %+v, want default and repository statements", task.VEXStatements)
	}
	if len(taskQueue.submitted) != 1 {
		t.Fatalf("submitted %d tasks, want 1", len(taskQueue.submitted))
	}
}

// Before the module existed, only the startup rescan of in-use failed images
// set PriorityHigh; watcher and API tasks left Priority at its zero value.
func TestEnqueueScanMetadata(t *testing.T) {
	tests := []struct {
		name          string
		enqueue       func(*Enqueuer) (*queue.ScanTask, error)
		wantRescan    bool
		wantFirstScan bool
		wantPriority  queue.TaskPriority
	}{
		{
			name: "discovery scan",
			enqueue: func(e *Enqueuer) (*queue.ScanTask, error) {
				return e.EnqueueDiscovery(context.Background(), testImage(), DiscoveryScan)
			},
			wantPriority: queue.PriorityNormal,
		},
		{
			name: "discovery first scan",
			enqueue: func(e *Enqueuer) (*queue.ScanTask, error) {
				return e.EnqueueDiscovery(context.Background(), testImage(), DiscoveryFirstScan)
			},
			wantFirstScan: true,
			wantPriority:  queue.PriorityHigh,
		},
		{
			name: "discovery interval rescan",
			enqueue: func(e *Enqueuer) (*queue.ScanTask, error) {
				return e.EnqueueDiscovery(context.Background(), testImage(), DiscoveryRescan)
			},
			wantRescan:   true,
			wantPriority: queue.PriorityHigh,
		},
		{
			name: "requested rescan",
			enqueue: func(e *Enqueuer) (*queue.ScanTask, error) {
				return e.EnqueueRescan(context.Background(), testImage())
			},
			wantRescan:   true,
			wantPriority: queue.PriorityNormal,
		},
		{
			name: "urgent rescan",
			enqueue: func(e *Enqueuer) (*queue.ScanTask, error) {
				return e.EnqueueUrgentRescan(context.Background(), testImage())
			},
			wantRescan:   true,
			wantPriority: queue.PriorityHigh,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			taskQueue := &capturingQueue{}
			enqueuer := New(taskQueue, testConfig())

			if _, err := tt.enqueue(enqueuer); err != nil {
				t.Fatalf("enqueue error = %v", err)
			}

			if len(taskQueue.submitted) != 1 {
				t.Fatalf("submitted %d tasks, want 1", len(taskQueue.submitted))
			}
			submitted := taskQueue.submitted[0]
			if submitted.IsRescan != tt.wantRescan {
				t.Errorf("IsRescan = %t, want %t", submitted.IsRescan, tt.wantRescan)
			}
			if submitted.IsFirstScan != tt.wantFirstScan {
				t.Errorf("IsFirstScan = %t, want %t", submitted.IsFirstScan, tt.wantFirstScan)
			}
			if submitted.Priority != tt.wantPriority {
				t.Errorf("Priority = %d, want %d", submitted.Priority, tt.wantPriority)
			}
		})
	}
}

func TestEnqueueWithoutRegsyncConfig(t *testing.T) {
	taskQueue := &capturingQueue{}
	enqueuer := New(taskQueue, nil)

	task, err := enqueuer.EnqueueRescan(context.Background(), testImage())
	if err != nil {
		t.Fatalf("EnqueueRescan() error = %v", err)
	}
	if len(task.VEXStatements) != 0 {
		t.Errorf("VEXStatements = %+v, want none", task.VEXStatements)
	}
	if task.UseVEXRepo {
		t.Error("UseVEXRepo = true, want false")
	}
}

// Enqueueing reads exemption evidence only, so an unparseable
// minimumReleaseAge must not stop a repository's scans from carrying VEX.
func TestEnqueueWithInvalidMinimumReleaseAge(t *testing.T) {
	taskQueue := &capturingQueue{}
	vexRepo := true
	enqueuer := New(taskQueue, &config.RegsyncConfig{
		Sync: []config.SyncEntry{{
			Target:  "registry.example/team/app",
			Type:    "repository",
			Policy:  &config.PolicyConfig{Expression: "criticalCount == 0", MinimumReleaseAge: "not-a-duration"},
			VEX:     []types.VEXStatement{{ID: "CVE-repository"}},
			VEXRepo: &vexRepo,
		}},
	})

	task, err := enqueuer.EnqueueRescan(context.Background(), testImage())
	if err != nil {
		t.Fatalf("EnqueueRescan() error = %v", err)
	}
	if len(task.VEXStatements) != 1 || task.VEXStatements[0].ID != "CVE-repository" {
		t.Errorf("VEXStatements = %+v, want configured statement", task.VEXStatements)
	}
	if !task.UseVEXRepo {
		t.Error("UseVEXRepo = false, want true")
	}
	if len(taskQueue.submitted) != 1 {
		t.Fatalf("submitted %d tasks, want 1", len(taskQueue.submitted))
	}
}

func TestEnqueueRescanPreservesQueueDedupe(t *testing.T) {
	taskQueue := queue.NewInMemoryQueue(4)
	enqueuer := New(taskQueue, &config.RegsyncConfig{})
	image := Image{Repository: "repo", Digest: "sha256:same", Tag: "latest"}

	if _, err := enqueuer.EnqueueRescan(context.Background(), image); err != nil {
		t.Fatalf("first EnqueueRescan() error = %v", err)
	}
	second, err := enqueuer.EnqueueRescan(context.Background(), image)
	if err != nil {
		t.Fatalf("second EnqueueRescan() error = %v", err)
	}
	if second == nil {
		t.Fatal("deduplicated enqueue returned nil task")
	}

	depth, err := taskQueue.GetQueueDepth(context.Background())
	if err != nil {
		t.Fatalf("GetQueueDepth() error = %v", err)
	}
	if depth != 1 {
		t.Errorf("queue depth = %d, want 1", depth)
	}
}

func TestEnqueueRescanReturnsQueueError(t *testing.T) {
	taskQueue := queue.NewInMemoryQueue(2)
	if err := taskQueue.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	enqueuer := New(taskQueue, &config.RegsyncConfig{})

	task, err := enqueuer.EnqueueRescan(context.Background(), Image{Digest: "sha256:abc"})
	if err == nil {
		t.Fatal("EnqueueRescan() error = nil, want queue error")
	}
	if task != nil {
		t.Errorf("EnqueueRescan() task = %+v, want nil", task)
	}
	if !strings.Contains(err.Error(), "queue is closed") {
		t.Errorf("EnqueueRescan() error = %v, want queue closed error", err)
	}
}
