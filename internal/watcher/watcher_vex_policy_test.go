package watcher

import (
	"context"
	"testing"
	"time"

	"github.com/daimoniac/suppline/internal/config"
	"github.com/daimoniac/suppline/internal/observability"
	"github.com/daimoniac/suppline/internal/queue"
	"github.com/daimoniac/suppline/internal/statestore"
	"github.com/daimoniac/suppline/internal/types"
)

// Discovery does not resolve policy, so a repository whose x-cooldown
// cannot be parsed is still discovered; the invalid duration surfaces during
// policy evaluation when the scan runs.
func TestWatcher_Discover_InvalidCooldownStillQueues(t *testing.T) {
	ctx := context.Background()

	mockRegistry := &mockRegistryClient{
		repositories: []string{"myorg/app1"},
		tags:         map[string][]string{"myorg/app1": {"v1.0"}},
		digests:      map[string]string{"myorg/app1:v1.0": "sha256:digest1"},
	}
	mockStore := &mockStateStore{scans: make(map[string]*statestore.ScanRecord)}
	mockQueue := queue.NewInMemoryQueue(100)

	expiresAt := time.Now().Add(30 * 24 * time.Hour).Unix()
	regsyncCfg := &config.RegsyncConfig{
		Sync: []config.SyncEntry{{
			Target:   "myorg/app1",
			Type:     "repository",
			Policy:   &config.PolicyConfig{Expression: "criticalCount == 0"},
			Cooldown: "not-a-duration",
			VEX: []types.VEXStatement{
				{ID: "CVE-2024-1234", State: types.VEXStateNotAffected, Detail: "test VEX statement", ExpiresAt: &expiresAt},
			},
		}},
	}

	w := NewWatcher(mockRegistry, regsyncCfg, mockStore, mockQueue, Config{
		PollInterval:   5 * time.Second,
		RescanInterval: 24 * time.Hour,
	}, observability.NewLogger("error"))

	if err := w.Discover(ctx); err != nil {
		t.Fatalf("Discover() error = %v", err)
	}

	queueDepth, _ := mockQueue.GetQueueDepth(ctx)
	if queueDepth != 1 {
		t.Fatalf("queue depth = %d, want 1", queueDepth)
	}

	task, err := mockQueue.Dequeue(ctx)
	if err != nil {
		t.Fatalf("Dequeue() error = %v", err)
	}
	if task.Repository != "myorg/app1" || task.Digest != "sha256:digest1" {
		t.Errorf("task = %s@%s, want myorg/app1@sha256:digest1", task.Repository, task.Digest)
	}
}
