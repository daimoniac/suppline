package watcher

import (
	"context"
	"testing"
	"time"

	"github.com/daimoniac/suppline/internal/config"
	"github.com/daimoniac/suppline/internal/observability"
	"github.com/daimoniac/suppline/internal/policy/catalog"
	"github.com/daimoniac/suppline/internal/queue"
	"github.com/daimoniac/suppline/internal/scanenqueue"
	"github.com/daimoniac/suppline/internal/statestore"
)

// Discovery reads the running configuration on every pass, so a reload that
// changes an image entry's tag is honoured without a restart.
func TestWatcher_DiscoverFollowsReloadedConfig(t *testing.T) {
	ctx := context.Background()
	imageEntry := func(tag string) *config.RegsyncConfig {
		return &config.RegsyncConfig{Sync: []config.SyncEntry{{
			Source: "upstream/app1:" + tag, Target: "myorg/app1:" + tag, Type: "image",
		}}}
	}
	running := catalog.NewConfigCatalog(imageEntry("v1.0"))

	registry := &mockRegistryClient{
		repositories: []string{"myorg/app1"},
		tags:         map[string][]string{"myorg/app1": {"v1.0", "v2.0"}},
		digests:      map[string]string{"myorg/app1:v1.0": "sha256:one", "myorg/app1:v2.0": "sha256:two"},
	}
	taskQueue := queue.NewInMemoryQueue(100)
	w := NewWatcherWithCatalogAndEnqueuer(
		registry, running.Current,
		&mockStateStore{scans: make(map[string]*statestore.ScanRecord)},
		taskQueue, scanenqueue.New(taskQueue, nil), running,
		Config{PollInterval: time.Second, RescanInterval: 24 * time.Hour},
		observability.NewLogger("error"),
	)

	discover := func() []string {
		t.Helper()
		if err := w.Discover(ctx); err != nil {
			t.Fatalf("Discover() error = %v", err)
		}
		var digests []string
		for {
			depth, _ := taskQueue.GetQueueDepth(ctx)
			if depth == 0 {
				return digests
			}
			task, err := taskQueue.Dequeue(ctx)
			if err != nil {
				t.Fatalf("Dequeue() error = %v", err)
			}
			digests = append(digests, task.Digest)
		}
	}

	if got := discover(); len(got) != 1 || got[0] != "sha256:one" {
		t.Fatalf("before reload discovered %v, want [sha256:one]", got)
	}
	running.Replace(imageEntry("v2.0"))
	if got := discover(); len(got) != 1 || got[0] != "sha256:two" {
		t.Fatalf("after reload discovered %v, want [sha256:two]", got)
	}
}

// A repository a reload adds is discovered at once, not on the next full pass.
func TestWatcher_DiscoversRepositoryAddedByReload(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	entry := func(target string) config.SyncEntry {
		return config.SyncEntry{Source: target, Target: target, Type: "repository", InPlace: true}
	}
	running := catalog.NewConfigCatalog(&config.RegsyncConfig{Sync: []config.SyncEntry{entry("ci.local/app1")}})
	registry := &mockRegistryClient{
		// The fake lists repositories itself; only the full pass reads it.
		repositories: []string{"ci.local/app1"},
		tags:         map[string][]string{"ci.local/app1": {"v1"}, "ci.local/app2": {"v1"}},
		digests:      map[string]string{"ci.local/app1:v1": "sha256:one", "ci.local/app2:v1": "sha256:two"},
	}
	taskQueue := queue.NewInMemoryQueue(100)
	w := NewWatcherWithCatalogAndEnqueuer(
		registry, running.Current,
		&mockStateStore{scans: make(map[string]*statestore.ScanRecord)},
		taskQueue, scanenqueue.New(taskQueue, nil), running,
		// The poll interval is far longer than the test: only the reload can discover app2.
		Config{PollInterval: time.Hour, RescanInterval: 24 * time.Hour, ConfigChanged: running.Changed},
		observability.NewLogger("error"),
	)
	go func() { _ = w.Start(ctx) }()

	next := func() *queue.ScanTask {
		t.Helper()
		task, err := taskQueue.Dequeue(ctx)
		if err != nil {
			t.Fatalf("no task: %v", err)
		}
		return task
	}
	if task := next(); task.Repository != "ci.local/app1" {
		t.Fatalf("initial discovery queued %s", task.Repository)
	}
	running.Replace(&config.RegsyncConfig{Sync: []config.SyncEntry{entry("ci.local/app1"), entry("ci.local/app2")}})
	if task := next(); task.Repository != "ci.local/app2" || task.Digest != "sha256:two" {
		t.Fatalf("after reload queued %s@%s, want ci.local/app2@sha256:two", task.Repository, task.Digest)
	}
}
