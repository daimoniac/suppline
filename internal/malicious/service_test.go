package malicious

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/go-git/go-git/v5/plumbing"

	"github.com/daimoniac/suppline/internal/observability"
)

type fakeFeed struct {
	result  SyncResult
	syncErr error
	entries map[string]*Entry
	changed map[string]*Entry
	removed []string
	diffErr error
	loads   int
	diffs   int
}

func (f *fakeFeed) Sync(context.Context) (SyncResult, error) { return f.result, f.syncErr }

func (f *fakeFeed) LoadAll(context.Context, plumbing.Hash) (map[string]*Entry, error) {
	f.loads++
	return f.entries, nil
}

func (f *fakeFeed) Diff(context.Context, plumbing.Hash, plumbing.Hash) (map[string]*Entry, []string, error) {
	f.diffs++
	return f.changed, f.removed, f.diffErr
}

type fakeHealth struct {
	status  observability.ComponentStatus
	message string
}

func (h *fakeHealth) UpdateComponentHealth(name string, status observability.ComponentStatus, message string) {
	if name != HealthComponent {
		panic("unexpected component " + name)
	}
	h.status, h.message = status, message
}

func hash(b byte) plumbing.Hash {
	var h plumbing.Hash
	h[0] = b
	return h
}

func newTestService(t *testing.T, feed *fakeFeed, health HealthReporter) (*Service, *time.Time, *[]Update) {
	t.Helper()
	service, err := newService(feed, ServiceConfig{SyncInterval: time.Hour, StaleAfter: 6 * time.Hour}, health, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	clock := time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)
	service.now = func() time.Time { return clock }
	var updates []Update
	service.OnUpdate(func(_ context.Context, u Update) { updates = append(updates, u) })
	return service, &clock, &updates
}

var npmEvil = Package{Ecosystem: EcosystemNPM, Name: "evil", Version: "1.0.0"}

func TestServiceLifecycle(t *testing.T) {
	ctx := context.Background()
	feed := &fakeFeed{
		result:  SyncResult{Current: hash(1)},
		entries: map[string]*Entry{"a": entry("MAL-1", EcosystemNPM, "evil", nil, allVersions())},
	}
	health := &fakeHealth{}
	service, clock, updates := newTestService(t, feed, health)

	if got := service.Snapshot(); got.Status != StatusUnavailable || got.Index.Match([]Package{npmEvil}) != nil {
		t.Fatalf("expected unavailable before first sync, got %+v", got)
	}

	// First sync: full load and a full update.
	service.Sync(ctx)
	snapshot := service.Snapshot()
	if snapshot.Status != StatusOK || snapshot.Commit != hash(1).String() || len(snapshot.Index.Match([]Package{npmEvil})) != 1 {
		t.Fatalf("unexpected snapshot %+v", snapshot)
	}
	if len(*updates) != 1 || !(*updates)[0].Full {
		t.Fatalf("expected one full update, got %+v", *updates)
	}
	if health.status != observability.StatusHealthy || !strings.HasPrefix(health.message, "ok") {
		t.Fatalf("unexpected health %s %q", health.status, health.message)
	}

	// No upstream change: no update, no reload.
	feed.result = SyncResult{Previous: hash(1), Current: hash(1)}
	service.Sync(ctx)
	if len(*updates) != 1 || feed.loads != 1 || feed.diffs != 0 {
		t.Fatalf("expected nothing to happen, updates=%d loads=%d diffs=%d", len(*updates), feed.loads, feed.diffs)
	}

	// Incremental change: diff applied, changed entries announced.
	feed.result = SyncResult{Previous: hash(1), Current: hash(2)}
	feed.changed = map[string]*Entry{"b": entry("MAL-2", EcosystemNPM, "worse", nil, allVersions())}
	feed.removed = []string{"a"}
	service.Sync(ctx)
	if len(*updates) != 2 || (*updates)[1].Full || len((*updates)[1].Changed) != 1 || (*updates)[1].Changed[0].ID != "MAL-2" {
		t.Fatalf("expected incremental update, got %+v", *updates)
	}
	if service.Snapshot().Index.Match([]Package{npmEvil}) != nil {
		t.Fatal("removed entry must no longer match")
	}

	// Sync failures past stale_after: stale, still healthy, old index still served.
	feed.syncErr = errors.New("network down")
	*clock = clock.Add(7 * time.Hour)
	service.Sync(ctx)
	snapshot = service.Snapshot()
	if snapshot.Status != StatusStale || snapshot.Index.Len() != 1 {
		t.Fatalf("expected stale snapshot with data, got %+v", snapshot)
	}
	if health.status != observability.StatusHealthy || !strings.Contains(health.message, "stale") || !strings.Contains(health.message, "network down") {
		t.Fatalf("unexpected health %s %q", health.status, health.message)
	}

	// Recovery from stale: a full update even without upstream changes.
	feed.syncErr = nil
	feed.result = SyncResult{Previous: hash(2), Current: hash(2)}
	service.Sync(ctx)
	if service.Snapshot().Status != StatusOK {
		t.Fatal("expected ok after recovery")
	}
	if len(*updates) != 3 || !(*updates)[2].Full {
		t.Fatalf("expected full update after recovery, got %+v", *updates)
	}
}

func TestServiceReloadsAfterReclone(t *testing.T) {
	ctx := context.Background()
	feed := &fakeFeed{result: SyncResult{Current: hash(1)}, entries: map[string]*Entry{}}
	service, _, updates := newTestService(t, feed, nil)
	service.Sync(ctx)

	// A re-clone reports no previous commit: everything is reloaded.
	feed.result = SyncResult{Current: hash(3)}
	service.Sync(ctx)
	if feed.loads != 2 || len(*updates) != 2 || !(*updates)[1].Full {
		t.Fatalf("expected a full reload, loads=%d updates=%+v", feed.loads, *updates)
	}
}

func TestServiceFallsBackToFullLoadWhenDiffFails(t *testing.T) {
	ctx := context.Background()
	feed := &fakeFeed{result: SyncResult{Current: hash(1)}, entries: map[string]*Entry{}}
	service, _, updates := newTestService(t, feed, nil)
	service.Sync(ctx)

	feed.result = SyncResult{Previous: hash(1), Current: hash(2)}
	feed.diffErr = errors.New("object not found")
	service.Sync(ctx)
	if feed.loads != 2 || !(*updates)[1].Full || service.Snapshot().Commit != hash(2).String() {
		t.Fatalf("expected full reload at the new commit, loads=%d updates=%+v", feed.loads, *updates)
	}
}

func TestServiceRejectsUnknownEcosystem(t *testing.T) {
	_, err := newService(&fakeFeed{}, ServiceConfig{Ecosystems: []string{"npm", "Hex"}}, nil, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "Hex") {
		t.Fatalf("expected unsupported ecosystem error, got %v", err)
	}
}
