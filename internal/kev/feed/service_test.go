package feed

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/daimoniac/suppline/internal/kev"
	"github.com/daimoniac/suppline/internal/observability"
)

const feedBody = `{
  "catalogVersion": "2026.11.25",
  "dateReleased": "2026-11-25T16:00:00.000Z",
  "vulnerabilities": [
    {"cveID": "CVE-2024-1234", "dateAdded": "2024-03-01", "dueDate": "2024-03-22", "knownRansomwareCampaignUse": "Known"},
    {"cveID": "cve-2023-4911", "dateAdded": "2023-11-21", "dueDate": "2023-12-12", "knownRansomwareCampaignUse": "Unknown"}
  ]
}`

type recordingHealth struct {
	mu       sync.Mutex
	messages []string
}

func (h *recordingHealth) UpdateComponentHealth(name string, status observability.ComponentStatus, message string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if name != HealthComponent || status != observability.StatusHealthy {
		panic("unexpected health update: " + name + " " + string(status))
	}
	h.messages = append(h.messages, message)
}

func (h *recordingHealth) last() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.messages) == 0 {
		return ""
	}
	return h.messages[len(h.messages)-1]
}

func feedServer(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	return server
}

func serveFeed(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(feedBody))
}

func TestContainsBeforeFirstSyncFails(t *testing.T) {
	service := NewService(Config{FeedURL: "http://127.0.0.1:0"}, nil, nil, nil)
	if got := service.Snapshot().Status; got != kev.StatusUnavailable {
		t.Fatalf("status = %q", got)
	}
	if _, err := service.Contains(context.Background(), "CVE-2024-1234"); err == nil {
		t.Fatal("no catalog must be an error, not a miss")
	}
}

func TestNilServiceIsDisabled(t *testing.T) {
	var service *Service
	if got := service.Snapshot().Status; got != kev.StatusDisabled {
		t.Fatalf("status = %q", got)
	}
	if _, err := service.Contains(context.Background(), "CVE-2024-1234"); err == nil {
		t.Fatal("a disabled feed must be an error for Contains")
	}
}

func TestSyncFallsBackWhenPrimaryIsForbidden(t *testing.T) {
	var mu sync.Mutex
	var userAgents []string
	server := feedServer(t, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		userAgents = append(userAgents, r.Header.Get("User-Agent"))
		mu.Unlock()
		if r.URL.Path == "/primary" {
			http.Error(w, "blocked", http.StatusForbidden)
			return
		}
		serveFeed(w, r)
	})
	health := &recordingHealth{}
	service := NewService(Config{FeedURL: server.URL + "/primary", FallbackURL: server.URL + "/fallback"}, health, nil, nil)
	service.Sync(context.Background())

	hit, err := service.Contains(context.Background(), "CVE-2024-1234")
	if err != nil || !hit {
		t.Fatalf("hit=%v err=%v", hit, err)
	}
	miss, err := service.Contains(context.Background(), "CVE-2099-0001")
	if err != nil || miss {
		t.Fatalf("miss=%v err=%v", miss, err)
	}
	if len(userAgents) != 2 || userAgents[0] == "" || userAgents[1] == "" {
		t.Fatalf("user agents = %v", userAgents)
	}
	if msg := health.last(); !strings.HasPrefix(msg, "ok: catalog 2026.11.25") {
		t.Fatalf("health message = %q", msg)
	}
}

func TestFailedSyncKeepsCatalogUntilStale(t *testing.T) {
	var fail bool
	server := feedServer(t, func(w http.ResponseWriter, r *http.Request) {
		if fail {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		serveFeed(w, r)
	})
	now := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)
	health := &recordingHealth{}
	service := NewService(Config{FeedURL: server.URL, SyncInterval: time.Hour, StaleAfter: 2 * time.Hour}, health, nil, nil)
	service.now = func() time.Time { return now }
	service.Sync(context.Background())

	fail = true
	now = now.Add(90 * time.Minute)
	service.Sync(context.Background())
	if hit, err := service.Contains(context.Background(), "CVE-2024-1234"); err != nil || !hit {
		t.Fatalf("a failed sync must keep the last catalog: hit=%v err=%v", hit, err)
	}
	if msg := health.last(); !strings.Contains(msg, "last sync failed: CISA KEV feed status 503") {
		t.Fatalf("health message = %q", msg)
	}

	now = now.Add(time.Hour)
	if got := service.Snapshot().Status; got != kev.StatusStale {
		t.Fatalf("status = %q", got)
	}
	if _, err := service.Contains(context.Background(), "CVE-2024-1234"); err == nil || !strings.Contains(err.Error(), "stale") {
		t.Fatalf("a stale catalog must be an error, got %v", err)
	}
	if service.Snapshot().Catalog.Len() != 2 {
		t.Fatal("a stale snapshot still carries the catalog")
	}
}

func TestSyncRejectsEmptyFeedAndKeepsCatalog(t *testing.T) {
	var empty bool
	server := feedServer(t, func(w http.ResponseWriter, r *http.Request) {
		if empty {
			_, _ = w.Write([]byte(`{"vulnerabilities":[]}`))
			return
		}
		serveFeed(w, r)
	})
	service := NewService(Config{FeedURL: server.URL}, nil, nil, nil)
	service.Sync(context.Background())
	empty = true
	service.Sync(context.Background())
	if hit, err := service.Contains(context.Background(), "CVE-2024-1234"); err != nil || !hit {
		t.Fatalf("an empty feed must not replace the catalog: hit=%v err=%v", hit, err)
	}
}

func TestRunSyncsImmediatelyAndStops(t *testing.T) {
	server := feedServer(t, serveFeed)
	service := NewService(Config{FeedURL: server.URL, SyncInterval: time.Hour}, nil, nil, nil)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		service.Run(ctx)
		close(done)
	}()
	deadline := time.Now().Add(5 * time.Second)
	for service.Snapshot().Status != kev.StatusOK {
		if time.Now().After(deadline) {
			t.Fatal("first sync did not complete")
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not stop on cancel")
	}
}
