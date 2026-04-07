package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/daimoniac/suppline/internal/config"
	"github.com/daimoniac/suppline/internal/observability"
	"github.com/daimoniac/suppline/internal/queue"
	"github.com/daimoniac/suppline/internal/statestore"
)

// tasksTestServer creates a server with the given inventory store and regsync config.
func tasksTestServer(t *testing.T, store statestore.StateStoreQuery, regsync *config.RegsyncConfig) *APIServer {
	t.Helper()
	cfg := &config.APIConfig{Enabled: true, Port: 8080, APIKey: "", ReadOnly: false}
	return NewAPIServer(cfg, mockAttestationConfig(), store, queue.NewInMemoryQueue(100), regsync, observability.NewLogger("error"))
}

// regsyncWithSemver returns a config with a single sync entry that has a semverRange.
func regsyncWithSemver(source, target string, ranges []string) *config.RegsyncConfig {
	return &config.RegsyncConfig{
		Version: 1,
		Sync: []config.SyncEntry{
			{
				Source: source,
				Target: target,
				Type:   "repository",
				Tags:   &config.TagFilter{SemverRange: ranges},
			},
		},
	}
}

func TestHandleGetSemverUpdateTasks_MethodNotAllowed(t *testing.T) {
	server := tasksTestServer(t, &mockStateStore{}, mockRegsyncConfig())

	req := httptest.NewRequest(http.MethodPost, "/api/v1/tasks/semver-updates", nil)
	w := httptest.NewRecorder()
	server.router.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", w.Code)
	}
}

func TestHandleGetSemverUpdateTasks_NoSemverEntries(t *testing.T) {
	// Config with a sync entry but no semverRange → empty entries list.
	regsync := &config.RegsyncConfig{
		Version: 1,
		Sync: []config.SyncEntry{
			{Source: "docker.io/nginx", Target: "registry.example.com/nginx", Type: "repository"},
		},
	}
	server := tasksTestServer(t, &mockStateStore{}, regsync)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/tasks/semver-updates", nil)
	w := httptest.NewRecorder()
	server.router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp SemverUpdateTasksResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Entries) != 0 {
		t.Errorf("expected 0 entries, got %d", len(resp.Entries))
	}
	if resp.NoRuntimeData {
		t.Error("NoRuntimeData should be false when there are no semver entries")
	}
}

func TestHandleGetSemverUpdateTasks_NoRuntimeData(t *testing.T) {
	// Has a semverRange entry but cluster inventory returns no clusters.
	regsync := regsyncWithSemver("docker.io/nginx", "registry.example.com/nginx", []string{">=1.20.0 <1.26.0"})
	store := &mockClusterInventoryStore{
		mockStateStore: &mockStateStore{},
		summaries:      []statestore.ClusterSummary{}, // no clusters
	}
	server := tasksTestServer(t, store, regsync)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/tasks/semver-updates", nil)
	w := httptest.NewRecorder()
	server.router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp SemverUpdateTasksResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !resp.NoRuntimeData {
		t.Error("expected NoRuntimeData=true when cluster list is empty")
	}
	// Entries should still be populated but with status=no_runtime_data.
	if len(resp.Entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(resp.Entries))
	}
	if resp.Entries[0].Status != "no_runtime_data" {
		t.Errorf("expected status no_runtime_data, got %q", resp.Entries[0].Status)
	}
}

func TestHandleGetSemverUpdateTasks_AllVersionsInRange(t *testing.T) {
	regsync := regsyncWithSemver("docker.io/nginx", "registry.example.com/nginx", []string{">=1.20.0 <1.26.0"})
	store := &mockClusterInventoryStore{
		mockStateStore: &mockStateStore{},
		summaries:      []statestore.ClusterSummary{{Name: "prod"}},
		clusterImages: []statestore.ClusterImageSummary{
			{Namespace: "default", ImageRef: "registry.example.com/nginx", Tag: "1.24.0"},
			{Namespace: "default", ImageRef: "registry.example.com/nginx", Tag: "1.25.3"},
		},
	}
	server := tasksTestServer(t, store, regsync)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/tasks/semver-updates", nil)
	w := httptest.NewRecorder()
	server.router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp SemverUpdateTasksResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.NoRuntimeData {
		t.Error("expected NoRuntimeData=false")
	}
	if len(resp.Entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(resp.Entries))
	}
	entry := resp.Entries[0]
	if entry.Status != "current" {
		t.Errorf("expected status=current, got %q", entry.Status)
	}
	if len(entry.SuggestedRanges) != 1 {
		t.Fatalf("expected 1 suggested range, got %v", entry.SuggestedRanges)
	}
	if entry.SuggestedRanges[0] != ">=1.24.0" {
		t.Errorf("expected suggested range >=1.24.0, got %q", entry.SuggestedRanges[0])
	}
	if len(entry.OutOfRangeVersions) != 0 {
		t.Errorf("expected no out-of-range versions, got %v", entry.OutOfRangeVersions)
	}
}

func TestHandleGetSemverUpdateTasks_OutdatedRange(t *testing.T) {
	// 1.27.2 is outside >=1.20.0 <1.26.0 → should suggest >=1.25.3.
	regsync := regsyncWithSemver("docker.io/nginx", "registry.example.com/nginx", []string{">=1.20.0 <1.26.0"})
	store := &mockClusterInventoryStore{
		mockStateStore: &mockStateStore{},
		summaries:      []statestore.ClusterSummary{{Name: "prod"}},
		clusterImages: []statestore.ClusterImageSummary{
			{Namespace: "default", ImageRef: "registry.example.com/nginx", Tag: "1.25.3"},
			{Namespace: "default", ImageRef: "registry.example.com/nginx", Tag: "1.27.2"},
		},
	}
	server := tasksTestServer(t, store, regsync)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/tasks/semver-updates", nil)
	w := httptest.NewRecorder()
	server.router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp SemverUpdateTasksResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if len(resp.Entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(resp.Entries))
	}
	entry := resp.Entries[0]

	if entry.Status != "outdated" {
		t.Errorf("expected status=outdated, got %q", entry.Status)
	}
	if len(entry.OutOfRangeVersions) != 1 || entry.OutOfRangeVersions[0] != "1.27.2" {
		t.Errorf("expected out-of-range [1.27.2], got %v", entry.OutOfRangeVersions)
	}

	// Suggested range should be lower-bound only at runtime floor.
	if len(entry.SuggestedRanges) != 1 {
		t.Fatalf("expected 1 suggested range, got %v", entry.SuggestedRanges)
	}
	if entry.SuggestedRanges[0] != ">=1.25.3" {
		t.Errorf("expected suggested range >=1.25.3, got %q", entry.SuggestedRanges[0])
	}

	// Entries contain the correct source/target.
	if entry.Source != "docker.io/nginx" {
		t.Errorf("unexpected source %q", entry.Source)
	}
	if entry.Target != "registry.example.com/nginx" {
		t.Errorf("unexpected target %q", entry.Target)
	}
}

func TestHandleGetSemverUpdateTasks_NonSemverTagsIgnored(t *testing.T) {
	// Cluster reports "latest" and an out-of-range version; "latest" must be silently skipped.
	regsync := regsyncWithSemver("docker.io/nginx", "registry.example.com/nginx", []string{">=1.20.0 <1.26.0"})
	store := &mockClusterInventoryStore{
		mockStateStore: &mockStateStore{},
		summaries:      []statestore.ClusterSummary{{Name: "prod"}},
		clusterImages: []statestore.ClusterImageSummary{
			{Namespace: "default", ImageRef: "registry.example.com/nginx", Tag: "latest"},
			{Namespace: "default", ImageRef: "registry.example.com/nginx", Tag: "stable"},
			{Namespace: "default", ImageRef: "registry.example.com/nginx", Tag: "1.25.0"},
		},
	}
	server := tasksTestServer(t, store, regsync)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/tasks/semver-updates", nil)
	w := httptest.NewRecorder()
	server.router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp SemverUpdateTasksResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}

	entry := resp.Entries[0]
	// Only 1.25.0 is a valid semver; "latest" / "stable" must be absent.
	if len(entry.RuntimeVersions) != 1 || entry.RuntimeVersions[0] != "1.25.0" {
		t.Errorf("expected runtime versions [1.25.0], got %v", entry.RuntimeVersions)
	}
	if entry.Status != "current" {
		t.Errorf("expected status=current, got %q", entry.Status)
	}
}

func TestHandleGetSemverUpdateTasks_MultipleSyncEntries(t *testing.T) {
	// Two semver entries: nginx current, redis outdated.
	regsync := &config.RegsyncConfig{
		Version: 1,
		Sync: []config.SyncEntry{
			{
				Source: "docker.io/nginx",
				Target: "registry.example.com/nginx",
				Type:   "repository",
				Tags:   &config.TagFilter{SemverRange: []string{">=1.20.0 <1.26.0"}},
			},
			{
				// No semverRange → should be ignored.
				Source: "docker.io/alpine",
				Target: "registry.example.com/alpine",
				Type:   "repository",
			},
			{
				Source: "docker.io/redis",
				Target: "registry.example.com/redis",
				Type:   "repository",
				Tags:   &config.TagFilter{SemverRange: []string{">=7.0.0 <7.2.0"}},
			},
		},
	}
	store := &mockClusterInventoryStore{
		mockStateStore: &mockStateStore{},
		summaries:      []statestore.ClusterSummary{{Name: "prod"}},
		clusterImages: []statestore.ClusterImageSummary{
			{Namespace: "default", ImageRef: "registry.example.com/nginx", Tag: "1.25.0"},
			{Namespace: "default", ImageRef: "registry.example.com/redis", Tag: "7.4.1"},
		},
	}
	server := tasksTestServer(t, store, regsync)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/tasks/semver-updates", nil)
	w := httptest.NewRecorder()
	server.router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp SemverUpdateTasksResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}

	// Only nginx and redis entries (alpine has no semverRange).
	if len(resp.Entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(resp.Entries))
	}

	byTarget := make(map[string]SemverUpdateEntry)
	for _, e := range resp.Entries {
		byTarget[e.Target] = e
	}

	nginx := byTarget["registry.example.com/nginx"]
	if nginx.Status != "current" {
		t.Errorf("nginx: expected current, got %q", nginx.Status)
	}

	redis := byTarget["registry.example.com/redis"]
	if redis.Status != "outdated" {
		t.Errorf("redis: expected outdated, got %q", redis.Status)
	}
	if len(redis.SuggestedRanges) != 1 {
		t.Fatalf("redis: expected 1 suggested range, got %v", redis.SuggestedRanges)
	}
	if redis.SuggestedRanges[0] != ">=7.4.1" {
		t.Errorf("redis: expected suggested >=7.4.1, got %q", redis.SuggestedRanges[0])
	}
}

func TestHandleGetSemverUpdateTasks_NoLowerBound(t *testing.T) {
	// Range without >= prefix still gets a runtime-based lower bound-only suggestion.
	regsync := regsyncWithSemver("docker.io/nginx", "registry.example.com/nginx", []string{"<1.26.0"})
	store := &mockClusterInventoryStore{
		mockStateStore: &mockStateStore{},
		summaries:      []statestore.ClusterSummary{{Name: "prod"}},
		clusterImages: []statestore.ClusterImageSummary{
			{Namespace: "default", ImageRef: "registry.example.com/nginx", Tag: "1.27.0"},
		},
	}
	server := tasksTestServer(t, store, regsync)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/tasks/semver-updates", nil)
	w := httptest.NewRecorder()
	server.router.ServeHTTP(w, req)

	var resp SemverUpdateTasksResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}

	entry := resp.Entries[0]
	if entry.Status != "outdated" {
		t.Fatalf("expected outdated, got %q", entry.Status)
	}
	if entry.SuggestedRanges[0] != ">=1.27.0" {
		t.Errorf("expected >=1.27.0, got %q", entry.SuggestedRanges[0])
	}
}

func TestHandleGetSemverUpdateTasks_CurrentRangeAlreadyMatchesSuggested(t *testing.T) {
	// Current range is semantically equivalent lower-bound-only -> no suggestion emitted.
	regsync := regsyncWithSemver("docker.io/nginx", "registry.example.com/nginx", []string{">=1.26.13"})
	store := &mockClusterInventoryStore{
		mockStateStore: &mockStateStore{},
		summaries:      []statestore.ClusterSummary{{Name: "prod"}},
		clusterImages: []statestore.ClusterImageSummary{
			{Namespace: "default", ImageRef: "registry.example.com/nginx", Tag: "1.26.13"},
			{Namespace: "default", ImageRef: "registry.example.com/nginx", Tag: "1.27.0"},
		},
	}
	server := tasksTestServer(t, store, regsync)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/tasks/semver-updates", nil)
	w := httptest.NewRecorder()
	server.router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp SemverUpdateTasksResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if len(resp.Entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(resp.Entries))
	}
	entry := resp.Entries[0]
	if entry.Status != "current" {
		t.Fatalf("expected current, got %q", entry.Status)
	}
	if len(entry.SuggestedRanges) != 0 {
		t.Errorf("expected no suggestion when range already matches, got %v", entry.SuggestedRanges)
	}
}

func TestHandleGetSemverUpdateTasks_RequiresAuth(t *testing.T) {
	// With an API key set, the endpoint must reject unauthenticated requests.
	cfg := &config.APIConfig{Enabled: true, Port: 8080, APIKey: "secret-key", ReadOnly: false}
	regsync := regsyncWithSemver("docker.io/nginx", "registry.example.com/nginx", []string{">=1.20.0 <1.26.0"})
	server := NewAPIServer(cfg, mockAttestationConfig(), &mockStateStore{}, queue.NewInMemoryQueue(100), regsync, observability.NewLogger("error"))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/tasks/semver-updates", nil)
	w := httptest.NewRecorder()
	server.router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without auth, got %d", w.Code)
	}
}
