package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/daimoniac/suppline/internal/config"
	"github.com/daimoniac/suppline/internal/observability"
	"github.com/daimoniac/suppline/internal/queue"
	"github.com/daimoniac/suppline/internal/statestore"
	"github.com/daimoniac/suppline/internal/types"
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

func regsyncWithVEX(target string, statements []types.VEXStatement) *config.RegsyncConfig {
	return &config.RegsyncConfig{
		Version: 1,
		Sync: []config.SyncEntry{
			{
				Source: "docker.io/test",
				Target: target,
				Type:   "repository",
				VEX:    statements,
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
	if entry.Status != "tighten" {
		t.Errorf("expected status=tighten, got %q", entry.Status)
	}
	if len(entry.SuggestedRanges) != 1 {
		t.Fatalf("expected 1 suggested range, got %v", entry.SuggestedRanges)
	}
	if entry.SuggestedRanges[0] != ">=1.24.0 <1.26.0" {
		t.Errorf("expected suggested range >=1.24.0 <1.26.0, got %q", entry.SuggestedRanges[0])
	}
	if len(entry.OutOfRangeVersions) != 0 {
		t.Errorf("expected no out-of-range versions, got %v", entry.OutOfRangeVersions)
	}
}

func TestHandleGetSemverUpdateTasks_MatchesCanonicalDockerHubRepositoryRefs(t *testing.T) {
	regsync := regsyncWithSemver("docker.io/falcosecurity/falco", "hostingmaloonde/falcosecurity_falco", []string{">=0.40.0 <0.42.0"})
	store := &mockClusterInventoryStore{
		mockStateStore: &mockStateStore{},
		summaries:      []statestore.ClusterSummary{{Name: "prod"}},
		clusterImages: []statestore.ClusterImageSummary{
			{Namespace: "security", ImageRef: "docker.io/hostingmaloonde/falcosecurity_falco", Tag: "0.41.3"},
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
	if len(entry.RuntimeVersions) != 1 || entry.RuntimeVersions[0] != "0.41.3" {
		t.Fatalf("expected runtime versions [0.41.3], got %v", entry.RuntimeVersions)
	}
	if entry.Status == "no_runtime_data" {
		t.Fatalf("expected runtime data match after canonicalization, got status=%q", entry.Status)
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

	if entry.Status != "out_of_bounds" {
		t.Errorf("expected status=out_of_bounds, got %q", entry.Status)
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
	if entry.Status != "tighten" {
		t.Errorf("expected status=tighten, got %q", entry.Status)
	}
}

func TestHandleGetSemverUpdateTasks_MultipleSyncEntries(t *testing.T) {
	// Two semver entries: nginx tighten, redis out_of_bounds.
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
	if nginx.Status != "tighten" {
		t.Errorf("nginx: expected tighten, got %q", nginx.Status)
	}

	redis := byTarget["registry.example.com/redis"]
	if redis.Status != "out_of_bounds" {
		t.Errorf("redis: expected out_of_bounds, got %q", redis.Status)
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
	if entry.Status != "out_of_bounds" {
		t.Fatalf("expected out_of_bounds, got %q", entry.Status)
	}
	if entry.SuggestedRanges[0] != ">=1.27.0" {
		t.Errorf("expected >=1.27.0, got %q", entry.SuggestedRanges[0])
	}
}

func TestHandleGetSemverUpdateTasks_PreservesPrereleaseMarkerInTightenSuggestion(t *testing.T) {
	regsync := regsyncWithSemver("docker.io/prom/memcached-exporter", "hostingmaloonde/prom_memcached_exporter", []string{">=0.15.3-0"})
	store := &mockClusterInventoryStore{
		mockStateStore: &mockStateStore{},
		summaries:      []statestore.ClusterSummary{{Name: "prod"}},
		clusterImages: []statestore.ClusterImageSummary{
			{Namespace: "default", ImageRef: "hostingmaloonde/prom_memcached_exporter", Tag: "0.15.5"},
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
	if entry.Status != "tighten" {
		t.Fatalf("expected tighten, got %q", entry.Status)
	}
	if len(entry.SuggestedRanges) != 1 || entry.SuggestedRanges[0] != ">=0.15.5-0" {
		t.Fatalf("expected suggested range >=0.15.5-0, got %v", entry.SuggestedRanges)
	}
}

func TestHandleGetSemverUpdateTasks_PreservesPrereleaseMarkerInOutOfBoundsSuggestion(t *testing.T) {
	regsync := regsyncWithSemver("docker.io/nginx", "registry.example.com/nginx", []string{">=1.20.0-0 <1.26.0"})
	store := &mockClusterInventoryStore{
		mockStateStore: &mockStateStore{},
		summaries:      []statestore.ClusterSummary{{Name: "prod"}},
		clusterImages: []statestore.ClusterImageSummary{
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
	if entry.Status != "out_of_bounds" {
		t.Fatalf("expected out_of_bounds, got %q", entry.Status)
	}
	if len(entry.SuggestedRanges) != 1 || entry.SuggestedRanges[0] != ">=1.27.2-0" {
		t.Fatalf("expected suggested range >=1.27.2-0, got %v", entry.SuggestedRanges)
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

func TestHandleGetSemverUpdateTasks_MultipleRangesORLogic(t *testing.T) {
	regsync := regsyncWithSemver("docker.io/nginx", "registry.example.com/nginx", []string{">=1.20.0 <1.25.0", ">=1.27.0"})
	store := &mockClusterInventoryStore{
		mockStateStore: &mockStateStore{},
		summaries:      []statestore.ClusterSummary{{Name: "prod"}},
		clusterImages: []statestore.ClusterImageSummary{
			{Namespace: "default", ImageRef: "registry.example.com/nginx", Tag: "1.27.5"},
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
	if entry.Status != "tighten" {
		t.Fatalf("expected status=tighten with OR range match, got %q", entry.Status)
	}
	if len(entry.OutOfRangeVersions) != 0 {
		t.Fatalf("expected no out-of-range versions, got %v", entry.OutOfRangeVersions)
	}
}

func TestHandleGetSemverUpdateTasks_MultipleRangesMixedResults(t *testing.T) {
	regsync := regsyncWithSemver("docker.io/nginx", "registry.example.com/nginx", []string{">=1.20.0 <1.25.0", ">=1.27.0"})
	store := &mockClusterInventoryStore{
		mockStateStore: &mockStateStore{},
		summaries:      []statestore.ClusterSummary{{Name: "prod"}},
		clusterImages: []statestore.ClusterImageSummary{
			{Namespace: "default", ImageRef: "registry.example.com/nginx", Tag: "1.24.0"},
			{Namespace: "default", ImageRef: "registry.example.com/nginx", Tag: "1.27.5"},
			{Namespace: "default", ImageRef: "registry.example.com/nginx", Tag: "1.25.5"},
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
	if entry.Status != "out_of_bounds" {
		t.Fatalf("expected status=out_of_bounds with mixed matches, got %q", entry.Status)
	}
	if len(entry.OutOfRangeVersions) != 1 || entry.OutOfRangeVersions[0] != "1.25.5" {
		t.Fatalf("expected out-of-range [1.25.5], got %v", entry.OutOfRangeVersions)
	}
}

func TestHandleGetSemverUpdateTasks_MultipleRangesTightenPreservesPinsAndVPrefix(t *testing.T) {
	regsync := regsyncWithSemver(
		"darthsim/imgproxy",
		"hostingmaloonde/darthsim_imgproxy",
		[]string{">=v3.30.0", "v3.8.0"},
	)
	store := &mockClusterInventoryStore{
		mockStateStore: &mockStateStore{},
		summaries:      []statestore.ClusterSummary{{Name: "prod"}},
		clusterImages: []statestore.ClusterImageSummary{
			{Namespace: "default", ImageRef: "hostingmaloonde/darthsim_imgproxy", Tag: "v3.8.0"},
			{Namespace: "default", ImageRef: "hostingmaloonde/darthsim_imgproxy", Tag: "v3.30.1"},
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
	if entry.Status != "tighten" {
		t.Fatalf("expected tighten, got %q", entry.Status)
	}
	if len(entry.OutOfRangeVersions) != 0 {
		t.Fatalf("expected no out-of-range versions, got %v", entry.OutOfRangeVersions)
	}
	if len(entry.SuggestedRanges) != 2 {
		t.Fatalf("expected two suggested ranges, got %v", entry.SuggestedRanges)
	}
	if entry.SuggestedRanges[0] != ">=v3.30.1" || entry.SuggestedRanges[1] != "v3.8.0" {
		t.Fatalf("expected [>=v3.30.1 v3.8.0], got %v", entry.SuggestedRanges)
	}
}

func TestHandleGetSemverUpdateTasks_MultipleRangesWithFutureWindowsRemainCurrent(t *testing.T) {
	regsync := regsyncWithSemver(
		"node",
		"hostingmaloonde/node",
		[]string{">=22.21.1 <23", ">=24.12.0 <25", ">=26.0.0 <27"},
	)
	store := &mockClusterInventoryStore{
		mockStateStore: &mockStateStore{},
		summaries:      []statestore.ClusterSummary{{Name: "prod"}},
		clusterImages: []statestore.ClusterImageSummary{
			{Namespace: "default", ImageRef: "hostingmaloonde/node", Tag: "22.21.1"},
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
		t.Fatalf("expected no suggestion, got %v", entry.SuggestedRanges)
	}
}

func TestHandleGetSemverUpdateTasks_MultipleRangesDropsObsoleteHistoricalWindows(t *testing.T) {
	regsync := regsyncWithSemver(
		"kiwigrid/k8s-sidecar",
		"hostingmaloonde/kiwigrid-k8s-sidecar",
		[]string{">=1.19.5 <1.24.6", ">=1.30.9 <2.0.0", ">=2.1.2"},
	)
	store := &mockClusterInventoryStore{
		mockStateStore: &mockStateStore{},
		summaries:      []statestore.ClusterSummary{{Name: "prod"}},
		clusterImages: []statestore.ClusterImageSummary{
			{Namespace: "default", ImageRef: "hostingmaloonde/kiwigrid-k8s-sidecar", Tag: "2.5.0"},
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
	if entry.Status != "tighten" {
		t.Fatalf("expected tighten, got %q", entry.Status)
	}
	if len(entry.SuggestedRanges) != 1 {
		t.Fatalf("expected one suggested range, got %v", entry.SuggestedRanges)
	}
	if entry.SuggestedRanges[0] != ">=2.5.0" {
		t.Fatalf("expected [>=2.5.0], got %v", entry.SuggestedRanges)
	}
	if len(entry.OutOfRangeVersions) != 0 {
		t.Fatalf("expected no out-of-range versions, got %v", entry.OutOfRangeVersions)
	}
}

func TestHandleGetSemverUpdateTasks_TightenDropsObsoleteTildeAndKeepsEquivalentLowerBoundStyle(t *testing.T) {
	regsync := regsyncWithSemver(
		"nginx",
		"hostingmaloonde/nginx",
		[]string{">=1.29", "~1.27"},
	)
	store := &mockClusterInventoryStore{
		mockStateStore: &mockStateStore{},
		summaries:      []statestore.ClusterSummary{{Name: "prod"}},
		clusterImages: []statestore.ClusterImageSummary{
			{Namespace: "default", ImageRef: "hostingmaloonde/nginx", Tag: "1.29"},
			{Namespace: "default", ImageRef: "hostingmaloonde/nginx", Tag: "1.29.3"},
			{Namespace: "default", ImageRef: "hostingmaloonde/nginx", Tag: "1.29.5"},
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
	if entry.Status != "tighten" {
		t.Fatalf("expected tighten, got %q", entry.Status)
	}
	if len(entry.OutOfRangeVersions) != 0 {
		t.Fatalf("expected no out-of-range versions, got %v", entry.OutOfRangeVersions)
	}
	if len(entry.SuggestedRanges) != 1 {
		t.Fatalf("expected one suggested range, got %v", entry.SuggestedRanges)
	}
	if entry.SuggestedRanges[0] != ">=1.29" {
		t.Fatalf("expected [>=1.29], got %v", entry.SuggestedRanges)
	}
}

func TestHandleGetSemverUpdateTasks_AIAgentPromptReturnedWhenSuggestionsExist(t *testing.T) {
	regsync := regsyncWithSemver("docker.io/nginx", "registry.example.com/nginx", []string{">=1.20.0 <1.26.0"})
	store := &mockClusterInventoryStore{
		mockStateStore: &mockStateStore{},
		summaries:      []statestore.ClusterSummary{{Name: "prod"}},
		clusterImages: []statestore.ClusterImageSummary{
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

	if resp.AIAgentPrompt == "" {
		t.Fatal("expected non-empty ai_agent_prompt")
	}
	if strings.Contains(resp.AIAgentPrompt, "\\n") {
		t.Fatalf("expected ai_agent_prompt to contain real newlines, got escaped newlines: %q", resp.AIAgentPrompt)
	}
	if !strings.Contains(resp.AIAgentPrompt, "\n") {
		t.Fatalf("expected ai_agent_prompt to contain newline characters, got: %q", resp.AIAgentPrompt)
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

func TestHandleGetVEXExpiryTasks_MethodNotAllowed(t *testing.T) {
	server := tasksTestServer(t, &mockStateStore{}, mockRegsyncConfig())

	req := httptest.NewRequest(http.MethodPost, "/api/v1/tasks/vex-expiry", nil)
	w := httptest.NewRecorder()
	server.router.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", w.Code)
	}
}

func TestHandleGetVEXExpiryTasks_ReturnsExpiredAndExpiringSoon(t *testing.T) {
	now := time.Now().UTC()
	expiredAt := now.Add(-2 * time.Hour).Unix()
	expiringSoonAt := now.Add(48 * time.Hour).Unix()
	futureAt := now.Add(20 * 24 * time.Hour).Unix()

	regsync := &config.RegsyncConfig{
		Version: 1,
		Sync: []config.SyncEntry{
			{
				Source: "docker.io/nginx",
				Target: "registry.example.com/nginx",
				Type:   "repository",
				VEX: []types.VEXStatement{
					{ID: "CVE-2026-0001", State: types.VEXStateNotAffected, ExpiresAt: &expiredAt},
					{ID: "CVE-2026-0002", State: types.VEXStateNotAffected, ExpiresAt: &expiringSoonAt},
					{ID: "CVE-2026-0003", State: types.VEXStateNotAffected, ExpiresAt: &futureAt},
				},
			},
		},
	}
	server := tasksTestServer(t, &mockStateStore{}, regsync)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/tasks/vex-expiry", nil)
	w := httptest.NewRecorder()
	server.router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp VEXExpiryTasksResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if len(resp.Entries) != 2 {
		t.Fatalf("expected 2 task entries, got %d", len(resp.Entries))
	}

	byCVE := map[string]VEXExpiryTaskEntry{}
	for _, entry := range resp.Entries {
		byCVE[entry.CVEID] = entry
	}

	if byCVE["CVE-2026-0001"].Status != "expired" {
		t.Fatalf("expected expired status, got %q", byCVE["CVE-2026-0001"].Status)
	}
	if byCVE["CVE-2026-0002"].Status != "expiring_soon" {
		t.Fatalf("expected expiring_soon status, got %q", byCVE["CVE-2026-0002"].Status)
	}
	if _, exists := byCVE["CVE-2026-0003"]; exists {
		t.Fatal("did not expect far-future VEX entry in task list")
	}

	if resp.AIAgentPrompt == "" {
		t.Fatal("expected non-empty ai_agent_prompt")
	}
	if !strings.Contains(resp.AIAgentPrompt, "CVE-2026-0001") || !strings.Contains(resp.AIAgentPrompt, "CVE-2026-0002") {
		t.Fatalf("prompt missing expected CVEs: %s", resp.AIAgentPrompt)
	}
}

func TestHandleGetVEXExpiryTasks_EmptyWhenNoExpiringEntries(t *testing.T) {
	futureAt := time.Now().UTC().Add(30 * 24 * time.Hour).Unix()
	regsync := regsyncWithVEX("registry.example.com/nginx", []types.VEXStatement{
		{ID: "CVE-2026-0100", State: types.VEXStateNotAffected, ExpiresAt: &futureAt},
	})
	server := tasksTestServer(t, &mockStateStore{}, regsync)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/tasks/vex-expiry", nil)
	w := httptest.NewRecorder()
	server.router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp VEXExpiryTasksResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if len(resp.Entries) != 0 {
		t.Fatalf("expected 0 entries, got %d", len(resp.Entries))
	}
	if resp.AIAgentPrompt != "" {
		t.Fatalf("expected empty ai_agent_prompt, got %q", resp.AIAgentPrompt)
	}
}
