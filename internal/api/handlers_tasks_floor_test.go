package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/daimoniac/suppline/internal/statestore"
)

func TestHandleGetSemverUpdateTasks_CurrentWithUpperBoundStaysCurrent(t *testing.T) {
	// If upper bounds are already configured and all runtime versions are in-range,
	// no tighten suggestion should be emitted.
	regsync := regsyncWithSemver("docker.io/nginx", "registry.example.com/nginx", []string{">=1.26.13 <1.30.0"})
	store := &mockClusterInventoryStore{
		mockStateStore: &mockStateStore{},
		summaries:      []statestore.ClusterSummary{{Name: "prod"}},
		clusterImages: []statestore.ClusterImageSummary{
			{Namespace: "default", ImageRef: "registry.example.com/nginx", Tag: "1.26.13"},
			{Namespace: "default", ImageRef: "registry.example.com/nginx", Tag: "1.29.5"},
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
		t.Fatalf("expected no suggested ranges, got %v", entry.SuggestedRanges)
	}
}
