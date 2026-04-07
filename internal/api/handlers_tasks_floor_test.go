package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/daimoniac/suppline/internal/statestore"
)

func TestHandleGetSemverUpdateTasks_CurrentWithUpperBoundGetsLowerOnlySuggestion(t *testing.T) {
	// Even when status is current, upper bounds are now considered optional,
	// so >=1.26.13 <1.30.0 should suggest >=1.26.13.
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
	if entry.Status != "tighten" {
		t.Fatalf("expected tighten, got %q", entry.Status)
	}
	if len(entry.SuggestedRanges) != 1 || entry.SuggestedRanges[0] != ">=1.26.13" {
		t.Fatalf("expected suggested range >=1.26.13, got %v", entry.SuggestedRanges)
	}
}
