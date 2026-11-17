package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/daimoniac/suppline/internal/config"
	"github.com/daimoniac/suppline/internal/configedit"
	"github.com/daimoniac/suppline/internal/observability"
	"github.com/daimoniac/suppline/internal/policy/catalog"
	"github.com/daimoniac/suppline/internal/statestore"
)

// Tags such as alpine-v19.5.3 compare as 19.5.3, so the suggested range must
// name the bare version: ">=alpine-v19.5.3" is not a valid constraint.
func TestHandleGetSemverUpdateTasks_PrefixedTagSuggestsBareVersion(t *testing.T) {
	for _, tc := range []struct{ name, tag string }{
		{"dash prefix", "alpine-v19.5.3"},
		{"distro and arch prefix", "alpine3.21-x86_64-v19.5.3"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			regsync := regsyncWithSemver(
				"registry.gitlab.com/gitlab-org/gitlab-runner",
				"hostingmaloonde/gitlab-org_gitlab-runner",
				[]string{">=20.0.0"},
			)
			store := &mockClusterInventoryStore{
				mockStateStore: &mockStateStore{},
				summaries:      []statestore.ClusterSummary{{Name: "prod"}},
				clusterImages: []statestore.ClusterImageSummary{
					{Namespace: "ci", ImageRef: "hostingmaloonde/gitlab-org_gitlab-runner", Tag: tc.tag},
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
				t.Fatalf("status = %q, want out_of_bounds", entry.Status)
			}
			if len(entry.SuggestedRanges) != 1 || entry.SuggestedRanges[0] != ">=19.5.3" {
				t.Fatalf("suggested = %v, want [>=19.5.3]", entry.SuggestedRanges)
			}
		})
	}
}

func TestApplySemverUpdatesRejectsInvalidRange(t *testing.T) {
	path := filepath.Join(t.TempDir(), "suppline.yml")
	original := []byte(`version: 1
sync:
  - source: registry.gitlab.com/gitlab-org/gitlab-runner
    target: registry.example.com/gitlab-runner
    type: repository
    tags:
      semverRange:
        - ">=18.9.0"
`)
	if err := os.WriteFile(path, original, 0o644); err != nil {
		t.Fatal(err)
	}
	regsync := regsyncWithSemver("registry.gitlab.com/gitlab-org/gitlab-runner", "registry.example.com/gitlab-runner", []string{">=18.9.0"})
	server := tasksTestServer(t, &mockStateStore{}, regsync)
	server.SetConfigEditor(configedit.New(
		configedit.Target{LocalPath: path, Retention: 10},
		server.policyCatalog.(*catalog.ConfigCatalog), nil, observability.NewLogger("error"),
	))

	body := `{"updates":[{"target":"registry.example.com/gitlab-runner","ranges":[">=alpine-v19.5.3"]}]}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/tasks/semver-updates", bytes.NewBufferString(body))
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d %s, want 400", rec.Code, rec.Body.String())
	}
	var errBody map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &errBody); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(errBody["error"], ">=alpine-v19.5.3") {
		t.Fatalf("error does not name the range: %q", errBody["error"])
	}
	if got, _ := os.ReadFile(path); !bytes.Equal(got, original) {
		t.Fatalf("config changed:\n%s", got)
	}
	var cfg *config.RegsyncConfig = server.runningConfig()
	if r := cfg.Sync[0].Tags.SemverRange; len(r) != 1 || r[0] != ">=18.9.0" {
		t.Fatalf("running ranges = %v", r)
	}
}
