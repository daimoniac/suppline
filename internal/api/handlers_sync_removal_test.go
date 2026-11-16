package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/daimoniac/suppline/internal/config"
	"github.com/daimoniac/suppline/internal/configedit"
	"github.com/daimoniac/suppline/internal/observability"
	"github.com/daimoniac/suppline/internal/policy/catalog"
	"github.com/daimoniac/suppline/internal/statestore"
)

// cleanupRecorder is a state store that records repository cleanups.
type cleanupRecorder struct {
	*mockStateStore
	cleaned []string
}

func (c *cleanupRecorder) CleanupArtifactScans(context.Context, string) error { return nil }
func (c *cleanupRecorder) CleanupArtifactTag(context.Context, string, string, string) error {
	return nil
}
func (c *cleanupRecorder) CleanupRepository(_ context.Context, repository string) error {
	c.cleaned = append(c.cleaned, repository)
	return nil
}
func (c *cleanupRecorder) ListArtifactTags(context.Context, string) ([]statestore.ArtifactTagBinding, error) {
	return nil, nil
}
func (c *cleanupRecorder) ListStoredRepositoryNames(context.Context) ([]string, error) {
	return nil, nil
}
func (c *cleanupRecorder) CleanupOrphanedRepositories(context.Context) ([]string, error) {
	return nil, nil
}
func (c *cleanupRecorder) CleanupExcessScans(context.Context, string, int) error { return nil }

// internal-1, 2026-11-16: hostingmaloonde/alpine_helm was removed from the config,
// then a watcher still on its startup configuration rediscovered the repository.
// It stayed in the unused-repositories task, and every further removal failed
// with "no matching config entries" before its state was cleaned.
func TestRemoveSyncTargetsCleansRepositoryAlreadyGoneFromConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "suppline.yml")
	original := []byte(`version: 1
sync:
  - source: docker.io/nginx
    target: registry.example.com/nginx
    type: repository
  - source: docker.io/alpine/helm
    target: registry.example.com/alpine_helm
    type: repository
`)
	if err := os.WriteFile(path, original, 0o644); err != nil {
		t.Fatal(err)
	}
	regsync := &config.RegsyncConfig{Version: 1, Sync: []config.SyncEntry{
		{Source: "docker.io/nginx", Target: "registry.example.com/nginx", Type: "repository"},
		{Source: "docker.io/alpine/helm", Target: "registry.example.com/alpine_helm", Type: "repository"},
	}}
	store := &cleanupRecorder{mockStateStore: &mockStateStore{}}
	server := tasksTestServer(t, store, regsync)
	server.SetConfigEditor(configedit.New(
		configedit.Target{LocalPath: path, Retention: 10},
		server.policyCatalog.(*catalog.ConfigCatalog), nil, observability.NewLogger("error"),
	))
	remove := func(body string) (int, ConfigEditResult, string) {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, "/api/v1/tasks/sync-removals", bytes.NewBufferString(body))
		rec := httptest.NewRecorder()
		server.router.ServeHTTP(rec, req)
		var result ConfigEditResult
		_ = json.Unmarshal(rec.Body.Bytes(), &result)
		return rec.Code, result, rec.Body.String()
	}

	code, first, body := remove(`{"targets":["registry.example.com/alpine_helm"]}`)
	if code != http.StatusOK || first.Updated != 1 || first.Cleaned != 0 {
		t.Fatalf("first removal: %d %s", code, body)
	}
	written, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	// The repository came back in suppline's state; the config no longer has it.
	store.cleaned = nil
	code, second, body := remove(`{"targets":["registry.example.com/alpine_helm"]}`)
	if code != http.StatusOK || second.Updated != 0 || second.Cleaned != 1 {
		t.Fatalf("second removal: %d %s, want 200 with cleaned 1", code, body)
	}
	if len(store.cleaned) != 1 || store.cleaned[0] != "registry.example.com/alpine_helm" {
		t.Fatalf("cleaned repositories = %v", store.cleaned)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(written) {
		t.Fatalf("config changed on the second removal:\n%s", after)
	}

	// A mix edits the file for the configured target and cleans both.
	store.cleaned = nil
	code, mixed, body := remove(`{"targets":["registry.example.com/nginx","registry.example.com/alpine_helm"]}`)
	if code != http.StatusOK || mixed.Updated != 1 || mixed.Cleaned != 1 {
		t.Fatalf("mixed removal: %d %s", code, body)
	}
	if len(store.cleaned) != 2 {
		t.Fatalf("cleaned repositories = %v, want both", store.cleaned)
	}
	if running := server.runningConfig(); len(running.Sync) != 0 {
		t.Fatalf("running sync = %+v, want empty", running.Sync)
	}
}
