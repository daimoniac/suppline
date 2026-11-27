package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/daimoniac/suppline/internal/config"
	"github.com/daimoniac/suppline/internal/observability"
	"github.com/daimoniac/suppline/internal/queue"
	"github.com/daimoniac/suppline/internal/statestore"
)

func migrationServer(t *testing.T) *APIServer {
	t.Helper()
	store := &mockClusterInventoryStore{
		mockStateStore: &mockStateStore{},
		summaries:      []statestore.ClusterSummary{{Name: "prod-a", ImageCount: 3}},
		clusterImages: []statestore.ClusterImageSummary{
			{Namespace: "web", ImageRef: "nginx", Tag: "1.27"},
			{Namespace: "web", ImageRef: "redis", Tag: "7"},
			{Namespace: "web", ImageRef: "harbor.example.com/suppline/curl", Tag: "8"},
		},
	}
	regsync := &config.RegsyncConfig{
		Version: 1,
		Sync:    []config.SyncEntry{{Source: "redis", Target: "harbor.example.com/suppline/redis", Type: "repository"}},
	}
	cfg := &config.APIConfig{Port: 8080}
	return NewAPIServer(cfg, mockAttestationConfig(), store, queue.NewInMemoryQueue(100), regsync, observability.NewLogger("error"))
}

func TestGetClusterMigrationPlansOnlyWhatIsMissing(t *testing.T) {
	t.Setenv("SUPPLINE_REGISTRY_URL", "harbor.example.com/suppline")
	server := migrationServer(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/integration/kubernetes/clusters/prod-a/migration", nil)
	w := httptest.NewRecorder()
	server.router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	for _, want := range []string{
		"source: docker.io/library/nginx:1.27",
		`target: '{{ env "SUPPLINE_REGISTRY_URL" }}/nginx:1.27'`,
		"# 1 to add, 1 already synced, 1 already pulled from the mirror.",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("body missing %q:\n%s", want, body)
		}
	}
	for _, unwanted := range []string{"redis:7\n", "curl"} {
		if strings.Contains(body, "source: "+unwanted) || strings.Contains(body, "    "+unwanted) {
			t.Errorf("body should not suggest %q:\n%s", unwanted, body)
		}
	}
}

func TestGetClusterMigrationWritesLiteralTargetsForAnExplicitMirror(t *testing.T) {
	server := migrationServer(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/integration/kubernetes/clusters/prod-a/migration?mirror=reg.example.org/team/", nil)
	w := httptest.NewRecorder()
	server.router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "target: 'reg.example.org/team/nginx:1.27'") {
		t.Fatalf("body:\n%s", w.Body.String())
	}
}

func TestGetClusterMigrationUnknownCluster(t *testing.T) {
	server := migrationServer(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/integration/kubernetes/clusters/nowhere/migration", nil)
	w := httptest.NewRecorder()
	server.router.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404: %s", w.Code, w.Body.String())
	}
}

func TestGenerateMirrorRewritePolicy(t *testing.T) {
	t.Setenv("SUPPLINE_REGISTRY_URL", "harbor.example.com/suppline")
	server := migrationServer(t)

	get := func(query string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/integration/kyverno/mirror-rewrite"+query, nil)
		w := httptest.NewRecorder()
		server.router.ServeHTTP(w, req)
		return w
	}

	w := get("?registries=docker.io,ghcr.io")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", w.Code, w.Body.String())
	}
	for _, want := range []string{"kind: MutatingPolicy", "'harbor.example.com/suppline'", "['ghcr.io', 'index.docker.io']", "suppline.cloud/mirror"} {
		if !strings.Contains(w.Body.String(), want) {
			t.Errorf("body missing %q:\n%s", want, w.Body.String())
		}
	}

	if w := get("?scope=all&mirror=other.example.com"); w.Code != http.StatusOK || strings.Contains(w.Body.String(), "namespaceSelector") {
		t.Errorf("scope=all: status %d, body:\n%s", w.Code, w.Body.String())
	}
	if w := get("?scope=nope"); w.Code != http.StatusBadRequest {
		t.Errorf("bad scope: status = %d", w.Code)
	}
	if w := get("?registries=a%27b"); w.Code != http.StatusBadRequest {
		t.Errorf("bad registry: status = %d", w.Code)
	}

	t.Setenv("SUPPLINE_REGISTRY_URL", "")
	if w := get(""); w.Code != http.StatusBadRequest {
		t.Errorf("no mirror: status = %d", w.Code)
	}
}

func TestGetClusterMigrationExcludesRegistries(t *testing.T) {
	t.Setenv("SUPPLINE_REGISTRY_URL", "harbor.example.com/suppline")
	server := migrationServer(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/integration/kubernetes/clusters/prod-a/migration?exclude=docker.io", nil)
	w := httptest.NewRecorder()
	server.router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "nginx") {
		t.Errorf("docker.io images must be left out:\n%s", w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "# 0 to add") {
		t.Errorf("expected nothing to add:\n%s", w.Body.String())
	}
}

func TestKyvernoPolicyRejectsInvalidPodsOnly(t *testing.T) {
	server := migrationServer(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/integration/kyverno/policy?pods_only=maybe", nil)
	w := httptest.NewRecorder()
	server.router.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400: %s", w.Code, w.Body.String())
	}
}
