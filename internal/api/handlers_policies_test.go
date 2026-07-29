package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/daimoniac/suppline/internal/config"
	"github.com/daimoniac/suppline/internal/observability"
	"github.com/daimoniac/suppline/internal/queue"
	"github.com/daimoniac/suppline/internal/statestore"
)

func TestHandleListPolicies_NoDefault(t *testing.T) {
	cfg := &config.APIConfig{Enabled: true, Port: 8080}
	server := NewAPIServer(cfg, mockAttestationConfig(), &mockStateStore{}, queue.NewInMemoryQueue(100), mockRegsyncConfig(), observability.NewLogger("error"))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/policies", nil)
	w := httptest.NewRecorder()
	server.router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp PoliciesResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.Default != nil {
		t.Fatalf("expected nil Default, got %+v", resp.Default)
	}
	if len(resp.Repositories) != 0 {
		t.Fatalf("expected no repository overrides, got %+v", resp.Repositories)
	}
}

func TestHandleListPolicies_DefaultAndOverrides(t *testing.T) {
	cfg := &config.APIConfig{Enabled: true, Port: 8080}
	regsync := &config.RegsyncConfig{
		Version: 1,
		Defaults: config.Defaults{
			Policy: &config.PolicyConfig{
				Expression: "criticalCount == 0",
			},
		},
		Sync: []config.SyncEntry{
			{
				Source: "nginx",
				Target: "myregistry/nginx",
				Type:   "repository",
				Policy: &config.PolicyConfig{
					Expression: "criticalCount == 0 && highCount == 0",
				},
			},
			{
				Source: "redis",
				Target: "myregistry/redis",
				Type:   "repository",
				// inherits default — not listed under Repositories
			},
		},
	}
	server := NewAPIServer(cfg, mockAttestationConfig(), &mockStateStore{}, queue.NewInMemoryQueue(100), regsync, observability.NewLogger("error"))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/policies", nil)
	w := httptest.NewRecorder()
	server.router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp PoliciesResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.Default == nil {
		t.Fatal("expected Default policy")
	}
	if resp.Default.Expression != "criticalCount == 0" {
		t.Fatalf("Default.Expression = %q", resp.Default.Expression)
	}
	if resp.Default.Description != "No critical vulnerabilities" {
		t.Fatalf("Default.Description = %q", resp.Default.Description)
	}
	if len(resp.Repositories) != 1 {
		t.Fatalf("expected 1 override, got %+v", resp.Repositories)
	}
	nginx := resp.Repositories["myregistry/nginx"]
	if nginx.Expression != "criticalCount == 0 && highCount == 0" {
		t.Fatalf("nginx Expression = %q", nginx.Expression)
	}
	if nginx.Description != "No critical or high vulnerabilities" {
		t.Fatalf("nginx Description = %q", nginx.Description)
	}
}

func TestHandleListRepositories_EnrichesPolicyDescription(t *testing.T) {
	cfg := &config.APIConfig{Enabled: true, Port: 8080}
	regsync := &config.RegsyncConfig{
		Version: 1,
		Defaults: config.Defaults{
			Policy: &config.PolicyConfig{Expression: "criticalCount == 0"},
		},
		Sync: []config.SyncEntry{
			{
				Source: "nginx",
				Target: "myregistry/nginx",
				Type:   "repository",
				Policy: &config.PolicyConfig{Expression: "criticalCount == 0 && highCount == 0"},
			},
		},
	}
	store := &policyReposMockStore{}
	server := NewAPIServer(cfg, mockAttestationConfig(), store, queue.NewInMemoryQueue(100), regsync, observability.NewLogger("error"))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/repositories", nil)
	w := httptest.NewRecorder()
	server.router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp statestore.RepositoriesListResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(resp.Repositories) != 2 {
		t.Fatalf("expected 2 repos, got %d", len(resp.Repositories))
	}

	byName := map[string]statestore.RepositoryInfo{}
	for _, r := range resp.Repositories {
		byName[r.Name] = r
	}

	nginx := byName["myregistry/nginx"]
	if nginx.PolicyDescription != "No critical or high vulnerabilities" {
		t.Fatalf("nginx PolicyDescription = %q", nginx.PolicyDescription)
	}
	if nginx.PolicyExpression != "criticalCount == 0 && highCount == 0" {
		t.Fatalf("nginx PolicyExpression = %q", nginx.PolicyExpression)
	}

	redis := byName["myregistry/redis"]
	if redis.PolicyDescription != "No critical vulnerabilities" {
		t.Fatalf("redis PolicyDescription = %q (expected default)", redis.PolicyDescription)
	}
}

// policyReposMockStore embeds mockStateStore and returns named repositories for enrichment tests.
type policyReposMockStore struct {
	mockStateStore
}

func (m *policyReposMockStore) ListRepositories(ctx context.Context, filter statestore.RepositoryFilter) (*statestore.RepositoriesListResponse, error) {
	return &statestore.RepositoriesListResponse{
		Repositories: []statestore.RepositoryInfo{
			{Name: "myregistry/nginx", PolicyPassed: true, PolicyStatus: "passed"},
			{Name: "myregistry/redis", PolicyPassed: true, PolicyStatus: "passed"},
		},
		Total: 2,
	}, nil
}
