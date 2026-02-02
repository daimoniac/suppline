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
	"github.com/daimoniac/suppline/internal/types"
)

func TestHandleListTolerations_ReturnsAllConfiguredTolerations(t *testing.T) {
	// Create a regsync config with tolerations
	expiresAt := int64(1735689600) // 2025-01-01
	regsyncCfg := &config.RegsyncConfig{
		Version: 1,
		Defaults: config.Defaults{
			Tolerate: []types.CVEToleration{
				{ID: "CVE-2024-0001", Statement: "Default toleration 1", ExpiresAt: &expiresAt},
				{ID: "CVE-2024-0002", Statement: "Default toleration 2", ExpiresAt: nil},
			},
		},
		Sync: []config.SyncEntry{
			{
				Source: "docker.io/nginx:latest",
				Target: "myregistry.com/nginx:latest",
				Type:   "image",
				Tolerate: []types.CVEToleration{
					{ID: "CVE-2024-0003", Statement: "Sync-specific toleration", ExpiresAt: &expiresAt},
				},
			},
			{
				Source: "docker.io/alpine",
				Target: "myregistry.com/alpine",
				Type:   "repository",
				Tolerate: []types.CVEToleration{
					{ID: "CVE-2024-0004", Statement: "Alpine-specific toleration", ExpiresAt: nil},
				},
			},
		},
	}

	// Create mock state store (returns empty list - no historical data)
	mockStore := &mockStateStore{}

	cfg := &config.APIConfig{
		Enabled:  true,
		Port:     8080,
		APIKey:   "",
		ReadOnly: false,
	}

	server := NewAPIServer(cfg, mockAttestationConfig(), mockStore, queue.NewInMemoryQueue(100), regsyncCfg, observability.NewLogger("error"))

	// Test 1: Get all tolerations (no filter)
	t.Run("GetAllTolerations", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/tolerations", nil)
		w := httptest.NewRecorder()

		server.router.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("Expected status 200, got %d: %s", w.Code, w.Body.String())
		}

		var tolerations []*types.TolerationSummary
		if err := json.NewDecoder(w.Body).Decode(&tolerations); err != nil {
			t.Fatalf("Failed to decode response: %v", err)
		}

		// Expected: 4 unique CVE IDs (2 defaults + 1 nginx-specific + 1 alpine-specific)
		expectedCount := 4
		if len(tolerations) != expectedCount {
			t.Errorf("Expected %d unique CVE tolerations, got %d", expectedCount, len(tolerations))
			for i, tol := range tolerations {
				t.Logf("Toleration %d: %s (%d repos)", i, tol.CVEID, len(tol.Repositories))
			}
		}

		// Verify defaults appear for both repositories
		for _, tol := range tolerations {
			if tol.CVEID == "CVE-2024-0001" || tol.CVEID == "CVE-2024-0002" {
				// Default tolerations should apply to both nginx and alpine
				if len(tol.Repositories) != 2 {
					t.Errorf("Expected default CVE %s to have 2 repositories, got %d", tol.CVEID, len(tol.Repositories))
				}
			} else if tol.CVEID == "CVE-2024-0003" {
				// Nginx-specific should only have 1 repo
				if len(tol.Repositories) != 1 {
					t.Errorf("Expected nginx-specific CVE to have 1 repository, got %d", len(tol.Repositories))
				}
				if tol.Repositories[0].Repository != "myregistry.com/nginx" {
					t.Errorf("Expected nginx repository, got %s", tol.Repositories[0].Repository)
				}
			} else if tol.CVEID == "CVE-2024-0004" {
				// Alpine-specific should only have 1 repo
				if len(tol.Repositories) != 1 {
					t.Errorf("Expected alpine-specific CVE to have 1 repository, got %d", len(tol.Repositories))
				}
				if tol.Repositories[0].Repository != "myregistry.com/alpine" {
					t.Errorf("Expected alpine repository, got %s", tol.Repositories[0].Repository)
				}
			}
		}
	})

	// Test 2: Filter by repository
	t.Run("FilterByRepository", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/tolerations?repository=myregistry.com/nginx", nil)
		w := httptest.NewRecorder()

		server.router.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("Expected status 200, got %d: %s", w.Code, w.Body.String())
		}

		var tolerations []*types.TolerationSummary
		if err := json.NewDecoder(w.Body).Decode(&tolerations); err != nil {
			t.Fatalf("Failed to decode response: %v", err)
		}

		// Expected: 3 unique CVEs for nginx (2 defaults + 1 nginx-specific)
		expectedCount := 3
		if len(tolerations) != expectedCount {
			t.Errorf("Expected %d tolerations for nginx, got %d", expectedCount, len(tolerations))
		}

		// All should only have nginx repository
		for _, tol := range tolerations {
			if len(tol.Repositories) != 1 {
				t.Errorf("Expected 1 repository for filtered result, got %d", len(tol.Repositories))
			}
			if tol.Repositories[0].Repository != "myregistry.com/nginx" {
				t.Errorf("Expected nginx repository, got %s", tol.Repositories[0].Repository)
			}
		}
	})

	// Test 3: Filter by CVE ID
	t.Run("FilterByCVEID", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/tolerations?cve_id=CVE-2024-0001", nil)
		w := httptest.NewRecorder()

		server.router.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("Expected status 200, got %d: %s", w.Code, w.Body.String())
		}

		var tolerations []*types.TolerationSummary
		if err := json.NewDecoder(w.Body).Decode(&tolerations); err != nil {
			t.Fatalf("Failed to decode response: %v", err)
		}

		// Expected: 1 CVE with 2 repositories
		if len(tolerations) != 1 {
			t.Fatalf("Expected 1 toleration for CVE-2024-0001, got %d", len(tolerations))
		}

		tol := tolerations[0]
		if tol.CVEID != "CVE-2024-0001" {
			t.Errorf("Expected CVE-2024-0001, got %s", tol.CVEID)
		}

		// Should have both nginx and alpine repositories
		if len(tol.Repositories) != 2 {
			t.Errorf("Expected 2 repositories for CVE-2024-0001, got %d", len(tol.Repositories))
		}
	})
}

func TestHandleListTolerations_WithHistoricalData(t *testing.T) {
	// Create a regsync config with tolerations
	expiresAt := int64(1735689600) // 2025-01-01
	regsyncCfg := &config.RegsyncConfig{
		Version: 1,
		Defaults: config.Defaults{
			Tolerate: []types.CVEToleration{
				{ID: "CVE-2024-0001", Statement: "Default toleration 1", ExpiresAt: &expiresAt},
			},
		},
		Sync: []config.SyncEntry{
			{
				Source: "docker.io/nginx:latest",
				Target: "myregistry.com/nginx:latest",
				Type:   "image",
			},
		},
	}

	// Create mock state store with historical data
	toleratedAt := int64(1700000000)
	mockStore := &mockStateStoreWithHistory{
		tolerations: []*types.TolerationInfo{
			{
				CVEID:       "CVE-2024-0001",
				Statement:   "Old statement",
				ToleratedAt: toleratedAt,
				ExpiresAt:   nil,
				Repository:  "myregistry.com/nginx",
			},
		},
	}

	cfg := &config.APIConfig{
		Enabled:  true,
		Port:     8080,
		APIKey:   "",
		ReadOnly: false,
	}

	server := NewAPIServer(cfg, mockAttestationConfig(), mockStore, queue.NewInMemoryQueue(100), regsyncCfg, observability.NewLogger("error"))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/tolerations", nil)
	w := httptest.NewRecorder()

	server.router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	var tolerations []*types.TolerationSummary
	if err := json.NewDecoder(w.Body).Decode(&tolerations); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if len(tolerations) != 1 {
		t.Fatalf("Expected 1 toleration summary, got %d", len(tolerations))
	}

	tol := tolerations[0]

	// Should use statement and expires_at from current config
	if tol.Statement != "Default toleration 1" {
		t.Errorf("Expected statement from config, got %s", tol.Statement)
	}
	if tol.ExpiresAt == nil || *tol.ExpiresAt != expiresAt {
		t.Errorf("Expected expires_at from config, got %v", tol.ExpiresAt)
	}

	// Should have 1 repository
	if len(tol.Repositories) != 1 {
		t.Fatalf("Expected 1 repository, got %d", len(tol.Repositories))
	}

	// Should preserve historical tolerated_at timestamp for the repository
	repo := tol.Repositories[0]
	if repo.ToleratedAt != toleratedAt {
		t.Errorf("Expected historical ToleratedAt %d, got %d", toleratedAt, repo.ToleratedAt)
	}
	if repo.Repository != "myregistry.com/nginx" {
		t.Errorf("Expected nginx repository, got %s", repo.Repository)
	}
}

// mockStateStoreWithHistory extends mockStateStore to return historical tolerations
type mockStateStoreWithHistory struct {
	mockStateStore
	tolerations []*types.TolerationInfo
}

func (m *mockStateStoreWithHistory) ListTolerations(ctx context.Context, filter statestore.TolerationFilter) ([]*types.TolerationInfo, error) {
	result := make([]*types.TolerationInfo, 0)
	for _, tol := range m.tolerations {
		if filter.CVEID != "" && tol.CVEID != filter.CVEID {
			continue
		}
		if filter.Repository != "" && tol.Repository != filter.Repository {
			continue
		}
		result = append(result, tol)
	}
	return result, nil
}
