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

		var vexStatements []*types.VEXSummary
		if err := json.NewDecoder(w.Body).Decode(&vexStatements); err != nil {
			t.Fatalf("Failed to decode response: %v", err)
		}

		// Expected: 4 unique CVE IDs (2 defaults + 1 nginx-specific + 1 alpine-specific)
		expectedCount := 4
		if len(vexStatements) != expectedCount {
			t.Errorf("Expected %d unique CVE VEX statements, got %d", expectedCount, len(vexStatements))
			for i, stmt := range vexStatements {
				t.Logf("VEX statement %d: %s (%d repos)", i, stmt.CVEID, len(stmt.Repositories))
			}
		}

		// Verify defaults appear for both repositories
		for _, stmt := range vexStatements {
			if stmt.CVEID == "CVE-2024-0001" || stmt.CVEID == "CVE-2024-0002" {
				// Default VEX statements should apply to both nginx and alpine
				if len(stmt.Repositories) != 2 {
					t.Errorf("Expected default CVE %s to have 2 repositories, got %d", stmt.CVEID, len(stmt.Repositories))
				}
			} else if stmt.CVEID == "CVE-2024-0003" {
				// Nginx-specific should only have 1 repo
				if len(stmt.Repositories) != 1 {
					t.Errorf("Expected nginx-specific CVE to have 1 repository, got %d", len(stmt.Repositories))
				}
				if stmt.Repositories[0].Repository != "myregistry.com/nginx" {
					t.Errorf("Expected nginx repository, got %s", stmt.Repositories[0].Repository)
				}
			} else if stmt.CVEID == "CVE-2024-0004" {
				// Alpine-specific should only have 1 repo
				if len(stmt.Repositories) != 1 {
					t.Errorf("Expected alpine-specific CVE to have 1 repository, got %d", len(stmt.Repositories))
				}
				if stmt.Repositories[0].Repository != "myregistry.com/alpine" {
					t.Errorf("Expected alpine repository, got %s", stmt.Repositories[0].Repository)
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

		var vexStatements []*types.VEXSummary
		if err := json.NewDecoder(w.Body).Decode(&vexStatements); err != nil {
			t.Fatalf("Failed to decode response: %v", err)
		}

		// Expected: 3 unique CVEs for nginx (2 defaults + 1 nginx-specific)
		expectedCount := 3
		if len(vexStatements) != expectedCount {
			t.Errorf("Expected %d VEX statements for nginx, got %d", expectedCount, len(vexStatements))
		}

		// All should only have nginx repository
		for _, stmt := range vexStatements {
			if len(stmt.Repositories) != 1 {
				t.Errorf("Expected 1 repository for filtered result, got %d", len(stmt.Repositories))
			}
			if stmt.Repositories[0].Repository != "myregistry.com/nginx" {
				t.Errorf("Expected nginx repository, got %s", stmt.Repositories[0].Repository)
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

		var vexStatements []*types.VEXSummary
		if err := json.NewDecoder(w.Body).Decode(&vexStatements); err != nil {
			t.Fatalf("Failed to decode response: %v", err)
		}

		// Expected: 1 CVE with 2 repositories
		if len(vexStatements) != 1 {
			t.Fatalf("Expected 1 VEX statement for CVE-2024-0001, got %d", len(vexStatements))
		}

		stmt := vexStatements[0]
		if stmt.CVEID != "CVE-2024-0001" {
			t.Errorf("Expected CVE-2024-0001, got %s", stmt.CVEID)
		}

		// Should have both nginx and alpine repositories
		if len(stmt.Repositories) != 2 {
			t.Errorf("Expected 2 repositories for CVE-2024-0001, got %d", len(stmt.Repositories))
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
	appliedAt := int64(1700000000)
	mockStore := &mockStateStoreWithHistory{
		vexInfos: []*types.VEXInfo{
			{
				CVEID:      "CVE-2024-0001",
				State:      types.VEXStateNotAffected,
				Detail:     "Old statement",
				AppliedAt:  appliedAt,
				ExpiresAt:  nil,
				Repository: "myregistry.com/nginx",
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

	var vexStatements []*types.VEXSummary
	if err := json.NewDecoder(w.Body).Decode(&vexStatements); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if len(vexStatements) != 1 {
		t.Fatalf("Expected 1 VEX summary, got %d", len(vexStatements))
	}

	stmt := vexStatements[0]

	// Should use detail and expires_at from current config
	if stmt.Detail != "Default toleration 1" {
		t.Errorf("Expected detail from config, got %s", stmt.Detail)
	}
	if stmt.ExpiresAt == nil || *stmt.ExpiresAt != expiresAt {
		t.Errorf("Expected expires_at from config, got %v", stmt.ExpiresAt)
	}

	// Should have 1 repository
	if len(stmt.Repositories) != 1 {
		t.Fatalf("Expected 1 repository, got %d", len(stmt.Repositories))
	}

	// Should preserve historical AppliedAt timestamp for the repository
	repo := stmt.Repositories[0]
	if repo.AppliedAt != appliedAt {
		t.Errorf("Expected historical AppliedAt %d, got %d", appliedAt, repo.AppliedAt)
	}
	if repo.Repository != "myregistry.com/nginx" {
		t.Errorf("Expected nginx repository, got %s", repo.Repository)
	}
}

// mockStateStoreWithHistory extends mockStateStore to return historical VEX statements
type mockStateStoreWithHistory struct {
	mockStateStore
	vexInfos []*types.VEXInfo
}

func (m *mockStateStoreWithHistory) ListVEXStatements(ctx context.Context, filter statestore.TolerationFilter) ([]*types.VEXInfo, error) {
	result := make([]*types.VEXInfo, 0)
	for _, stmt := range m.vexInfos {
		if filter.CVEID != "" && stmt.CVEID != filter.CVEID {
			continue
		}
		if filter.Repository != "" && stmt.Repository != filter.Repository {
			continue
		}
		result = append(result, stmt)
	}
	return result, nil
}
func (m *mockStateStoreWithHistory) GetUniqueVulnerabilityCounts(ctx context.Context) (map[string]int, error) {
	return map[string]int{
		"CRITICAL": 5,
		"HIGH":     10,
		"MEDIUM":   15,
		"LOW":      20,
	}, nil
}

func TestHandleGetVulnerabilityStats(t *testing.T) {
	mockStore := &mockStateStoreWithHistory{}
	cfg := &config.APIConfig{Enabled: true}
	server := NewAPIServer(cfg, nil, mockStore, nil, nil, observability.NewLogger("error"))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/vulnerabilities/stats", nil)
	w := httptest.NewRecorder()

	server.router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected status 200, got %d", w.Code)
	}

	var counts map[string]int
	if err := json.NewDecoder(w.Body).Decode(&counts); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if counts["CRITICAL"] != 5 || counts["HIGH"] != 10 {
		t.Errorf("Unexpected counts: %v", counts)
	}
}
