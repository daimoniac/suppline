package api

import (
	"context"
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

// mockStateStore is a minimal mock for testing
type mockStateStore struct{}

// mockAttestationConfig returns a minimal attestation config for testing
func mockAttestationConfig() *config.AttestationConfig {
	return &config.AttestationConfig{
		KeyBased: struct {
			Key string
		}{
			Key: "",
		},
	}
}

func (m *mockStateStore) RecordScan(ctx context.Context, record *statestore.ScanRecord) error {
	return nil
}

func (m *mockStateStore) GetLastScan(ctx context.Context, digest string) (*statestore.ScanRecord, error) {
	return nil, nil
}

func (m *mockStateStore) ListDueForRescan(ctx context.Context, interval time.Duration) ([]string, error) {
	return nil, nil
}

func (m *mockStateStore) GetScanHistory(ctx context.Context, digest string, limit int) ([]*statestore.ScanRecord, error) {
	return nil, nil
}

func (m *mockStateStore) QueryVulnerabilities(ctx context.Context, filter statestore.VulnFilter) ([]*types.VulnerabilityRecord, error) {
	return nil, nil
}

func (m *mockStateStore) GetImagesByCVE(ctx context.Context, cveID string) ([]*statestore.ScanRecord, error) {
	return nil, nil
}

func (m *mockStateStore) ListScans(ctx context.Context, filter statestore.ScanFilter) ([]*statestore.ScanRecord, error) {
	return nil, nil
}

func (m *mockStateStore) ListTolerations(ctx context.Context, filter statestore.TolerationFilter) ([]*types.TolerationInfo, error) {
	return nil, nil
}

func (m *mockStateStore) ListRepositories(ctx context.Context, filter statestore.RepositoryFilter) (*statestore.RepositoriesListResponse, error) {
	return &statestore.RepositoriesListResponse{
		Repositories: []statestore.RepositoryInfo{},
		Total:        0,
	}, nil
}

func (m *mockStateStore) GetRepository(ctx context.Context, name string, filter statestore.RepositoryTagFilter) (*statestore.RepositoryDetail, error) {
	// Return a repository with at least one tag so it's not considered "not found"
	now := time.Now()
	return &statestore.RepositoryDetail{
		Name: name,
		Tags: []statestore.TagInfo{
			{
				Name:       "latest",
				Digest:     "sha256:abc123",
				LastScanTime: &now,
				NextScanTime: &now,
				VulnerabilityCount: statestore.VulnerabilityCountSummary{
					Critical:  1,
					High:      2,
					Medium:    3,
					Low:       1,
					Tolerated: 0,
				},
				PolicyPassed: true,
			},
		},
		Total: 1,
	}, nil
}

func TestNewAPIServer(t *testing.T) {
	cfg := &config.APIConfig{
		Enabled:  true,
		Port:     8080,
		APIKey:   "",
		ReadOnly: false,
	}

	store := &mockStateStore{}
	queue := queue.NewInMemoryQueue(100)
	regsyncPath := "suppline.yml"
	logger := observability.NewLogger("error")

	server := NewAPIServer(cfg, mockAttestationConfig(), store, queue, regsyncPath, logger)

	if server == nil {
		t.Fatal("Expected server to be created")
	}

	if server.config != cfg {
		t.Error("Expected config to be set")
	}

	if server.stateStore != store {
		t.Error("Expected state store to be set")
	}

	if server.taskQueue != queue {
		t.Error("Expected task queue to be set")
	}

	if server.regsyncPath != regsyncPath {
		t.Error("Expected regsync path to be set")
	}

	if server.router == nil {
		t.Error("Expected router to be initialized")
	}

	if server.server == nil {
		t.Error("Expected HTTP server to be initialized")
	}
}

func TestAuthMiddleware_NoAPIKey(t *testing.T) {
	cfg := &config.APIConfig{
		Enabled:  true,
		Port:     8080,
		APIKey:   "", // No API key required
		ReadOnly: false,
	}

	server := NewAPIServer(cfg, mockAttestationConfig(), &mockStateStore{}, queue.NewInMemoryQueue(100), "suppline.yml", observability.NewLogger("error"))

	// Test that requests pass through without authentication
	req := httptest.NewRequest(http.MethodGet, "/api/v1/scans", nil)
	w := httptest.NewRecorder()

	handler := server.authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}, false)

	handler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}
}

func TestAuthMiddleware_WithAPIKey_Valid(t *testing.T) {
	cfg := &config.APIConfig{
		Enabled:  true,
		Port:     8080,
		APIKey:   "test-api-key",
		ReadOnly: false,
	}

	server := NewAPIServer(cfg, mockAttestationConfig(), &mockStateStore{}, queue.NewInMemoryQueue(100), "suppline.yml", observability.NewLogger("error"))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/scans", nil)
	req.Header.Set("Authorization", "Bearer test-api-key")
	w := httptest.NewRecorder()

	handler := server.authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}, false)

	handler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}
}

func TestAuthMiddleware_WithAPIKey_Invalid(t *testing.T) {
	cfg := &config.APIConfig{
		Enabled:  true,
		Port:     8080,
		APIKey:   "test-api-key",
		ReadOnly: false,
	}

	server := NewAPIServer(cfg, mockAttestationConfig(), &mockStateStore{}, queue.NewInMemoryQueue(100), "suppline.yml", observability.NewLogger("error"))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/scans", nil)
	req.Header.Set("Authorization", "Bearer wrong-key")
	w := httptest.NewRecorder()

	handler := server.authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}, false)

	handler(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401, got %d", w.Code)
	}
}

func TestAuthMiddleware_WithAPIKey_Missing(t *testing.T) {
	cfg := &config.APIConfig{
		Enabled:  true,
		Port:     8080,
		APIKey:   "test-api-key",
		ReadOnly: false,
	}

	server := NewAPIServer(cfg, mockAttestationConfig(), &mockStateStore{}, queue.NewInMemoryQueue(100), "suppline.yml", observability.NewLogger("error"))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/scans", nil)
	// No Authorization header
	w := httptest.NewRecorder()

	handler := server.authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}, false)

	handler(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401, got %d", w.Code)
	}
}

func TestAuthMiddleware_ReadOnlyMode(t *testing.T) {
	cfg := &config.APIConfig{
		Enabled:  true,
		Port:     8080,
		APIKey:   "",
		ReadOnly: true,
	}

	server := NewAPIServer(cfg, mockAttestationConfig(), &mockStateStore{}, queue.NewInMemoryQueue(100), "suppline.yml", observability.NewLogger("error"))

	// Test read operation (should pass)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/scans", nil)
	w := httptest.NewRecorder()

	handler := server.authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}, false)

	handler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200 for read operation, got %d", w.Code)
	}

	// Test write operation (should fail)
	req = httptest.NewRequest(http.MethodPost, "/api/v1/scans/trigger", nil)
	w = httptest.NewRecorder()

	handler = server.authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}, true)

	handler(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("Expected status 403 for write operation in read-only mode, got %d", w.Code)
	}
}

func TestRoutes_QueryEndpoints(t *testing.T) {
	cfg := &config.APIConfig{
		Enabled:  true,
		Port:     8080,
		APIKey:   "",
		ReadOnly: false,
	}

	server := NewAPIServer(cfg, mockAttestationConfig(), &mockStateStore{}, queue.NewInMemoryQueue(100), "suppline.yml", observability.NewLogger("error"))

	tests := []struct {
		name   string
		path   string
		method string
	}{
		{"GetScan", "/api/v1/scans/sha256:abc123", http.MethodGet},
		{"ListScans", "/api/v1/scans", http.MethodGet},
		{"QueryVulnerabilities", "/api/v1/vulnerabilities", http.MethodGet},
		{"ListTolerations", "/api/v1/tolerations", http.MethodGet},
		{"ListFailedImages", "/api/v1/images/failed", http.MethodGet},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, nil)
			w := httptest.NewRecorder()

			server.router.ServeHTTP(w, req)

			// Query endpoints should now return 200 or 404 (implemented)
			// GetScan with invalid digest returns 404, others return 200 with empty arrays
			if w.Code != http.StatusOK && w.Code != http.StatusNotFound {
				t.Errorf("Expected status 200 or 404, got %d", w.Code)
			}
		})
	}
}

func TestRoutes_ActionEndpoints(t *testing.T) {
	cfg := &config.APIConfig{
		Enabled:  true,
		Port:     8080,
		APIKey:   "",
		ReadOnly: false,
	}

	server := NewAPIServer(cfg, mockAttestationConfig(), &mockStateStore{}, queue.NewInMemoryQueue(100), "suppline.yml", observability.NewLogger("error"))

	tests := []struct {
		name   string
		path   string
		method string
	}{
		{"TriggerScan", "/api/v1/scans/trigger", http.MethodPost},
		{"ReevaluatePolicy", "/api/v1/policy/reevaluate", http.MethodPost},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, nil)
			w := httptest.NewRecorder()

			server.router.ServeHTTP(w, req)

			// Should return 400 Bad Request (missing required fields) or 404 (no data)
			// Not 501 anymore since we implemented the handlers
			if w.Code != http.StatusBadRequest && w.Code != http.StatusNotFound && w.Code != http.StatusInternalServerError {
				t.Errorf("Expected status 400, 404, or 500, got %d", w.Code)
			}
		})
	}
}

func TestHealthEndpoint(t *testing.T) {
	cfg := &config.APIConfig{
		Enabled:  true,
		Port:     8080,
		APIKey:   "",
		ReadOnly: false,
	}

	server := NewAPIServer(cfg, mockAttestationConfig(), &mockStateStore{}, queue.NewInMemoryQueue(100), "suppline.yml", observability.NewLogger("error"))

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()

	server.router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	// Check response contains status
	body := w.Body.String()
	if body == "" {
		t.Error("Expected non-empty response body")
	}
}

func TestMetricsEndpoint(t *testing.T) {
	cfg := &config.APIConfig{
		Enabled:  true,
		Port:     8080,
		APIKey:   "",
		ReadOnly: false,
	}

	server := NewAPIServer(cfg, mockAttestationConfig(), &mockStateStore{}, queue.NewInMemoryQueue(100), "suppline.yml", observability.NewLogger("error"))

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	w := httptest.NewRecorder()

	server.router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	// Check content type
	contentType := w.Header().Get("Content-Type")
	if contentType != "text/plain" {
		t.Errorf("Expected Content-Type text/plain, got %s", contentType)
	}
}

func TestHandleTriggerScan_MissingFields(t *testing.T) {
	cfg := &config.APIConfig{
		Enabled:  true,
		Port:     8080,
		APIKey:   "",
		ReadOnly: false,
	}

	server := NewAPIServer(cfg, mockAttestationConfig(), &mockStateStore{}, queue.NewInMemoryQueue(100), "suppline.yml", observability.NewLogger("error"))

	// Test with empty body
	req := httptest.NewRequest(http.MethodPost, "/api/v1/scans/trigger", strings.NewReader("{}"))
	w := httptest.NewRecorder()

	server.router.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400 for empty body, got %d", w.Code)
	}
}

func TestHandleTriggerScan_BothFields(t *testing.T) {
	cfg := &config.APIConfig{
		Enabled:  true,
		Port:     8080,
		APIKey:   "",
		ReadOnly: false,
	}

	server := NewAPIServer(cfg, mockAttestationConfig(), &mockStateStore{}, queue.NewInMemoryQueue(100), "suppline.yml", observability.NewLogger("error"))

	// Test with both digest and repository
	body := `{"digest": "sha256:abc123", "repository": "test/repo"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/scans/trigger", strings.NewReader(body))
	w := httptest.NewRecorder()

	server.router.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400 for both fields, got %d", w.Code)
	}
}

func TestHandleTriggerScan_InvalidJSON(t *testing.T) {
	cfg := &config.APIConfig{
		Enabled:  true,
		Port:     8080,
		APIKey:   "",
		ReadOnly: false,
	}

	server := NewAPIServer(cfg, mockAttestationConfig(), &mockStateStore{}, queue.NewInMemoryQueue(100), "suppline.yml", observability.NewLogger("error"))

	// Test with invalid JSON
	req := httptest.NewRequest(http.MethodPost, "/api/v1/scans/trigger", strings.NewReader("invalid json"))
	w := httptest.NewRecorder()

	server.router.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400 for invalid JSON, got %d", w.Code)
	}
}

func TestHandleReevaluatePolicy_EmptyBody(t *testing.T) {
	cfg := &config.APIConfig{
		Enabled:  true,
		Port:     8080,
		APIKey:   "",
		ReadOnly: false,
	}

	server := NewAPIServer(cfg, mockAttestationConfig(), &mockStateStore{}, queue.NewInMemoryQueue(100), "suppline.yml", observability.NewLogger("error"))

	// Test with empty body (should be acceptable)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/policy/reevaluate", nil)
	w := httptest.NewRecorder()

	server.router.ServeHTTP(w, req)

	// Should return 404 or 500 (no scans found or regsync file not found)
	if w.Code != http.StatusNotFound && w.Code != http.StatusInternalServerError {
		t.Errorf("Expected status 404 or 500, got %d", w.Code)
	}
}

func TestHandleReevaluatePolicy_WithRepository(t *testing.T) {
	cfg := &config.APIConfig{
		Enabled:  true,
		Port:     8080,
		APIKey:   "",
		ReadOnly: false,
	}

	server := NewAPIServer(cfg, mockAttestationConfig(), &mockStateStore{}, queue.NewInMemoryQueue(100), "suppline.yml", observability.NewLogger("error"))

	// Test with repository filter
	body := `{"repository": "test/repo"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/policy/reevaluate", strings.NewReader(body))
	w := httptest.NewRecorder()

	server.router.ServeHTTP(w, req)

	// Should return 404 or 500 (no scans found or regsync file not found)
	if w.Code != http.StatusNotFound && w.Code != http.StatusInternalServerError {
		t.Errorf("Expected status 404 or 500, got %d", w.Code)
	}
}

func TestActionEndpoints_ReadOnlyMode(t *testing.T) {
	cfg := &config.APIConfig{
		Enabled:  true,
		Port:     8080,
		APIKey:   "",
		ReadOnly: true,
	}

	server := NewAPIServer(cfg, mockAttestationConfig(), &mockStateStore{}, queue.NewInMemoryQueue(100), "suppline.yml", observability.NewLogger("error"))

	tests := []struct {
		name string
		path string
		body string
	}{
		{"TriggerScan", "/api/v1/scans/trigger", `{"digest": "sha256:abc123"}`},
		{"ReevaluatePolicy", "/api/v1/policy/reevaluate", `{}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, tt.path, strings.NewReader(tt.body))
			w := httptest.NewRecorder()

			server.router.ServeHTTP(w, req)

			if w.Code != http.StatusForbidden {
				t.Errorf("Expected status 403 for read-only mode, got %d", w.Code)
			}
		})
	}
}

func TestHandleGetRepository_Success(t *testing.T) {
	cfg := &config.APIConfig{
		Enabled:  true,
		Port:     8080,
		APIKey:   "",
		ReadOnly: false,
	}

	// Create a mock state store that returns repository details
	mockStore := &mockStateStore{}
	server := NewAPIServer(cfg, mockAttestationConfig(), mockStore, queue.NewInMemoryQueue(100), "suppline.yml", observability.NewLogger("error"))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/repositories/test-repo", nil)
	w := httptest.NewRecorder()

	server.router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	// Verify response contains repository detail structure
	body := w.Body.String()
	if !strings.Contains(body, "test-repo") {
		t.Errorf("Expected response to contain repository name")
	}
}

// emptyRepositoryMockStore returns empty repositories
type emptyRepositoryMockStore struct {
	*mockStateStore
}

func (m *emptyRepositoryMockStore) GetRepository(ctx context.Context, name string, filter statestore.RepositoryTagFilter) (*statestore.RepositoryDetail, error) {
	return &statestore.RepositoryDetail{
		Name:  name,
		Tags:  []statestore.TagInfo{},
		Total: 0,
	}, nil
}

func TestHandleGetRepository_NotFound(t *testing.T) {
	cfg := &config.APIConfig{
		Enabled:  true,
		Port:     8080,
		APIKey:   "",
		ReadOnly: false,
	}

	// Create a mock state store that returns empty repository
	mockStore := &emptyRepositoryMockStore{mockStateStore: &mockStateStore{}}
	server := NewAPIServer(cfg, mockAttestationConfig(), mockStore, queue.NewInMemoryQueue(100), "suppline.yml", observability.NewLogger("error"))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/repositories/nonexistent", nil)
	w := httptest.NewRecorder()

	server.router.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("Expected status 404, got %d", w.Code)
	}
}

func TestHandleGetRepository_WithPagination(t *testing.T) {
	cfg := &config.APIConfig{
		Enabled:  true,
		Port:     8080,
		APIKey:   "",
		ReadOnly: false,
	}

	mockStore := &mockStateStore{}
	server := NewAPIServer(cfg, mockAttestationConfig(), mockStore, queue.NewInMemoryQueue(100), "suppline.yml", observability.NewLogger("error"))

	// Test with pagination parameters
	req := httptest.NewRequest(http.MethodGet, "/api/v1/repositories/test-repo?limit=10&offset=0", nil)
	w := httptest.NewRecorder()

	server.router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}
}

func TestHandleGetRepository_WithSearch(t *testing.T) {
	cfg := &config.APIConfig{
		Enabled:  true,
		Port:     8080,
		APIKey:   "",
		ReadOnly: false,
	}

	mockStore := &mockStateStore{}
	server := NewAPIServer(cfg, mockAttestationConfig(), mockStore, queue.NewInMemoryQueue(100), "suppline.yml", observability.NewLogger("error"))

	// Test with search parameter
	req := httptest.NewRequest(http.MethodGet, "/api/v1/repositories/test-repo?search=latest", nil)
	w := httptest.NewRecorder()

	server.router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}
}
