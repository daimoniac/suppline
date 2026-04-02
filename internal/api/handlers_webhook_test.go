package api

import (
	"context"
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
)

type mockClusterInventoryStore struct {
	*mockStateStore

	err        error
	called     bool
	cluster    string
	images     []statestore.ClusterImageEntry
	reportedAt time.Time
}

func (m *mockClusterInventoryStore) RecordClusterInventory(ctx context.Context, clusterName string, images []statestore.ClusterImageEntry, reportedAt time.Time) error {
	m.called = true
	m.cluster = clusterName
	m.images = images
	m.reportedAt = reportedAt
	return m.err
}

func webhookTestServer(t *testing.T, store statestore.StateStoreQuery) *APIServer {
	t.Helper()
	cfg := &config.APIConfig{Enabled: true, Port: 8080, APIKey: "", ReadOnly: false}
	return NewAPIServer(cfg, mockAttestationConfig(), store, queue.NewInMemoryQueue(100), mockRegsyncConfig(), observability.NewLogger("error"))
}

func TestHandleClusterInventory_MethodNotAllowed(t *testing.T) {
	server := webhookTestServer(t, &mockStateStore{})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/webhook/cluster-inventory", nil)
	w := httptest.NewRecorder()

	server.router.ServeHTTP(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("Expected status %d, got %d", http.StatusMethodNotAllowed, w.Code)
	}
}

func TestHandleClusterInventory_ValidationErrors(t *testing.T) {
	store := &mockClusterInventoryStore{mockStateStore: &mockStateStore{}}
	server := webhookTestServer(t, store)

	t.Run("missing cluster", func(t *testing.T) {
		body := `{"images":[{"namespace":"default","image_ref":"nginx:1.25"}]}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/webhook/cluster-inventory", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		server.router.ServeHTTP(w, req)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("Expected status %d, got %d", http.StatusBadRequest, w.Code)
		}
	})

	t.Run("missing namespace", func(t *testing.T) {
		body := `{"cluster":"prod-a","images":[{"image_ref":"nginx:1.25"}]}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/webhook/cluster-inventory", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		server.router.ServeHTTP(w, req)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("Expected status %d, got %d", http.StatusBadRequest, w.Code)
		}
	})
}

func TestHandleClusterInventory_AcceptsBothImageRefFormats(t *testing.T) {
	store := &mockClusterInventoryStore{mockStateStore: &mockStateStore{}}
	server := webhookTestServer(t, store)

	body := `{
		"cluster":"prod-a",
		"images":[
			{"namespace":"default","image_ref":"nginx:1.25","tag":"1.25"},
			{"namespace":"payments","image_ref":"registry.example.com/app@sha256:abc","digest":"sha256:abc"}
		]
	}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/webhook/cluster-inventory", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	server.router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("Expected status %d, got %d body=%s", http.StatusOK, w.Code, w.Body.String())
	}
	if !store.called {
		t.Fatal("Expected RecordClusterInventory to be called")
	}
	if store.cluster != "prod-a" {
		t.Fatalf("Expected cluster prod-a, got %s", store.cluster)
	}
	if len(store.images) != 2 {
		t.Fatalf("Expected 2 images, got %d", len(store.images))
	}
	if store.images[0].ImageRef != "nginx:1.25" {
		t.Fatalf("Expected first image ref nginx:1.25, got %s", store.images[0].ImageRef)
	}
	if store.images[1].ImageRef != "registry.example.com/app@sha256:abc" {
		t.Fatalf("Expected second image digest ref, got %s", store.images[1].ImageRef)
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response JSON: %v", err)
	}
	if resp["status"] != "ok" {
		t.Fatalf("Expected response status ok, got %v", resp["status"])
	}
}
