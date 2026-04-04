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

	err           error
	called        bool
	cluster       string
	images        []statestore.ClusterImageEntry
	reportedAt    time.Time
	summaries     []statestore.ClusterSummary
	clusterImages []statestore.ClusterImageSummary
	deleteCalled  bool
	deleteCluster string
}

func (m *mockClusterInventoryStore) RecordClusterInventory(ctx context.Context, clusterName string, images []statestore.ClusterImageEntry, reportedAt time.Time) error {
	m.called = true
	m.cluster = clusterName
	m.images = images
	m.reportedAt = reportedAt
	return m.err
}

func (m *mockClusterInventoryStore) ListClusterSummaries(ctx context.Context) ([]statestore.ClusterSummary, error) {
	return m.summaries, m.err
}

func (m *mockClusterInventoryStore) ListClusterImages(ctx context.Context, clusterName string) ([]statestore.ClusterImageSummary, error) {
	m.cluster = clusterName
	return m.clusterImages, m.err
}

func (m *mockClusterInventoryStore) DeleteClusterInventory(ctx context.Context, clusterName string) error {
	m.deleteCalled = true
	m.deleteCluster = clusterName
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

func TestHandleListKubernetesClusters(t *testing.T) {
	now := time.Now().UTC().Unix()
	store := &mockClusterInventoryStore{
		mockStateStore: &mockStateStore{},
		summaries: []statestore.ClusterSummary{
			{Name: "prod-a", LastReported: &now, ImageCount: 12},
			{Name: "prod-b", LastReported: &now, ImageCount: 3},
		},
	}
	server := webhookTestServer(t, store)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/integration/kubernetes/clusters", nil)
	w := httptest.NewRecorder()

	server.router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("Expected status %d, got %d body=%s", http.StatusOK, w.Code, w.Body.String())
	}

	var resp []statestore.ClusterSummary
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response JSON: %v", err)
	}
	if len(resp) != 2 {
		t.Fatalf("Expected 2 clusters, got %d", len(resp))
	}
	if resp[0].Name != "prod-a" || resp[0].ImageCount != 12 {
		t.Fatalf("Unexpected first cluster summary: %+v", resp[0])
	}
}

func TestHandleListKubernetesClusters_NotConfigured(t *testing.T) {
	server := webhookTestServer(t, &mockStateStore{})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/integration/kubernetes/clusters", nil)
	w := httptest.NewRecorder()

	server.router.ServeHTTP(w, req)
	if w.Code != http.StatusNotImplemented {
		t.Fatalf("Expected status %d, got %d", http.StatusNotImplemented, w.Code)
	}
}

func TestHandleDeleteKubernetesCluster(t *testing.T) {
	store := &mockClusterInventoryStore{mockStateStore: &mockStateStore{}}
	server := webhookTestServer(t, store)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/integration/kubernetes/clusters/prod-a", nil)
	w := httptest.NewRecorder()

	server.router.ServeHTTP(w, req)
	if w.Code != http.StatusNoContent {
		t.Fatalf("Expected status %d, got %d body=%s", http.StatusNoContent, w.Code, w.Body.String())
	}
	if !store.deleteCalled {
		t.Fatal("Expected DeleteClusterInventory to be called")
	}
	if store.deleteCluster != "prod-a" {
		t.Fatalf("Expected delete cluster prod-a, got %s", store.deleteCluster)
	}
}

func TestHandleDeleteKubernetesCluster_NotConfigured(t *testing.T) {
	server := webhookTestServer(t, &mockStateStore{})

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/integration/kubernetes/clusters/prod-a", nil)
	w := httptest.NewRecorder()

	server.router.ServeHTTP(w, req)
	if w.Code != http.StatusNotImplemented {
		t.Fatalf("Expected status %d, got %d", http.StatusNotImplemented, w.Code)
	}
}

func TestHandleGetKubernetesClusterImages(t *testing.T) {
	store := &mockClusterInventoryStore{
		mockStateStore: &mockStateStore{},
		clusterImages: []statestore.ClusterImageSummary{
			{Namespace: "default", ImageRef: "nginx:1.25", Tag: "1.25", Digest: "sha256:abc"},
			{Namespace: "payments", ImageRef: "ghcr.io/org/app:2.0", Tag: "2.0", Digest: "sha256:def"},
		},
	}
	server := webhookTestServer(t, store)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/integration/kubernetes/clusters/prod-a/images", nil)
	w := httptest.NewRecorder()

	server.router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("Expected status %d, got %d body=%s", http.StatusOK, w.Code, w.Body.String())
	}
	if store.cluster != "prod-a" {
		t.Fatalf("Expected cluster prod-a, got %s", store.cluster)
	}

	var resp []statestore.ClusterImageSummary
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response JSON: %v", err)
	}
	if len(resp) != 2 {
		t.Fatalf("Expected 2 cluster images, got %d", len(resp))
	}
	if resp[0].Namespace != "default" || resp[0].ImageRef != "nginx:1.25" {
		t.Fatalf("Unexpected first cluster image row: %+v", resp[0])
	}
}
