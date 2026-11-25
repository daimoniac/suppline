package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/daimoniac/suppline/internal/statestore"
	"github.com/daimoniac/suppline/internal/statestore/storetest"
)

func getClusterInstances(t *testing.T, server *APIServer) map[string]ClusterInstanceResponse {
	t.Helper()
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/cluster/instances", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	var got ClusterInstancesResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	byHost := map[string]ClusterInstanceResponse{}
	for _, in := range got.Instances {
		byHost[in.Hostname] = in
	}
	return byHost
}

func TestClusterInstancesListsRunningInstances(t *testing.T) {
	store := storetest.New(t)
	started := time.Unix(1_800_000_000, 0)
	for host, status := range map[string]string{"suppline-7896ff8d5f-5d8vd": "healthy", "suppline-7896ff8d5f-q9mnh": "unhealthy"} {
		if err := store.Heartbeat(t.Context(), statestore.Instance{Holder: host + "-h", Hostname: host, Address: "http://10.0.0.1:8080", Version: "v1", StartedAt: started, Status: status}); err != nil {
			t.Fatal(err)
		}
	}
	server := tasksTestServer(t, store, nil)

	got := getClusterInstances(t, server)
	if len(got) != 2 {
		t.Fatalf("instances = %+v", got)
	}
	ok, sick := got["suppline-7896ff8d5f-5d8vd"], got["suppline-7896ff8d5f-q9mnh"]
	if !ok.Healthy || ok.Status != "healthy" || ok.Leader {
		t.Fatalf("healthy instance = %+v", ok)
	}
	if sick.Healthy || sick.Status != "unhealthy" {
		t.Fatalf("unhealthy instance = %+v", sick)
	}
	if ok.StartedAt != started.Unix() || ok.Version != "v1" || ok.SeenAt == 0 {
		t.Fatalf("instance = %+v", ok)
	}

	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/cluster/instances", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST status %d, want 405", rec.Code)
	}
}

// A pod that stopped sending heartbeats stays listed for a while, in red,
// so a crash is visible instead of the pod silently disappearing.
func TestClusterInstancesMarksSilentInstanceUnhealthy(t *testing.T) {
	store := storetest.New(t)
	if err := store.Heartbeat(t.Context(), statestore.Instance{Holder: "h", Hostname: "pod-silent", Address: "http://10.0.0.1:8080", Version: "v1", StartedAt: time.Now(), Status: "healthy"}); err != nil {
		t.Fatal(err)
	}
	server := tasksTestServer(t, store, nil)
	server.clock = func() time.Time { return time.Now().Add(time.Minute) }

	got := getClusterInstances(t, server)["pod-silent"]
	if got.Hostname == "" || got.Healthy {
		t.Fatalf("silent instance = %+v, want listed and unhealthy", got)
	}
}
