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

func TestClusterInstancesListsRunningInstances(t *testing.T) {
	store := storetest.New(t)
	started := time.Unix(1_800_000_000, 0)
	for _, host := range []string{"suppline-7896ff8d5f-5d8vd", "suppline-7896ff8d5f-q9mnh"} {
		if err := store.Heartbeat(t.Context(), statestore.Instance{Holder: host + "-h", Hostname: host, Address: "http://10.0.0.1:8080", Version: "v1", StartedAt: started}); err != nil {
			t.Fatal(err)
		}
	}
	server := tasksTestServer(t, store, nil)

	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/cluster/instances", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	var got ClusterInstancesResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Instances) != 2 || got.Instances[0].Hostname != "suppline-7896ff8d5f-5d8vd" || got.Instances[0].Leader {
		t.Fatalf("instances = %+v", got.Instances)
	}
	if got.Instances[1].StartedAt != started.Unix() || got.Instances[1].Version != "v1" || got.Instances[1].SeenAt == 0 {
		t.Fatalf("instance = %+v", got.Instances[1])
	}

	rec = httptest.NewRecorder()
	server.router.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/cluster/instances", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST status %d, want 405", rec.Code)
	}
}
