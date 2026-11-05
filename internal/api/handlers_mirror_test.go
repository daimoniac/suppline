package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/daimoniac/suppline/internal/config"
	"github.com/daimoniac/suppline/internal/mirror"
	"github.com/daimoniac/suppline/internal/observability"
	"github.com/daimoniac/suppline/internal/queue"
	"github.com/daimoniac/suppline/internal/statestore"
)

func TestMirrorEndpointOverlaysRunning(t *testing.T) {
	store, err := statestore.NewSQLiteStore(filepath.Join(t.TempDir(), "mirror.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	ctx := t.Context()
	if err := store.ReplaceMirrorSyncs(ctx, []statestore.MirrorSync{{
		Key: "sync-a", Source: "src", Target: "dst", Type: "repository", Schedule: "@every 1h", Position: 0,
	}}); err != nil {
		t.Fatal(err)
	}
	if err := store.FinishMirrorSync(ctx, "sync-a", "failed", "copy timeout", time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := store.SetMirrorHubError(ctx, "hub down"); err != nil {
		t.Fatal(err)
	}

	cfg := &config.APIConfig{Enabled: true, Port: 8080}
	server := NewAPIServer(cfg, mockAttestationConfig(), store, queue.NewInMemoryQueue(8), mockRegsyncConfig(), observability.NewLogger("error"))
	activity := mirror.NewActivity()
	activity.Mark("sync-a")
	server.SetMirror(true, activity)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/mirror", nil)
	w := httptest.NewRecorder()
	server.router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d body %s", w.Code, w.Body.String())
	}
	var overview MirrorOverviewResponse
	if err := json.Unmarshal(w.Body.Bytes(), &overview); err != nil {
		t.Fatal(err)
	}
	if len(overview.Syncs) != 1 || overview.Syncs[0].Status != "running" || overview.Syncs[0].Error != "" {
		t.Fatalf("overview = %+v", overview)
	}
	if overview.HubError != "hub down" {
		t.Fatalf("hub error = %q", overview.HubError)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/v1/mirror/syncs/sync-a/images?limit=10&offset=0", nil)
	w = httptest.NewRecorder()
	server.router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("images status %d", w.Code)
	}
	if w.Header().Get("X-Total-Count") != "0" {
		t.Fatalf("total = %s", w.Header().Get("X-Total-Count"))
	}
}
