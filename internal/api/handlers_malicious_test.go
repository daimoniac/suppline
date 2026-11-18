package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/daimoniac/suppline/internal/config"
	"github.com/daimoniac/suppline/internal/malicious"
	"github.com/daimoniac/suppline/internal/observability"
	"github.com/daimoniac/suppline/internal/queue"
	"github.com/daimoniac/suppline/internal/statestore"
	"github.com/daimoniac/suppline/internal/types"
)

type stubMaliciousFeed struct{ overview malicious.Overview }

func (s stubMaliciousFeed) Overview() malicious.Overview { return s.overview }

func TestMaliciousEndpoint(t *testing.T) {
	store, err := statestore.NewSQLiteStore(filepath.Join(t.TempDir(), "malicious.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	ctx := t.Context()
	evil := "sha256:aaaa000000000000000000000000000000000000000000000000000000000000"
	clean := "sha256:bbbb000000000000000000000000000000000000000000000000000000000000"
	old := "sha256:cccc000000000000000000000000000000000000000000000000000000000000"
	check := &types.MaliciousCheck{Status: types.MaliciousCheckOK, Findings: []types.MaliciousFinding{{ID: "MAL-1", Ecosystem: "npm", PackageName: "evil", Version: "1.0.0"}}}
	for _, scan := range []*statestore.ScanRecord{
		{Repository: "library/app", Digest: evil, Tag: "1.0", PolicyStatus: "failed", Malicious: check},
		{Repository: "library/app", Digest: evil, Tag: "latest", PolicyStatus: "failed", Malicious: check},
		{Repository: "library/app", Digest: clean, Tag: "0.9", PolicyPassed: true, PolicyStatus: "passed", Malicious: &types.MaliciousCheck{Status: types.MaliciousCheckStale}},
		{Repository: "library/old", Digest: old, Tag: "1", PolicyPassed: true, PolicyStatus: "passed"},
	} {
		if err := store.RecordScan(ctx, scan); err != nil {
			t.Fatal(err)
		}
	}

	server := NewAPIServer(&config.APIConfig{Enabled: true, Port: 8080}, mockAttestationConfig(), store, queue.NewInMemoryQueue(8), mockRegsyncConfig(), observability.NewLogger("error"))
	synced := time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)
	server.SetMalicious(stubMaliciousFeed{malicious.Overview{
		Status: malicious.StatusOK, Commit: "abc", SyncedAt: synced, LastAttemptAt: synced,
		SyncInterval: time.Hour, StaleAfter: 6 * time.Hour, Entries: 3, Packages: map[string]int{"npm": 3},
	}}, MaliciousSettings{Block: true, RepoURL: "https://example/mal.git", Ref: "main"})

	w := httptest.NewRecorder()
	server.router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/malicious", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status %d body %s", w.Code, w.Body.String())
	}
	var overview MaliciousOverviewResponse
	if err := json.Unmarshal(w.Body.Bytes(), &overview); err != nil {
		t.Fatal(err)
	}
	if !overview.Enabled || overview.Feed == nil || overview.Feed.Status != "ok" || *overview.Feed.SyncedAt != synced.Unix() || overview.Feed.SyncIntervalSeconds != 3600 || !overview.Feed.Block {
		t.Fatalf("feed = %+v", overview.Feed)
	}
	if overview.Coverage != (statestore.MaliciousCoverage{OK: 1, Stale: 1, Unchecked: 1}) {
		t.Fatalf("coverage = %+v", overview.Coverage)
	}
	if len(overview.Images) != 1 {
		t.Fatalf("images = %+v", overview.Images)
	}
	image := overview.Images[0]
	if image.Digest != evil || strings.Join(image.Tags, ",") != "1.0,latest" || len(image.Findings) != 1 || image.Findings[0].ID != "MAL-1" {
		t.Fatalf("image = %+v", image)
	}

	health := httptest.NewRecorder()
	server.router.ServeHTTP(health, httptest.NewRequest(http.MethodGet, "/health", nil))
	if !strings.Contains(health.Body.String(), `"maliciousEnabled":true`) {
		t.Fatalf("health body = %s", health.Body.String())
	}
}

func TestMaliciousEndpointDisabled(t *testing.T) {
	server := NewAPIServer(&config.APIConfig{Enabled: true, Port: 8080}, mockAttestationConfig(), &mockStateStore{}, queue.NewInMemoryQueue(8), mockRegsyncConfig(), observability.NewLogger("error"))
	w := httptest.NewRecorder()
	server.router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/malicious", nil))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"Enabled":false`) || !strings.Contains(w.Body.String(), `"Feed":null`) {
		t.Fatalf("status %d body %s", w.Code, w.Body.String())
	}
	health := httptest.NewRecorder()
	server.router.ServeHTTP(health, httptest.NewRequest(http.MethodGet, "/health", nil))
	if !strings.Contains(health.Body.String(), `"maliciousEnabled":false`) {
		t.Fatalf("health body = %s", health.Body.String())
	}
}
