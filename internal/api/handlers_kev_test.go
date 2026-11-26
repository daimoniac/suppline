package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/daimoniac/suppline/internal/config"
	"github.com/daimoniac/suppline/internal/kev"
	"github.com/daimoniac/suppline/internal/observability"
	"github.com/daimoniac/suppline/internal/queue"
	"github.com/daimoniac/suppline/internal/statestore"
	"github.com/daimoniac/suppline/internal/statestore/storetest"
	"github.com/daimoniac/suppline/internal/types"
)

type stubKEVFeed struct{ snapshot kev.Snapshot }

func (s stubKEVFeed) Snapshot() kev.Snapshot { return s.snapshot }

func kevTestServer(t *testing.T) (*APIServer, string) {
	t.Helper()
	store, err := statestore.NewPostgresStore(storetest.URL(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	ctx := t.Context()
	listed := "sha256:aaaa000000000000000000000000000000000000000000000000000000000000"
	exempted := "sha256:bbbb000000000000000000000000000000000000000000000000000000000000"
	now := time.Now().Unix()
	for _, scan := range []*statestore.ScanRecord{
		{Repository: "library/app", Digest: listed, Tag: "1.0", PolicyPassed: true, PolicyStatus: "passed",
			Vulnerabilities: []types.VulnerabilityRecord{
				{CVEID: "CVE-2024-0001", Severity: "HIGH", PackageName: "libxslt", InstalledVersion: "1"},
				{CVEID: "CVE-2024-0002", Severity: "HIGH", PackageName: "openssl", InstalledVersion: "1"},
			}},
		{Repository: "library/other", Digest: exempted, Tag: "1", PolicyPassed: true, PolicyStatus: "passed",
			Vulnerabilities:      []types.VulnerabilityRecord{{CVEID: "CVE-2024-0001", Severity: "HIGH", PackageName: "libxslt", InstalledVersion: "1"}},
			AppliedVEXStatements: []types.AppliedVEXStatement{{CVEID: "CVE-2024-0001", State: types.VEXStateNotAffected, AppliedAt: now}}},
	} {
		if err := store.RecordScan(ctx, scan); err != nil {
			t.Fatal(err)
		}
	}
	catalog, err := kev.Parse([]byte(`{"catalogVersion":"2026.11.25","vulnerabilities":[{"cveID":"CVE-2024-0001","dateAdded":"2024-03-01","dueDate":"2024-03-22","knownRansomwareCampaignUse":"Known"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	server := NewAPIServer(&config.APIConfig{Port: 8080}, mockAttestationConfig(), store, queue.NewInMemoryQueue(8), mockRegsyncConfig(), observability.NewLogger("error"))
	server.SetKEV(stubKEVFeed{kev.Snapshot{Catalog: catalog, Status: kev.StatusOK, SyncedAt: time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)}})
	return server, listed
}

func get(t *testing.T, server *APIServer, path string) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	server.router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
	if w.Code != http.StatusOK {
		t.Fatalf("GET %s: status %d body %s", path, w.Code, w.Body.String())
	}
	return w
}

func TestKEVOverviewCountsUnexemptedImages(t *testing.T) {
	server, _ := kevTestServer(t)
	var overview KEVOverviewResponse
	if err := json.Unmarshal(get(t, server, "/api/v1/kev").Body.Bytes(), &overview); err != nil {
		t.Fatal(err)
	}
	if !overview.Enabled || overview.Status != "ok" || overview.CatalogVersion != "2026.11.25" || overview.Entries != 1 {
		t.Fatalf("feed = %+v", overview)
	}
	// library/other has the CVE exempted, so only library/app counts.
	if overview.Images != 1 || overview.PassingImages != 1 || overview.InUseImages != 0 || overview.CVEs != 1 {
		t.Fatalf("counts = %+v", overview)
	}
	if body := get(t, server, "/health").Body.String(); !strings.Contains(body, `"kevEnabled":true`) || !strings.Contains(body, `"kevStatus":"ok"`) {
		t.Fatalf("health = %s", body)
	}
}

func TestVulnerabilitiesKEVFilterAndFields(t *testing.T) {
	server, digest := kevTestServer(t)
	var groups []types.VulnerabilityGroup
	if err := json.Unmarshal(get(t, server, "/api/v1/vulnerabilities?kev=true").Body.Bytes(), &groups); err != nil {
		t.Fatal(err)
	}
	if len(groups) != 1 || groups[0].CVEID != "CVE-2024-0001" || groups[0].KEV == nil || !groups[0].KEV.Ransomware || groups[0].KEV.DateAdded != "2024-03-01" {
		t.Fatalf("kev=true groups = %+v", groups)
	}
	groups = nil // KEV is omitted when unlisted; decoding into the old slice would keep it
	if err := json.Unmarshal(get(t, server, "/api/v1/vulnerabilities?cve_id=CVE-2024-0002").Body.Bytes(), &groups); err != nil {
		t.Fatal(err)
	}
	if len(groups) != 1 || groups[0].KEV != nil {
		t.Fatalf("an unlisted CVE must have no KEV: %+v", groups)
	}

	body := get(t, server, "/api/v1/scans/"+digest).Body.String()
	if !strings.Contains(body, `"KEV":{"DateAdded":"2024-03-01","DueDate":"2024-03-22","Ransomware":true}`) {
		t.Fatalf("scan detail lacks KEV info: %s", body)
	}
}

func TestKEVDisabled(t *testing.T) {
	server := NewAPIServer(&config.APIConfig{Port: 8080}, mockAttestationConfig(), &mockStateStore{}, queue.NewInMemoryQueue(8), mockRegsyncConfig(), observability.NewLogger("error"))
	if body := get(t, server, "/api/v1/kev").Body.String(); !strings.Contains(body, `"Enabled":false`) || !strings.Contains(body, `"Status":"disabled"`) {
		t.Fatalf("body = %s", body)
	}
	if body := get(t, server, "/health").Body.String(); !strings.Contains(body, `"kevEnabled":false`) {
		t.Fatalf("health = %s", body)
	}
}
