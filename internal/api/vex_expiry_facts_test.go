package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/daimoniac/suppline/internal/config"
	"github.com/daimoniac/suppline/internal/statestore"
	"github.com/daimoniac/suppline/internal/types"
)

// expiryScanStore returns fixed scans per repository.
type expiryScanStore struct {
	mockStateStore
	scans map[string][]*statestore.ScanRecord
}

func (s *expiryScanStore) ListScans(_ context.Context, filter statestore.ScanFilter) ([]*statestore.ScanRecord, error) {
	return s.scans[filter.Repository], nil
}

func (s *expiryScanStore) GetLastRepositoryScan(_ context.Context, repository, digest string) (*statestore.ScanRecord, error) {
	for _, scan := range s.scans[repository] {
		if scan.Digest == digest {
			return scan, nil
		}
	}
	return nil, statestore.ErrScanNotFound
}

func TestVEXExpiryRowsCarryPerRepositoryActionFacts(t *testing.T) {
	now := time.Now().UTC()
	studioExpires := now.Add(6 * 24 * time.Hour).Unix()
	falcoExpires := now.Add(2 * 24 * time.Hour).Unix()
	realtimeExpires := now.Add(-time.Hour).Unix()
	defaultsExpires := now.Add(3 * 24 * time.Hour).Unix()
	regsync := &config.RegsyncConfig{
		Version: 1,
		Defaults: config.Defaults{VEX: []types.VEXStatement{
			{ID: "CVE-DEF", State: types.VEXStateNotAffected, ExpiresAt: &defaultsExpires},
		}},
		Sync: []config.SyncEntry{
			{Source: "docker.io/supabase/studio", Target: "registry.example.com/studio", Type: "repository",
				VEX: []types.VEXStatement{{ID: "CVE-1", State: types.VEXStateNotAffected, Justification: types.VEXJustProtectedAtPerimeter, Detail: "temporary", ExpiresAt: &studioExpires}}},
			{Source: "docker.io/falcosecurity/falco", Target: "registry.example.com/falco", Type: "repository",
				VEXAuto: []types.VEXStatement{{ID: "CVE-1", State: types.VEXStateNotAffected, Justification: types.VEXJustCodeNotReachable, ExpiresAt: &falcoExpires}}},
			{Source: "docker.io/supabase/realtime", Target: "registry.example.com/realtime", Type: "repository",
				VEXAuto: []types.VEXStatement{{ID: "CVE-2", State: types.VEXStateNotAffected, ExpiresAt: &realtimeExpires}}},
		},
	}
	store := &expiryScanStore{scans: map[string][]*statestore.ScanRecord{
		"registry.example.com/studio": {
			{Repository: "registry.example.com/studio", Tag: "2026.09.07", Digest: "sha256:old", ImageCreatedAt: 100,
				AppliedVEXStatements: []types.AppliedVEXStatement{{CVEID: "CVE-1"}}},
			{Repository: "registry.example.com/studio", Tag: "2026.10.26", Digest: "sha256:new", ImageCreatedAt: 200,
				Vulnerabilities: []types.VulnerabilityRecord{{CVEID: "CVE-OTHER"}}},
		},
		"registry.example.com/falco": {
			{Repository: "registry.example.com/falco", Tag: "0.40", Digest: "sha256:f", ImageCreatedAt: 50,
				Vulnerabilities: []types.VulnerabilityRecord{{CVEID: "CVE-1"}}},
		},
		"registry.example.com/realtime": {
			{Repository: "registry.example.com/realtime", Tag: "2.30", Digest: "sha256:r", ImageCreatedAt: 50,
				Vulnerabilities: []types.VulnerabilityRecord{{CVEID: "CVE-OTHER"}}},
		},
	}}
	server := tasksTestServer(t, store, regsync)

	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/tasks/vex-expiry", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	var resp VEXExpiryTasksResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	rows := map[string]VEXExpiryTaskEntry{}
	for _, entry := range resp.Entries {
		rows[entry.Repository+" "+entry.CVEID] = entry
	}

	studio := rows["registry.example.com/studio CVE-1"]
	if studio.ExpiresAt != studioExpires || studio.Source != types.VEXSourceManual || !studio.Editable || studio.Justification != "protected_at_perimeter" {
		t.Errorf("studio row %+v", studio)
	}
	if !studio.InScans || len(studio.AffectedTags) != 1 || studio.AffectedTags[0] != "2026.09.07" || studio.FixedTag != "2026.10.26" {
		t.Errorf("studio scan facts %+v", studio)
	}
	falco := rows["registry.example.com/falco CVE-1"]
	if falco.ExpiresAt != falcoExpires || falco.Source != types.VEXSourceAuto || !falco.Editable || !falco.InScans || falco.FixedTag != "" {
		t.Errorf("falco row has its own expiry and source %+v", falco)
	}
	realtime := rows["registry.example.com/realtime CVE-2"]
	if realtime.Status != "expired" || realtime.InScans || len(realtime.AffectedTags) != 0 {
		t.Errorf("realtime row: no scan reports the CVE %+v", realtime)
	}
	for _, repo := range []string{"registry.example.com/studio", "registry.example.com/falco", "registry.example.com/realtime"} {
		row, ok := rows[repo+" CVE-DEF"]
		if !ok || row.Editable {
			t.Errorf("defaults.vex row for %s must exist and not be editable: %+v", repo, row)
		}
	}
	if len(resp.Entries) != 6 {
		t.Fatalf("entries = %d, want one per repository and CVE", len(resp.Entries))
	}
	if resp.TriageEnabled {
		t.Error("triage is not configured in this server")
	}
}

func TestCVETagFactsNeedsANewerFixedTag(t *testing.T) {
	tags := map[string][]taggedScan{"CVE-1": {
		{Tag: "new", BuiltAt: 200, Reports: true},
		{Tag: "old", BuiltAt: 100},
	}}
	in, affected, fixed := cveTagFacts(tags, "CVE-1")
	if !in || len(affected) != 1 || fixed != "" {
		t.Fatalf("an older clean tag is not a fix: %v %v %q", in, affected, fixed)
	}
	if in, _, _ := cveTagFacts(tags, "CVE-2"); in {
		t.Fatal("unreported CVE counted as in scans")
	}
}
