package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/daimoniac/suppline/internal/config"
	"github.com/daimoniac/suppline/internal/statestore"
	"github.com/daimoniac/suppline/internal/statestore/storetest"
	"github.com/daimoniac/suppline/internal/types"
)

// The live CVE-2026-91403 case: three repositories, three different
// statements for one CVE. The triage list showed one of them on every row.
func TestTriageStatementsShowEachRepositorysOwnStatement(t *testing.T) {
	store, regsync := threeStatementsForOneCVE(t)
	eckExpires, falcoExpires := int64(1798111939), int64(1796138031)
	server := tasksTestServer(t, store, regsync)

	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/triage/statements", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	var rows []TriageStatement
	if err := json.Unmarshal(rec.Body.Bytes(), &rows); err != nil {
		t.Fatal(err)
	}
	byRepo := map[string]TriageStatement{}
	for _, row := range rows {
		byRepo[row.Repository] = row
	}
	if len(byRepo) != 3 {
		t.Fatalf("rows = %+v", rows)
	}
	if got := byRepo["registry.example.com/eck"]; got.State != "affected" || got.Detail != "triage_id: ts-eck" || got.ExpiresAt != eckExpires || got.Source != "auto" {
		t.Errorf("eck row %+v", got)
	}
	if got := byRepo["registry.example.com/falcoctl"]; got.Justification != "protected_at_perimeter" || got.Detail != "hand-written" || got.ExpiresAt != 0 || got.Source != "manual" {
		t.Errorf("falcoctl row %+v", got)
	}
	if got := byRepo["registry.example.com/falco"]; got.Justification != "code_not_reachable" || got.Detail != "triage_id: tr-falco" || got.ExpiresAt != falcoExpires {
		t.Errorf("falco row %+v", got)
	}
}

// threeStatementsForOneCVE is the live CVE-2026-91403 layout: falco auto
// not_affected, eck auto affected, falcoctl hand-written with no expiry.
func threeStatementsForOneCVE(t *testing.T) (*statestore.SQLiteStore, *config.RegsyncConfig) {
	t.Helper()
	store := storetest.New(t)
	eckExpires, falcoExpires := int64(1798111939), int64(1796138031)
	return store, &config.RegsyncConfig{
		Version: 1,
		Sync: []config.SyncEntry{
			{Source: "docker.io/falcosecurity/falco", Target: "registry.example.com/falco", Type: "repository",
				VEXAuto: []types.VEXStatement{{ID: "CVE-1", State: types.VEXStateNotAffected, Justification: types.VEXJustCodeNotReachable, Detail: "triage_id: tr-falco", ExpiresAt: &falcoExpires}}},
			{Source: "docker.elastic.co/eck/eck-operator", Target: "registry.example.com/eck", Type: "repository",
				VEXAuto: []types.VEXStatement{{ID: "CVE-1", State: types.VEXStateAffected, Detail: "triage_id: ts-eck", ExpiresAt: &eckExpires}}},
			{Source: "docker.io/falcosecurity/falcoctl", Target: "registry.example.com/falcoctl", Type: "repository",
				VEX: []types.VEXStatement{{ID: "CVE-1", State: types.VEXStateNotAffected, Justification: types.VEXJustProtectedAtPerimeter, Detail: "hand-written"}}},
		},
	}
}

// The Tasks page lists unused statements per CVE. Each repository entry must
// carry its own state and expiry, and the summary must not depend on map order.
func TestInactiveVEXKeepsEachRepositorysStatement(t *testing.T) {
	store, regsync := threeStatementsForOneCVE(t)
	server := tasksTestServer(t, store, regsync)
	for range 5 {
		rec := httptest.NewRecorder()
		server.router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/vex/inactive", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
		}
		var summaries []types.VEXSummary
		if err := json.Unmarshal(rec.Body.Bytes(), &summaries); err != nil {
			t.Fatal(err)
		}
		if len(summaries) != 1 || len(summaries[0].Repositories) != 3 {
			t.Fatalf("summaries = %+v", summaries)
		}
		got := summaries[0]
		repos := got.Repositories
		if repos[0].Repository != "registry.example.com/eck" || repos[0].State != types.VEXStateAffected || repos[0].ExpiresAt == nil || *repos[0].ExpiresAt != 1798111939 {
			t.Fatalf("eck entry %+v", repos[0])
		}
		if repos[1].Repository != "registry.example.com/falco" || repos[1].Justification != types.VEXJustCodeNotReachable || *repos[1].ExpiresAt != 1796138031 {
			t.Fatalf("falco entry %+v", repos[1])
		}
		if repos[2].Repository != "registry.example.com/falcoctl" || repos[2].Justification != types.VEXJustProtectedAtPerimeter || repos[2].ExpiresAt != nil || repos[2].Source != types.VEXSourceManual {
			t.Fatalf("falcoctl entry %+v", repos[2])
		}
		if got.State != types.VEXStateAffected || got.Detail != "triage_id: ts-eck" {
			t.Fatalf("summary fields follow the first repository by name: %+v", got)
		}
	}
}
