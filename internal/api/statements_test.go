package api

import (
	"testing"

	"github.com/daimoniac/suppline/internal/types"
)

func TestStatementListKeepsOneMeaningOfOpen(t *testing.T) {
	expires := int64(100)
	statements := []*types.VEXInfo{
		{CVEID: "CVE-1", Repository: "app", State: types.VEXStateNotAffected, Detail: "written", ExpiresAt: &expires, AppliedAt: 50, Source: types.VEXSourceAuto},
		{CVEID: "CVE-2", Repository: "lib", State: types.VEXStateNotAffected, Source: types.VEXSourceManual},
	}
	runs := []TriageRunResponse{
		{ID: 3, Repository: "app", CVEID: "CVE-1", Verdict: "not_affected", Status: "dry_run", CreatedAt: 9},
		{ID: 2, Repository: "app", CVEID: "CVE-3", Verdict: "uncertain", Status: "dry_run", CreatedAt: 8, Reasoning: "no commit"},
		{ID: 1, Repository: "app", CVEID: "CVE-3", Verdict: "uncertain", Status: "dry_run", CreatedAt: 7, Superseded: true},
		{ID: 4, Repository: "app", CVEID: "CVE-4", Verdict: "not_affected", Status: "dry_run", CreatedAt: 6, Reasoning: "recorded"},
		{ID: 5, Repository: "lib", CVEID: "CVE-2", Verdict: "not_affected", Status: "push_failed", CreatedAt: 5, Superseded: false},
	}
	rows := statementList(statements, runs, map[string]int{"CVE-1": 9, "CVE-3": 2})
	byKey := map[string]TriageStatement{}
	for _, row := range rows {
		byKey[row.Repository+"\n"+row.CVEID] = row
	}
	if got := byKey["app\nCVE-1"]; got.Source != "auto" || got.AffectedImageCount != 9 || got.NeedsFix || got.CreatedAt != 50 || got.TriagedAt != 9 {
		t.Fatalf("auto row %+v", got)
	}
	if got := byKey["lib\nCVE-2"]; got.Source != "manual" || !got.NeedsFix || got.Run == nil || got.Run.Status != "push_failed" || got.TriagedAt != 5 {
		t.Fatalf("manual row still needs a fix %+v", got)
	}
	if got := byKey["app\nCVE-3"]; got.Source != "open" || !got.NeedsFix || got.Detail != "no commit" || got.State != "" || got.AffectedImageCount != 2 || got.TriagedAt != 8 {
		t.Fatalf("open uncertain %+v", got)
	}
	if _, ok := byKey["app\nCVE-3-old"]; ok {
		t.Fatal("superseded run became its own row")
	}
	if got := byKey["app\nCVE-4"]; got.Source != "open" || got.NeedsFix || got.State != "not_affected" || got.TriagedAt != 6 {
		t.Fatalf("dry run is listed and does not need a fix %+v", got)
	}
}

// Three repositories hold different statements for one CVE. Each row must
// carry its own repository's statement, not whichever one was seen first.
func TestStatementListKeepsEachRepositorysStatement(t *testing.T) {
	eckExpires, falcoExpires := int64(1798111939), int64(1796138031)
	statements := []*types.VEXInfo{
		{CVEID: "CVE-1", Repository: "falco", State: types.VEXStateNotAffected, Justification: types.VEXJustCodeNotReachable, Detail: "triage_id: tr-falco", ExpiresAt: &falcoExpires, Source: types.VEXSourceAuto},
		{CVEID: "CVE-1", Repository: "eck", State: types.VEXStateAffected, Detail: "triage_id: ts-eck", ExpiresAt: &eckExpires, Source: types.VEXSourceAuto},
		{CVEID: "CVE-1", Repository: "falcoctl", State: types.VEXStateNotAffected, Justification: types.VEXJustProtectedAtPerimeter, Detail: "hand-written", Source: types.VEXSourceManual},
	}
	rows := statementList(statements, nil, nil)
	if len(rows) != 3 {
		t.Fatalf("rows = %+v", rows)
	}
	byRepo := map[string]TriageStatement{}
	for _, row := range rows {
		byRepo[row.Repository] = row
	}
	if got := byRepo["eck"]; got.State != "affected" || got.Justification != "" || got.Detail != "triage_id: ts-eck" || got.ExpiresAt != eckExpires || got.Source != "auto" {
		t.Errorf("eck row %+v", got)
	}
	if got := byRepo["falcoctl"]; got.State != "not_affected" || got.Justification != "protected_at_perimeter" || got.Detail != "hand-written" || got.ExpiresAt != 0 || got.Source != "manual" {
		t.Errorf("falcoctl row %+v", got)
	}
	if got := byRepo["falco"]; got.Justification != "code_not_reachable" || got.Detail != "triage_id: tr-falco" || got.ExpiresAt != falcoExpires {
		t.Errorf("falco row %+v", got)
	}
}
