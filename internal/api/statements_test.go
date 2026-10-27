package api

import (
	"testing"

	"github.com/daimoniac/suppline/internal/types"
)

func TestStatementListKeepsOneMeaningOfOpen(t *testing.T) {
	expires := int64(100)
	active := []*types.VEXSummary{{
		CVEID: "CVE-1", State: types.VEXStateNotAffected, Detail: "written",
		ExpiresAt: &expires, AffectedImageCount: 4,
		Repositories: []types.RepositoryVEXInfo{{Repository: "app", AppliedAt: 50, Source: types.VEXSourceAuto}},
	}}
	inactive := []*types.VEXSummary{{
		CVEID: "CVE-1", AffectedImageCount: 0,
		Repositories: []types.RepositoryVEXInfo{{Repository: "app", Source: types.VEXSourceAuto}},
	}, {
		CVEID: "CVE-2", State: types.VEXStateNotAffected,
		Repositories: []types.RepositoryVEXInfo{{Repository: "lib", Source: types.VEXSourceManual}},
	}}
	runs := []TriageRunResponse{
		{ID: 3, Repository: "app", CVEID: "CVE-1", Verdict: "not_affected", Status: "dry_run", CreatedAt: 9},
		{ID: 2, Repository: "app", CVEID: "CVE-3", Verdict: "uncertain", Status: "dry_run", CreatedAt: 8, Reasoning: "no commit"},
		{ID: 1, Repository: "app", CVEID: "CVE-3", Verdict: "uncertain", Status: "dry_run", CreatedAt: 7, Superseded: true},
		{ID: 4, Repository: "app", CVEID: "CVE-4", Verdict: "not_affected", Status: "dry_run", CreatedAt: 6, Reasoning: "recorded"},
		{ID: 5, Repository: "lib", CVEID: "CVE-2", Verdict: "not_affected", Status: "push_failed", CreatedAt: 5, Superseded: false},
	}
	rows := statementList(active, inactive, runs)
	byKey := map[string]TriageStatement{}
	for _, row := range rows {
		byKey[row.Repository+"\n"+row.CVEID] = row
	}
	if got := byKey["app\nCVE-1"]; got.Source != "auto" || got.AffectedImageCount != 4 || got.NeedsFix || got.CreatedAt != 50 {
		t.Fatalf("auto row %+v", got)
	}
	if got := byKey["lib\nCVE-2"]; got.Source != "manual" || !got.NeedsFix || got.Run == nil || got.Run.Status != "push_failed" {
		t.Fatalf("manual row still needs a fix %+v", got)
	}
	if got := byKey["app\nCVE-3"]; got.Source != "open" || !got.NeedsFix || got.Detail != "no commit" || got.State != "" {
		t.Fatalf("open uncertain %+v", got)
	}
	if _, ok := byKey["app\nCVE-3-old"]; ok {
		t.Fatal("superseded run became its own row")
	}
	if got := byKey["app\nCVE-4"]; got.Source != "open" || got.NeedsFix || got.State != "not_affected" {
		t.Fatalf("dry run is listed and does not need a fix %+v", got)
	}
}
