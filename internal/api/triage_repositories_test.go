package api

import (
	"testing"
	"time"

	"github.com/daimoniac/suppline/internal/statestore"
	"github.com/daimoniac/suppline/internal/triage"
	"github.com/daimoniac/suppline/internal/types"
)

func cardCVE(card TriageRepository, id string) *TriageRepositoryCVE {
	for i := range card.CVEs {
		if card.CVEs[i].CVEID == id {
			return &card.CVEs[i]
		}
	}
	return nil
}

func TestBuildTriageRepositoriesStates(t *testing.T) {
	expires := int64(2000000000)
	scans := []*statestore.ScanRecord{
		{
			Repository: "r/app", Tag: "1.0", Digest: "sha256:a", RuntimeUsed: true, PolicyStatus: "failed",
			PolicyFailureFindings: []types.PolicyFailureFinding{
				{CVEID: "CVE-UNCERTAIN", PackageName: "libx"},
				{CVEID: "CVE-NONE", PackageName: "liby"},
				{CVEID: "CVE-QUEUED", PackageName: "libz"},
				{CVEID: "CVE-DONE", PackageName: "libw"},
				{CVEID: "CVE-BUDGET", PackageName: "libv"},
			},
			AppliedVEXStatements: []types.AppliedVEXStatement{
				{CVEID: "CVE-AUTO", State: types.VEXStateNotAffected, ExpiresAt: &expires},
				{CVEID: "CVE-HAND", State: types.VEXStateNotAffected},
			},
		},
		{Repository: "r/app", Tag: "0.9", Digest: "sha256:b", RuntimeUsed: false, PolicyStatus: "failed",
			PolicyFailureFindings: []types.PolicyFailureFinding{{CVEID: "CVE-OLD"}}},
		{Repository: "r/ok", Tag: "2", Digest: "sha256:c", RuntimeUsed: true, PolicyStatus: "passed", PolicyPassed: true},
	}
	in := repositoryCardInput{
		Scans: scans,
		Runs: map[string]TriageRunResponse{
			triage.SkipKey("r/app", "CVE-UNCERTAIN"): {Repository: "r/app", CVEID: "CVE-UNCERTAIN", Status: "rejected_by_guardrail", Verdict: "uncertain"},
			triage.SkipKey("r/app", "CVE-DONE"):      {Repository: "r/app", CVEID: "CVE-DONE", Status: "committed", Verdict: "not_affected"},
		},
		Statements: func(repository string) []types.VEXStatement {
			return []types.VEXStatement{
				{ID: "CVE-AUTO", Source: types.VEXSourceAuto},
				{ID: "CVE-HAND", Source: types.VEXSourceManual},
			}
		},
		Running: map[string]bool{},
		Queued:  map[string]bool{triage.SkipKey("r/app", "CVE-QUEUED"): true},
		Skips: map[string]triage.Skip{
			triage.SkipKey("r/app", "CVE-UNCERTAIN"): {Code: triage.SkipCached, At: time.Unix(1700000000, 0)},
			triage.SkipKey("r/app", "CVE-BUDGET"):    {Code: triage.SkipBudget, At: time.Unix(1700000001, 0)},
		},
	}

	cards := buildTriageRepositories(in)
	if len(cards) != 2 {
		t.Fatalf("cards = %d, want 2", len(cards))
	}
	if cards[0].Repository != "r/app" || cards[1].Repository != "r/ok" {
		t.Fatalf("order = %s, %s; the card needing attention comes first", cards[0].Repository, cards[1].Repository)
	}
	app := cards[0]
	if app.PolicyPassed {
		t.Fatal("r/app has a failing running tag")
	}
	if len(app.Tags) != 1 || app.Tags[0].Tag != "1.0" {
		t.Fatalf("tags = %+v, want only the running tag", app.Tags)
	}
	if cardCVE(app, "CVE-OLD") != nil {
		t.Fatal("a CVE that fails only on a tag that is not running must not appear")
	}

	cases := map[string]string{
		"CVE-UNCERTAIN": phaseUncertain,
		"CVE-NONE":      phaseNotTriaged,
		"CVE-BUDGET":    phaseNotTriaged,
		"CVE-QUEUED":    phaseQueued,
		"CVE-DONE":      phaseDecided,
		"CVE-AUTO":      phaseExempt,
		"CVE-HAND":      phaseExempt,
	}
	for id, want := range cases {
		got := cardCVE(app, id)
		if got == nil {
			t.Fatalf("%s is missing", id)
		}
		if got.Phase != want {
			t.Errorf("%s phase = %s, want %s", id, got.Phase, want)
		}
		if got.Reason == "" {
			t.Errorf("%s has no reason", id)
		}
	}
	if got := cardCVE(app, "CVE-UNCERTAIN"); got.ReasonCode != triage.SkipCached || got.ReasonAt != 1700000000 {
		t.Errorf("uncertain skip = %q at %d", got.ReasonCode, got.ReasonAt)
	}
	if got := cardCVE(app, "CVE-BUDGET"); got.ReasonCode != triage.SkipBudget {
		t.Errorf("budget skip = %q", got.ReasonCode)
	}
	if got := cardCVE(app, "CVE-AUTO"); got.Origin != "auto" || got.ExpiresAt != expires {
		t.Errorf("auto exemption = %+v", got)
	}
	if got := cardCVE(app, "CVE-HAND"); got.Origin != "manual" {
		t.Errorf("manual exemption origin = %q", got.Origin)
	}
	want := TriageRepositoryCounts{Blocking: 5, NeedsAttention: 3, NotTriaged: 2, Uncertain: 1, InProgress: 1, Decided: 1, ExemptAuto: 1, ExemptManual: 1}
	if app.Counts != want {
		t.Errorf("counts = %+v, want %+v", app.Counts, want)
	}
	if app.CVEs[0].Phase != phaseUncertain {
		t.Errorf("first CVE phase = %s, attention states sort first", app.CVEs[0].Phase)
	}
	if !cards[1].PolicyPassed || len(cards[1].CVEs) != 0 {
		t.Errorf("passing card = %+v", cards[1])
	}
}

func TestBuildTriageRepositoriesQueuedWaitsForBudget(t *testing.T) {
	in := repositoryCardInput{
		Scans: []*statestore.ScanRecord{{
			Repository: "r/app", Tag: "1", RuntimeUsed: true, PolicyStatus: "failed",
			PolicyFailureFindings: []types.PolicyFailureFinding{{CVEID: "CVE-1"}},
		}},
		Queued:          map[string]bool{triage.SkipKey("r/app", "CVE-1"): true},
		BudgetExhausted: true,
	}
	got := cardCVE(buildTriageRepositories(in)[0], "CVE-1")
	if got.Phase != phaseQueued || got.Reason == "Queued. It starts when the worker is free." {
		t.Fatalf("queued while exhausted = %+v", got)
	}
}
