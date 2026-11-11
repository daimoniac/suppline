package statestore

import (
	"context"
	"github.com/daimoniac/suppline/internal/types"
	"path/filepath"
	"testing"
	"time"
)

func TestTriageRunRoundTrip(t *testing.T) {
	store, err := NewSQLiteStore(filepath.Join(t.TempDir(), "triage.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	ctx := context.Background()
	now := time.Date(2026, 10, 23, 8, 0, 0, 0, time.UTC)
	if err := store.InsertTriageRun(ctx, &TriageRun{
		Repository: "app", CVEID: "CVE-1", Verdict: "not_affected", Confidence: 0.9,
		EvidenceJSON: "[]", Status: "written", Tokens: 12, RepoSHAsJSON: "[]", CVEHash: "abc", CreatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	latest, err := store.LatestTriageRun(ctx, "app", "CVE-1")
	if err != nil || latest == nil || latest.Status != "written" || latest.Tokens != 12 {
		t.Fatalf("latest = %+v err=%v", latest, err)
	}
	used, err := store.TriageTokensSince(ctx, now.Add(-time.Hour))
	if err != nil || used != 12 {
		t.Fatalf("tokens = %d err=%v", used, err)
	}
	if err := store.SetBudgetResetAt(ctx, now); err != nil {
		t.Fatal(err)
	}
	reset, err := store.BudgetResetAt(ctx)
	if err != nil || !reset.Equal(now) {
		t.Fatalf("reset = %s err=%v", reset, err)
	}
	used, err = store.TriageTokensSince(ctx, reset.Add(time.Second))
	if err != nil || used != 0 {
		t.Fatalf("tokens after reset = %d err=%v", used, err)
	}
	listed, err := store.ListTriageRuns(ctx, TriageFilter{Repository: "app", Status: "written"})
	if err != nil || len(listed) != 1 {
		t.Fatalf("list = %+v err=%v", listed, err)
	}
	if commit, err := store.LatestTriageCommit(ctx); err != nil || commit != nil {
		t.Fatalf("commit = %+v err=%v", commit, err)
	}
	if err := store.InsertTriageRun(ctx, &TriageRun{
		Repository: "app", CVEID: "CVE-1", Status: "committed", CommitSHA: "abc123", CreatedAt: now.Add(time.Minute),
	}); err != nil {
		t.Fatal(err)
	}
	commit, err := store.LatestTriageCommit(ctx)
	if err != nil || commit == nil || commit.CommitSHA != "abc123" {
		t.Fatalf("commit = %+v err=%v", commit, err)
	}
}

func TestListTriageRunsLatestOnlyDropsSupersededRuns(t *testing.T) {
	store, err := NewSQLiteStore(filepath.Join(t.TempDir(), "triage.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	ctx := context.Background()
	at := time.Date(2026, 10, 23, 8, 0, 0, 0, time.UTC)
	insert := func(repo, cve, status string, offset time.Duration) {
		t.Helper()
		if err := store.InsertTriageRun(ctx, &TriageRun{
			Repository: repo, CVEID: cve, Status: status, EvidenceJSON: "[]", RepoSHAsJSON: "[]", CreatedAt: at.Add(offset),
		}); err != nil {
			t.Fatal(err)
		}
	}
	insert("app", "CVE-1", "dry_run", 0)
	insert("app", "CVE-1", "rejected_by_guardrail", time.Hour)
	insert("app", "CVE-1", "committed", 2*time.Hour)
	insert("app", "CVE-2", "error", 0)
	insert("other", "CVE-1", "rejected_by_guardrail", 0)
	// Same second: the higher id wins.
	insert("app", "CVE-3", "error", 3*time.Hour)
	insert("app", "CVE-3", "dry_run", 3*time.Hour)

	runs, err := store.ListTriageRuns(ctx, TriageFilter{LatestOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, run := range runs {
		got[run.Repository+"/"+run.CVEID] = run.Status
	}
	want := map[string]string{"app/CVE-1": "committed", "app/CVE-2": "error", "other/CVE-1": "rejected_by_guardrail", "app/CVE-3": "dry_run"}
	if len(runs) != len(want) {
		t.Fatalf("runs = %d, want %d: %v", len(runs), len(want), got)
	}
	for key, status := range want {
		if got[key] != status {
			t.Errorf("%s = %q, want %q", key, got[key], status)
		}
	}

	filtered, err := store.ListTriageRuns(ctx, TriageFilter{LatestOnly: true, Status: "rejected_by_guardrail"})
	if err != nil {
		t.Fatal(err)
	}
	if len(filtered) != 1 || filtered[0].Repository != "other" {
		t.Fatalf("a replaced rejection must not come back through the status filter: %+v", filtered)
	}
}

func TestListScansIncludeExemptionsIsOptIn(t *testing.T) {
	store, err := NewSQLiteStore(filepath.Join(t.TempDir(), "scans.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	ctx := context.Background()
	if err := store.RecordScan(ctx, &ScanRecord{
		Repository: "docker.io/lib/app", Tag: "1.0", Digest: "sha256:exempt", PolicyPassed: true,
		SBOMAttested: true, VulnAttested: true, SCAIAttested: true,
		Vulnerabilities: []types.VulnerabilityRecord{},
		AppliedVEXStatements: []types.AppliedVEXStatement{
			{CVEID: "CVE-2026-1", State: types.VEXStateNotAffected, AppliedAt: 1},
		},
	}); err != nil {
		t.Fatal(err)
	}

	plain, err := store.ListScans(ctx, ScanFilter{})
	if err != nil || len(plain) != 1 {
		t.Fatalf("plain = %d err=%v", len(plain), err)
	}
	if len(plain[0].AppliedVEXStatements) != 0 {
		t.Fatalf("a plain list must stay light, got %+v", plain[0].AppliedVEXStatements)
	}
	full, err := store.ListScans(ctx, ScanFilter{IncludeExemptions: true})
	if err != nil || len(full) != 1 {
		t.Fatalf("full = %d err=%v", len(full), err)
	}
	if len(full[0].AppliedVEXStatements) != 1 || full[0].AppliedVEXStatements[0].CVEID != "CVE-2026-1" {
		t.Fatalf("exemptions = %+v", full[0].AppliedVEXStatements)
	}
}
