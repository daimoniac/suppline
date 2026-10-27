package statestore

import (
	"context"
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
