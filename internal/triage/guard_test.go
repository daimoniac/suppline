package triage

import (
	"testing"
	"time"

	"github.com/daimoniac/suppline/internal/statestore"
	"github.com/daimoniac/suppline/internal/types"
)

func TestShouldSkip(t *testing.T) {
	now := time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)
	interval := 24 * time.Hour
	last := &statestore.TriageRun{Status: StatusWritten, RepoSHAsJSON: "same", CVEHash: "hash", CreatedAt: now.Add(-time.Hour)}
	if !ShouldSkip(last, false, "same", "hash", interval, now) {
		t.Fatal("same checkout and CVE text should skip")
	}
	if ShouldSkip(last, false, "same", "changed", interval, now) {
		t.Fatal("changed CVE text should run")
	}
	if !ShouldSkip(last, false, "other", "hash", interval, now) {
		t.Fatal("changed checkout inside the interval should skip")
	}
	last.CreatedAt = now.Add(-48 * time.Hour)
	if ShouldSkip(last, false, "other", "hash", interval, now) {
		t.Fatal("changed checkout after the interval should run")
	}
	last.CreatedAt = now.Add(-time.Hour)
	if !ShouldSkip(last, true, "same", "hash", interval, now) {
		t.Fatal("renewal inside the interval should skip")
	}
	last.CreatedAt = now.Add(-48 * time.Hour)
	if ShouldSkip(last, true, "same", "hash", interval, now) {
		t.Fatal("renewal after the interval should run")
	}
	last.Status = StatusError
	if ShouldSkip(last, false, "same", "hash", interval, now) {
		t.Fatal("errors are not cached")
	}
}

func TestDecideFlipsExistingAutoStatement(t *testing.T) {
	now := time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)
	settings := Settings{
		MinConfidence: 0.8,
		Expiry:        30 * 24 * time.Hour,
		Allowed:       justificationSet([]string{string(types.VEXJustRequiresConfiguration)}),
		BlockKEV:      true,
		Model:         "test",
	}
	job := Job{CVEID: "CVE-1", Repository: "app"}
	existing := &types.VEXStatement{ID: "CVE-1", State: types.VEXStateNotAffected}
	decision := decide(settings, job, modelVerdict{Verdict: "uncertain", Reasoning: "not enough"}, "", false, nil, existing, nil, "tr-1", now)
	if decision.Action != outcomeAffected || decision.Statement.State != types.VEXStateAffected || decision.Statement.Justification != "" {
		t.Fatalf("decision = %+v", decision)
	}
	accepted := decide(settings, job, modelVerdict{
		Verdict: "not_affected", Justification: "requires_configuration", Confidence: 0.9, Reasoning: "ingress blocks it",
		Evidence: []modelEvidence{{Repo: "infra", Path: "app.yaml", Line: 2, Quote: "ingress: internal"}},
	}, "", false, nil, nil, nil, "tr-2", now)
	if accepted.Action != outcomeNotAffected || accepted.Statement.ExpiresAt == nil {
		t.Fatalf("accepted = %+v", accepted)
	}
	kev := decide(settings, job, modelVerdict{Verdict: "not_affected", Confidence: 1, Reasoning: "no"}, "", true, nil, nil, nil, "tr-3", now)
	if kev.Action != outcomeReject {
		t.Fatalf("kev without an existing statement = %+v", kev)
	}
}

func TestGlobAndSecretPath(t *testing.T) {
	if !globMatch("**/*.yaml", "clusters/prod/app.yaml") {
		t.Fatal("yaml glob")
	}
	if !deniedName("secrets/app.sops.yaml") || !deniedName(".git/config") {
		t.Fatal("denylist")
	}
}
