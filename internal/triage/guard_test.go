package triage

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/daimoniac/suppline/internal/config"
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

func TestCodeNotReachableNeedsUpstreamLine(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "app.yaml"), []byte("image: studio\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	roots := Roots{Checkouts: []CheckoutRoot{{Name: "infra", Dir: dir}}}
	pub := &publicSource{}
	pub.remember("supabase/supabase", "apps/studio/lib/sanitize.ts", "40|DOMPurify.sanitize(value)\n")
	upstream := modelVerdict{
		Verdict:       "not_affected",
		Justification: "vulnerable_code_not_in_execute_path",
		Confidence:    0.91,
		Reasoning:     "the call does not pass SAFE_FOR_TEMPLATES",
		Evidence: []modelEvidence{{
			Repo: "Supabase/supabase", Path: "apps/studio/lib/sanitize.ts", Line: 40, Quote: "DOMPurify.sanitize(value)",
		}},
	}
	if err := verifyEvidence(roots, pub, Job{}, upstream); err != nil {
		t.Fatal(err)
	}
	invented := upstream
	invented.Evidence = []modelEvidence{{
		Repo: "supabase/supabase", Path: "apps/studio/lib/sanitize.ts", Line: 40, Quote: "SAFE_FOR_TEMPLATES: true",
	}}
	if err := verifyEvidence(roots, pub, Job{}, invented); err == nil {
		t.Fatal("accepted a quote the file read did not return")
	}
	checkoutOnly := modelVerdict{
		Verdict: "not_affected", Justification: "code_not_reachable",
		Evidence: []modelEvidence{{Repo: "infra", Path: "app.yaml", Line: 1, Quote: "image: studio"}},
	}
	if err := verifyEvidence(roots, pub, Job{}, checkoutOnly); err == nil || !strings.Contains(err.Error(), "public checkout") {
		t.Fatalf("checkout line: %v", err)
	}
	deployment := modelVerdict{
		Verdict: "not_affected", Justification: "requires_configuration",
		Evidence: upstream.Evidence,
	}
	if err := verifyEvidence(roots, pub, Job{}, deployment); err != nil {
		t.Fatalf("public line as configuration evidence: %v", err)
	}
	neither := modelVerdict{
		Verdict: "not_affected", Justification: "requires_configuration",
		Evidence: []modelEvidence{{Repo: "missing", Path: "nope.ts", Line: 1, Quote: "no such line"}},
	}
	if err := verifyEvidence(roots, pub, Job{}, neither); err == nil {
		t.Fatal("accepted configuration evidence from neither tree")
	}

	found := false
	for _, justification := range config.DefaultTriageJustifications() {
		if justification == string(types.VEXJustCodeNotReachable) {
			found = true
		}
	}
	if !found {
		t.Fatal("code_not_reachable is not a default justification")
	}
	now := time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)
	settings := Settings{
		MinConfidence: 0.8,
		Expiry:        time.Hour,
		Allowed:       justificationSet(config.DefaultTriageJustifications()),
		Model:         "test",
	}
	decision := decide(settings, Job{CVEID: "GHSA-1", Repository: "app"}, upstream, "", false, nil, nil, nil, "tr", now)
	if decision.Action != outcomeNotAffected || decision.Statement.Justification != types.VEXJustCodeNotReachable {
		t.Fatalf("decision = %+v", decision)
	}
}

func TestEmptyGrepAndKernelWorkload(t *testing.T) {
	dir := t.TempDir()
	body := "image: hostingmaloonde/supabase_postgres:15\ncontainerPort: 5432\n"
	if err := os.WriteFile(filepath.Join(dir, "values.yaml"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	roots := Roots{Checkouts: []CheckoutRoot{{Name: "infra", Dir: dir}, {Name: "supabase/supabase", Dir: dir, Public: true, SHA: studioSHA}}}
	pub := &publicSource{}
	pub.rememberEmptyGrep("supabase/supabase", "use cache", "apps/studio", studioSHA)
	absence := modelVerdict{
		Verdict: "not_affected", Justification: "code_not_reachable", Confidence: 0.9, Reasoning: "no use cache",
		Evidence: []modelEvidence{{Repo: "supabase/supabase", Path: "apps/studio", Pattern: "use cache", Commit: studioSHA}},
	}
	if err := verifyEvidence(roots, pub, Job{PackageName: "next"}, absence); err != nil {
		t.Fatal(err)
	}
	invented := absence
	invented.Evidence[0].Pattern = "SAFE_FOR_TEMPLATES"
	if err := verifyEvidence(roots, pub, Job{}, invented); err == nil {
		t.Fatal("accepted an empty grep that was not run")
	}
	kernel := modelVerdict{
		Verdict: "not_affected", Justification: "code_not_reachable", Confidence: 0.9, Reasoning: "userspace",
		Evidence: []modelEvidence{{Repo: "infra", Path: "values.yaml", Line: 1, Quote: "image: hostingmaloonde/supabase_postgres:15"}},
	}
	if err := verifyEvidence(roots, pub, Job{Repository: "hostingmaloonde/supabase_postgres", PackageName: "linux-libc-dev"}, kernel); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "values.yaml"), []byte(body+"privileged: true\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := verifyEvidence(roots, pub, Job{Repository: "hostingmaloonde/supabase_postgres", PackageName: "linux"}, kernel); err == nil || !strings.Contains(err.Error(), "privileged") {
		t.Fatalf("privileged workload: %v", err)
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
