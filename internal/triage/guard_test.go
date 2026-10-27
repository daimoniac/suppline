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
	if err := verifyEvidence(roots, pub, Job{}, &upstream); err != nil {
		t.Fatal(err)
	}
	invented := upstream
	invented.Evidence = []modelEvidence{{
		Repo: "supabase/supabase", Path: "apps/studio/lib/sanitize.ts", Line: 40, Quote: "SAFE_FOR_TEMPLATES: true",
	}}
	if err := verifyEvidence(roots, pub, Job{}, &invented); err == nil {
		t.Fatal("accepted a quote the file read did not return")
	}
	checkoutOnly := modelVerdict{
		Verdict: "not_affected", Justification: "code_not_reachable",
		Evidence: []modelEvidence{{Repo: "infra", Path: "app.yaml", Line: 1, Quote: "image: studio"}},
	}
	if err := verifyEvidence(roots, pub, Job{}, &checkoutOnly); err == nil || !strings.Contains(err.Error(), "public checkout") {
		t.Fatalf("checkout line: %v", err)
	}
	deployment := modelVerdict{
		Verdict: "not_affected", Justification: "requires_configuration",
		Evidence: upstream.Evidence,
	}
	if err := verifyEvidence(roots, pub, Job{}, &deployment); err != nil {
		t.Fatalf("public line as configuration evidence: %v", err)
	}
	neither := modelVerdict{
		Verdict: "not_affected", Justification: "requires_configuration",
		Evidence: []modelEvidence{{Repo: "missing", Path: "nope.ts", Line: 1, Quote: "no such line"}},
	}
	if err := verifyEvidence(roots, pub, Job{}, &neither); err == nil {
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
	const cone = "src/platform/packages/shared/kbn-design-tools"
	if err := os.MkdirAll(filepath.Join(dir, cone), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, cone, "sanitize_html.ts"), []byte("return purifier.sanitize(html, {\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	roots := Roots{Checkouts: []CheckoutRoot{
		{Name: "infra", Dir: dir},
		{Name: "elastic/kibana", Dir: dir, Public: true, SHA: studioSHA, Paths: []string{cone}},
	}}
	pub := &publicSource{}
	parent, err := publicGrep(&roots, pub, "elastic/kibana", "SAFE_FOR_TEMPLATES", "src")
	if err != nil || !strings.Contains(parent, "not fully checked out") || strings.Contains(parent, "grep_id:") {
		t.Fatalf("parent grep: %q %v", parent, err)
	}
	empty, err := publicGrep(&roots, pub, "elastic/kibana", "SAFE_FOR_TEMPLATES", cone)
	if err != nil || !strings.Contains(empty, "grep_id: g1") || !strings.Contains(empty, "matches: 0") || !strings.Contains(empty, "path: "+cone) {
		t.Fatalf("empty grep: %q %v", empty, err)
	}
	absence := modelVerdict{
		Verdict: "not_affected", Justification: "code_not_reachable", Confidence: 0.9, Reasoning: "no template mode",
		Evidence: []modelEvidence{{GrepID: "g1"}},
	}
	if err := verifyEvidence(roots, pub, Job{PackageName: "dompurify"}, &absence); err != nil {
		t.Fatal(err)
	}
	if len(absence.Evidence) != 1 || absence.Evidence[0].Path != cone || absence.Evidence[0].Pattern != "SAFE_FOR_TEMPLATES" || absence.Evidence[0].GrepID != "g1" {
		t.Fatalf("stored evidence = %+v", absence.Evidence)
	}
	pub.remember("elastic/kibana", cone+"/sanitize_html.ts", "1|return purifier.sanitize(html, {\n")
	paraphrase := modelVerdict{
		Verdict: "not_affected", Justification: "code_not_reachable", Confidence: 0.9, Reasoning: "narrated src",
		Evidence: []modelEvidence{
			{Repo: "elastic/kibana", Path: "src", Pattern: "SAFE_FOR_TEMPLATES", Commit: studioSHA},
			{Repo: "elastic/kibana", Path: cone + "/sanitize_html.ts", Line: 1, Quote: "return purifier.sanitize(html, {"},
		},
	}
	if err := verifyEvidence(roots, pub, Job{PackageName: "dompurify"}, &paraphrase); err != nil {
		t.Fatal(err)
	}
	if len(paraphrase.Evidence) != 1 || paraphrase.Evidence[0].Line != 1 {
		t.Fatalf("paraphrase was stored: %+v", paraphrase.Evidence)
	}
	unknown := modelVerdict{
		Verdict: "not_affected", Justification: "code_not_reachable", Reasoning: "missing id",
		Evidence: []modelEvidence{{GrepID: "g9"}},
	}
	if err := verifyEvidence(roots, pub, Job{}, &unknown); err == nil || !strings.Contains(err.Error(), "grep_id") {
		t.Fatalf("unknown id: %v", err)
	}
	kernel := modelVerdict{
		Verdict: "not_affected", Justification: "code_not_reachable", Confidence: 0.9, Reasoning: "userspace",
		Evidence: []modelEvidence{{Repo: "infra", Path: "values.yaml", Line: 1, Quote: "image: hostingmaloonde/supabase_postgres:15"}},
	}
	if err := verifyEvidence(roots, pub, Job{Repository: "hostingmaloonde/supabase_postgres", PackageName: "linux-libc-dev"}, &kernel); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "values.yaml"), []byte(body+"privileged: true\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := verifyEvidence(roots, pub, Job{Repository: "hostingmaloonde/supabase_postgres", PackageName: "linux"}, &kernel); err == nil || !strings.Contains(err.Error(), "privileged") {
		t.Fatalf("privileged workload: %v", err)
	}
}

func TestGrepIDExpandsReturnedLines(t *testing.T) {
	dir := t.TempDir()
	const rel = "apps/studio"
	if err := os.MkdirAll(filepath.Join(dir, rel), 0o755); err != nil {
		t.Fatal(err)
	}
	body := "export default {\n  images: { dangerouslyAllowSVG: false },\n}\n"
	if err := os.WriteFile(filepath.Join(dir, rel, "next.config.ts"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	roots := Roots{Checkouts: []CheckoutRoot{{
		Name: "supabase/supabase", Dir: dir, Public: true, SHA: studioSHA, Paths: []string{rel},
	}}}
	pub := &publicSource{}
	out, err := publicGrep(&roots, pub, "supabase/supabase", "dangerouslyAllowSVG", rel)
	if err != nil || !strings.Contains(out, "grep_id: g1") || !strings.Contains(out, "matches: 1") {
		t.Fatalf("grep: %q %v", out, err)
	}
	cited := modelVerdict{
		Verdict: "not_affected", Justification: "requires_configuration", Confidence: 0.9, Reasoning: "svg off",
		Evidence: []modelEvidence{{GrepID: "g1"}},
	}
	if err := verifyEvidence(roots, pub, Job{}, &cited); err != nil {
		t.Fatal(err)
	}
	if len(cited.Evidence) != 1 || cited.Evidence[0].Line != 2 || !strings.Contains(cited.Evidence[0].Quote, "dangerouslyAllowSVG: false") {
		t.Fatalf("evidence = %+v", cited.Evidence)
	}
	if _, err := publicGrep(&roots, pub, "supabase/supabase", "SAFE_FOR_TEMPLATES", rel); err != nil {
		t.Fatal(err)
	}
	absence := modelVerdict{
		Verdict: "not_affected", Justification: "requires_configuration", Reasoning: "no symbol",
		Evidence: []modelEvidence{{GrepID: "g2"}},
	}
	if err := verifyEvidence(roots, pub, Job{}, &absence); err == nil || !strings.Contains(err.Error(), "requires_configuration") {
		t.Fatalf("empty grep as configuration: %v", err)
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
