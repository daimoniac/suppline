package triage

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/daimoniac/suppline/internal/types"
)

type stubKEV struct {
	listed map[string]bool
	err    error
	calls  int
}

func (s *stubKEV) Contains(_ context.Context, cve string) (bool, error) {
	s.calls++
	return s.listed[cve], s.err
}

// judgeFixture is a session whose gitops checkout holds one citable line.
func judgeFixture(t *testing.T) (*toolbox, Settings, modelVerdict) {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "app.yaml"), []byte("kind: Ingress\ningress: internal\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	tools := &toolbox{roots: &Roots{Checkouts: []CheckoutRoot{{Name: "infra", Dir: dir}}}, pub: newPublicSource()}
	settings := Settings{
		MinConfidence: 0.8,
		Expiry:        30 * 24 * time.Hour,
		Allowed:       justificationSet([]string{string(types.VEXJustRequiresConfiguration)}),
		BlockKEV:      true,
		Model:         "test",
	}
	verdict := modelVerdict{
		Verdict: "not_affected", Justification: "requires_configuration", Confidence: 0.9, Reasoning: "ingress blocks it",
		Evidence: []modelEvidence{{Repo: "infra", Path: "app.yaml", Line: 2, Quote: "ingress: internal"}},
	}
	return tools, settings, verdict
}

func fixedNow() time.Time { return time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC) }

func TestGuardJudge(t *testing.T) {
	job := Job{CVEID: "CVE-1", Repository: "app"}
	autoStatement := &types.VEXStatement{ID: "CVE-1", State: types.VEXStateNotAffected}
	tests := []struct {
		name       string
		kev        *stubKEV
		blockKEV   bool
		existing   *types.VEXStatement
		edit       func(*modelVerdict)
		want       outcome
		wantReason string
		wantCalls  int
	}{
		{name: "cited line checks out", kev: &stubKEV{}, blockKEV: true, want: outcomeNotAffected, wantCalls: 1},
		{name: "KEV listed rejects", kev: &stubKEV{listed: map[string]bool{"CVE-1": true}}, blockKEV: true, want: outcomeReject, wantReason: "Known Exploited", wantCalls: 1},
		{name: "KEV listed flips an existing auto statement", kev: &stubKEV{listed: map[string]bool{"CVE-1": true}}, blockKEV: true, existing: autoStatement, want: outcomeAffected, wantCalls: 1},
		{name: "KEV feed down rejects", kev: &stubKEV{err: errors.New("timeout")}, blockKEV: true, want: outcomeReject, wantReason: "KEV feed unavailable", wantCalls: 1},
		{name: "KEV not consulted when not blocking", kev: &stubKEV{listed: map[string]bool{"CVE-1": true}}, blockKEV: false, want: outcomeNotAffected, wantCalls: 0},
		{
			name: "quote that does not match the file rejects", kev: &stubKEV{}, blockKEV: true,
			edit:       func(v *modelVerdict) { v.Evidence[0].Quote = "ingress: public" },
			want:       outcomeReject,
			wantReason: "quote does not match",
			wantCalls:  1,
		},
		{
			name: "grep id never returned rejects", kev: &stubKEV{}, blockKEV: true,
			edit:       func(v *modelVerdict) { v.Evidence = []modelEvidence{{GrepID: "g-unknown"}} },
			want:       outcomeReject,
			wantReason: "grep_id",
			wantCalls:  1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tools, settings, verdict := judgeFixture(t)
			settings.BlockKEV = tt.blockKEV
			if tt.edit != nil {
				tt.edit(&verdict)
			}
			g := guard{settings: settings, kev: tt.kev, now: fixedNow}

			decision := g.judge(context.Background(), tools, job, &verdict, tt.existing, nil, "ts-1")
			if decision.Action != tt.want {
				t.Fatalf("Action = %s (%s), want %s", decision.Action, decision.Reason, tt.want)
			}
			if tt.wantReason != "" && !strings.Contains(decision.Reason, tt.wantReason) {
				t.Errorf("Reason = %q, want it to mention %q", decision.Reason, tt.wantReason)
			}
			if tt.kev.calls != tt.wantCalls {
				t.Errorf("KEV lookups = %d, want %d", tt.kev.calls, tt.wantCalls)
			}
			if decision.Action == outcomeNotAffected {
				if decision.Statement.ExpiresAt == nil || *decision.Statement.ExpiresAt != fixedNow().Add(settings.Expiry).Unix() {
					t.Errorf("ExpiresAt = %v, want now + expiry", decision.Statement.ExpiresAt)
				}
			}
		})
	}
}

// A grep made while the model worked on another CVE cannot back this verdict:
// the guard reads the same ledger the tools wrote.
func TestGuardJudgeRejectsGrepFromAnotherCVE(t *testing.T) {
	tools, settings, _ := judgeFixture(t)
	settings.Allowed = justificationSet([]string{string(types.VEXJustCodeNotReachable)})
	tools.pub.setPhase("CVE-A")
	id := tools.pub.recordGrep("acme/app", "sink", "apps", strings.Repeat("a", 40), "")
	tools.pub.setPhase("CVE-B")
	verdict := modelVerdict{Verdict: "not_affected", Justification: "code_not_reachable", Confidence: 0.9, Evidence: []modelEvidence{{GrepID: id}}}

	decision := guard{settings: settings, now: fixedNow}.judge(context.Background(), tools, Job{CVEID: "CVE-B", PackageName: "dompurify"}, &verdict, nil, nil, "ts-1")
	if decision.Action != outcomeReject || !strings.Contains(decision.Reason, "CVE-A") {
		t.Fatalf("decision = %+v, want a rejection naming CVE-A", decision)
	}
}
