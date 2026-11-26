package triage

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/daimoniac/suppline/internal/statestore"
)

// staticKEV is a KEV lookup with a fixed answer.
type staticKEV struct {
	listed map[string]bool
	err    error
}

func (k staticKEV) Contains(_ context.Context, cve string) (bool, error) {
	if k.err != nil {
		return false, k.err
	}
	return k.listed[cve], nil
}

func TestShouldSkipRetriesKEVFeedFailure(t *testing.T) {
	last := &statestore.TriageRun{
		Status:       StatusRejected,
		Reasoning:    "CISA KEV feed unavailable: CISA KEV feed status 403",
		RepoSHAsJSON: "same",
		CVEHash:      "same",
		CreatedAt:    time.Now(),
	}
	if ShouldSkip(last, false, "same", "same", time.Hour, time.Now()) {
		t.Fatal("a KEV feed failure should be retried")
	}
}

func TestKEVCheckFailsClosedWithoutFeed(t *testing.T) {
	svc := &Service{settings: Settings{Enabled: true, BlockKEV: true}, kev: noKEVFeed{}}
	if !svc.NeedsKEV() {
		t.Fatal("enabled triage with block_kev needs a KEV feed")
	}
	if _, err := svc.KEVBlocked(context.Background(), "CVE-2024-1234"); err == nil {
		t.Fatal("without a feed the KEV check must fail, not report unlisted")
	}

	// The same lookup and decision guard.judge makes for a model verdict.
	g := svc.guard()
	hit, kevErr := g.kev.Contains(context.Background(), "CVE-2024-1234")
	verdict := modelVerdict{Verdict: "not_affected", Confidence: 1, Justification: "vulnerable_code_not_present", Evidence: []modelEvidence{{Repo: "infra", Path: "a", Line: 1}}}
	decision := decide(svc.settings, Job{CVEID: "CVE-2024-1234"}, verdict, "", hit, kevErr, nil, nil, "t", time.Now())
	if decision.Action != outcomeReject || !strings.Contains(decision.Reason, "no KEV feed configured") {
		t.Fatalf("decision = %+v", decision)
	}
}

func TestSetKEVUsesSharedFeed(t *testing.T) {
	svc := &Service{settings: Settings{Enabled: true, BlockKEV: true}, kev: noKEVFeed{}}
	svc.SetKEV(staticKEV{listed: map[string]bool{"CVE-2024-1234": true}})
	if hit, err := svc.KEVBlocked(context.Background(), "CVE-2024-1234"); err != nil || !hit {
		t.Fatalf("hit=%v err=%v", hit, err)
	}
	svc.SetKEV(nil)
	if hit, err := svc.KEVBlocked(context.Background(), "CVE-2024-1234"); err != nil || !hit {
		t.Fatal("SetKEV(nil) must keep the current feed")
	}
	svc.SetKEV(staticKEV{err: errors.New("catalog is stale")})
	if _, err := svc.KEVBlocked(context.Background(), "CVE-2024-1234"); err == nil {
		t.Fatal("a feed error must reach the caller")
	}
}

func TestNeedsKEVFollowsSettings(t *testing.T) {
	for _, tc := range []struct {
		enabled, block, want bool
	}{{true, true, true}, {true, false, false}, {false, true, false}} {
		svc := &Service{settings: Settings{Enabled: tc.enabled, BlockKEV: tc.block}}
		if got := svc.NeedsKEV(); got != tc.want {
			t.Fatalf("enabled=%v block=%v: NeedsKEV=%v", tc.enabled, tc.block, got)
		}
	}
	var nilService *Service
	if nilService.NeedsKEV() {
		t.Fatal("nil service needs no feed")
	}
}
