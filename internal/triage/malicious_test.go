package triage

import (
	"context"
	"log/slog"
	"testing"

	"github.com/daimoniac/suppline/internal/types"
	"github.com/daimoniac/suppline/internal/worker"
)

func TestMaliciousFindingsNeverQueueTriage(t *testing.T) {
	svc := &Service{
		settings: Settings{Enabled: true, OnlyInUse: false},
		logger:   slog.Default(),
		jobs:     make(chan Job, 4),
		pending:  map[string]ActiveJob{},
	}
	maliciousOnly := worker.PolicyFailureNotice{
		Repository: "example/app",
		Digest:     "sha256:abc",
		Tag:        "1.0",
		Findings:   []types.PolicyFailureFinding{{CVEID: "MAL-2025-1", PackageName: "evil", Kind: types.PolicyFailureKindMalicious}},
	}
	svc.NotifyPolicyFailure(context.Background(), maliciousOnly)
	if queued := svc.QueuePolicyFailure(context.Background(), maliciousOnly); queued != 0 {
		t.Fatalf("queued %d jobs for a malicious-only failure", queued)
	}
	select {
	case job := <-svc.jobs:
		t.Fatalf("queued triage for malicious finding %s", job.CVEID)
	default:
	}

	mixed := maliciousOnly
	mixed.Findings = append([]types.PolicyFailureFinding{{CVEID: "CVE-1", PackageName: "openssl"}}, maliciousOnly.Findings...)
	if queued := svc.QueuePolicyFailure(context.Background(), mixed); queued != 1 {
		t.Fatalf("queued = %d, want only the CVE", queued)
	}
	if job := <-svc.jobs; job.CVEID != "CVE-1" {
		t.Fatalf("queued %s", job.CVEID)
	}
}
