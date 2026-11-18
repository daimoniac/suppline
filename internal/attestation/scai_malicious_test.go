package attestation

import (
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/daimoniac/suppline/internal/config"
	"github.com/daimoniac/suppline/internal/policy"
	"github.com/daimoniac/suppline/internal/scanner"
	"github.com/daimoniac/suppline/internal/types"
)

func TestSCAIRecordsMaliciousCheck(t *testing.T) {
	generator := NewSCAIGenerator(&config.RegsyncConfig{}, slog.Default())
	result := &scanner.ScanResult{
		ScannedAt: time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC),
		Malicious: &types.MaliciousCheck{Status: types.MaliciousCheckOK, Commit: "abc123", SnapshotAt: 1763467200},
	}
	scai, err := generator.GenerateSCAI(context.Background(), "repo/app@sha256:abc", result, "repo/app", &policy.PolicyDecision{Passed: true})
	if err != nil {
		t.Fatal(err)
	}
	if scai.Evidence.ScanStatus != "passed" {
		t.Fatalf("the check attribute must not count as an exception, got %q", scai.Evidence.ScanStatus)
	}
	data, err := json.Marshal(scai)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"attribute":"malicious-package-check","evidence":{"status":"ok","snapshotCommit":"abc123","snapshotAt":"2025-11-18T12:00:00Z","findings":[]}}`
	if !strings.Contains(string(data), want) {
		t.Fatalf("SCAI JSON missing clean check\n got: %s\nwant substring: %s", data, want)
	}

	result.Malicious = &types.MaliciousCheck{Status: types.MaliciousCheckOK, Commit: "abc123", SnapshotAt: 1763467200, Findings: []types.MaliciousFinding{
		{ID: "MAL-1", Ecosystem: "npm", PackageName: "evil", Version: "1.0.0", PURL: "pkg:npm/evil@1.0.0", URL: "https://osv.dev/vulnerability/MAL-1"},
	}}
	scai, err = generator.GenerateSCAI(context.Background(), "repo/app@sha256:abc", result, "repo/app", &policy.PolicyDecision{Passed: false})
	if err != nil {
		t.Fatal(err)
	}
	data, _ = json.Marshal(scai)
	if !strings.Contains(string(data), `"findings":[{"id":"MAL-1","ecosystem":"npm","packageName":"evil","version":"1.0.0","purl":"pkg:npm/evil@1.0.0","url":"https://osv.dev/vulnerability/MAL-1"}]`) {
		t.Fatalf("SCAI JSON missing finding: %s", data)
	}
}

func TestSCAIOmitsCheckWhenDisabled(t *testing.T) {
	generator := NewSCAIGenerator(&config.RegsyncConfig{}, slog.Default())
	scai, err := generator.GenerateSCAI(context.Background(), "repo/app@sha256:abc", &scanner.ScanResult{ScannedAt: time.Now()}, "repo/app", &policy.PolicyDecision{Passed: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(scai.Attributes) != 0 {
		t.Fatalf("expected no attributes, got %+v", scai.Attributes)
	}
}
