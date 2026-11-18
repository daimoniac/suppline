package policy

import (
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/daimoniac/suppline/internal/scanner"
	"github.com/daimoniac/suppline/internal/types"
)

func maliciousResult(vulns ...types.Vulnerability) *scanner.ScanResult {
	return &scanner.ScanResult{
		Vulnerabilities: vulns,
		Malicious: &types.MaliciousCheck{
			Status: types.MaliciousCheckOK,
			Findings: []types.MaliciousFinding{
				{ID: "MAL-2025-1", Ecosystem: "npm", PackageName: "evil", Version: "1.0.0"},
				{ID: "MAL-2025-1", Ecosystem: "npm", PackageName: "evil", Version: "1.0.0", PURL: "dup"},
			},
		},
	}
}

func newMaliciousTestEngine(t *testing.T, expression string, opts ...Option) *Engine {
	t.Helper()
	engine, err := NewEngine(slog.Default(), PolicyConfig{Expression: expression}, opts...)
	if err != nil {
		t.Fatal(err)
	}
	return engine
}

func countKind(findings []types.PolicyFailureFinding, malicious bool) int {
	n := 0
	for _, f := range findings {
		if f.IsMalicious() == malicious {
			n++
		}
	}
	return n
}

func TestMaliciousGateFailsPassingPolicy(t *testing.T) {
	engine := newMaliciousTestEngine(t, "criticalCount == 0")
	decision, err := engine.Evaluate(context.Background(), "img", maliciousResult(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Passed || decision.Status != PolicyStatusFailed {
		t.Fatalf("expected gate to fail the image, got %+v", decision)
	}
	if !strings.HasPrefix(decision.Reason, "malicious packages found: MAL-2025-1") {
		t.Fatalf("unexpected reason %q", decision.Reason)
	}
	if len(decision.PolicyFailureFindings) != 1 || !decision.PolicyFailureFindings[0].IsMalicious() {
		t.Fatalf("expected one deduplicated malicious finding, got %+v", decision.PolicyFailureFindings)
	}
	if !decision.ShouldAttest {
		t.Fatal("a failed image is still attested")
	}
}

func TestMaliciousGateKeepsVulnerabilityFindings(t *testing.T) {
	engine := newMaliciousTestEngine(t, "criticalCount == 0")
	critical := types.Vulnerability{ID: "CVE-1", Severity: "CRITICAL", PackageName: "openssl"}
	decision, err := engine.Evaluate(context.Background(), "img", maliciousResult(critical), nil)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Passed {
		t.Fatal("expected failure")
	}
	if countKind(decision.PolicyFailureFindings, false) != 1 || countKind(decision.PolicyFailureFindings, true) != 1 {
		t.Fatalf("expected one CVE and one malicious finding, got %+v", decision.PolicyFailureFindings)
	}
	if !strings.HasPrefix(decision.Reason, "malicious packages found") || !strings.Contains(decision.Reason, "critical=1") {
		t.Fatalf("reason should carry both causes, got %q", decision.Reason)
	}
}

func TestMaliciousGateCannotBeExemptedByVEX(t *testing.T) {
	engine := newMaliciousTestEngine(t, "criticalCount == 0")
	vex := []types.VEXStatement{{ID: "MAL-2025-1", State: types.VEXStateNotAffected, Justification: types.VEXJustCodeNotPresent}}
	decision, err := engine.Evaluate(context.Background(), "img", maliciousResult(), vex)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Passed {
		t.Fatal("VEX must not exempt a malicious package")
	}
}

func TestMaliciousGateDisabled(t *testing.T) {
	engine := newMaliciousTestEngine(t, "criticalCount == 0", WithMaliciousGate(false))
	decision, err := engine.Evaluate(context.Background(), "img", maliciousResult(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if !decision.Passed {
		t.Fatalf("expected pass with the gate off, got %+v", decision)
	}

	// With the gate off, the expression decides, and its malicious failures
	// are attributed to the malicious findings.
	strict := newMaliciousTestEngine(t, "criticalCount == 0 && maliciousCount == 0", WithMaliciousGate(false))
	decision, err = strict.Evaluate(context.Background(), "img", maliciousResult(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Passed || countKind(decision.PolicyFailureFindings, true) != 1 {
		t.Fatalf("expected expression failure attributed to malware, got %+v", decision)
	}

	// A failure caused only by a CVE does not list malicious findings.
	critical := types.Vulnerability{ID: "CVE-1", Severity: "CRITICAL", PackageName: "openssl"}
	decision, err = engine.Evaluate(context.Background(), "img", maliciousResult(critical), nil)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Passed || countKind(decision.PolicyFailureFindings, true) != 0 {
		t.Fatalf("malicious findings must not be blamed for a CVE failure, got %+v", decision.PolicyFailureFindings)
	}
}

func TestCELReadsMaliciousList(t *testing.T) {
	engine := newMaliciousTestEngine(t, `malicious.filter(m, m.ecosystem == "npm").size() == 0`, WithMaliciousGate(false))
	decision, err := engine.Evaluate(context.Background(), "img", maliciousResult(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Passed {
		t.Fatal("expression over malicious list should fail")
	}
	clean := &scanner.ScanResult{}
	decision, err = engine.Evaluate(context.Background(), "img", clean, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !decision.Passed {
		t.Fatalf("no check means no findings, got %+v", decision)
	}
}

func falsePositive(id string, expiresAt *int64) types.VEXStatement {
	return types.VEXStatement{ID: id, State: types.VEXStateFalsePositive, Detail: "workspace package", ExpiresAt: expiresAt}
}

func TestMaliciousFalsePositiveExempts(t *testing.T) {
	engine := newMaliciousTestEngine(t, "criticalCount == 0 && maliciousCount == 0")
	result := maliciousResult()
	decision, err := engine.Evaluate(context.Background(), "img", result, []types.VEXStatement{falsePositive("MAL-2025-1", nil)})
	if err != nil {
		t.Fatal(err)
	}
	if !decision.Passed || len(decision.PolicyFailureFindings) != 0 {
		t.Fatalf("a false_positive statement should exempt the finding, got %+v", decision)
	}
	if len(decision.ExemptedCVEs) != 1 || decision.ExemptedCVEs[0] != "MAL-2025-1" {
		t.Fatalf("exempted id should be reported for the VEX attestation, got %v", decision.ExemptedCVEs)
	}
	if result.Malicious.Findings[0].Exempted {
		t.Fatal("Evaluate must not mutate the scan result")
	}
	marked := MarkExemptedMalicious(result.Malicious, decision.ExemptedCVEs)
	if !marked.Findings[0].Exempted || !marked.Findings[1].Exempted {
		t.Fatalf("marked copy should flag the findings, got %+v", marked.Findings)
	}

	// CEL still sees the exempted finding, flagged.
	listing := newMaliciousTestEngine(t, `malicious.exists(m, m.exempted) && maliciousCount == 0`)
	decision, err = listing.Evaluate(context.Background(), "img", maliciousResult(), []types.VEXStatement{falsePositive("MAL-2025-1", nil)})
	if err != nil {
		t.Fatal(err)
	}
	if !decision.Passed {
		t.Fatalf("expected the exempted finding in the malicious list, got %+v", decision)
	}
}

func TestMaliciousFalsePositiveExpiredOrOtherIDDoesNotExempt(t *testing.T) {
	engine := newMaliciousTestEngine(t, "criticalCount == 0")
	expired := time.Now().Add(-time.Hour).Unix()
	for name, statements := range map[string][]types.VEXStatement{
		"expired":  {falsePositive("MAL-2025-1", &expired)},
		"other id": {falsePositive("MAL-2025-2", nil)},
	} {
		decision, err := engine.Evaluate(context.Background(), "img", maliciousResult(), statements)
		if err != nil {
			t.Fatal(err)
		}
		if decision.Passed {
			t.Fatalf("%s: statement must not exempt, got %+v", name, decision)
		}
	}
}

// A malicious match during the cooldown fails at once: the cooldown only
// holds a passing scan back, so the match is visible for triage while held.
func TestMaliciousGateFailsDuringCooldown(t *testing.T) {
	engine, err := NewEngine(slog.Default(), PolicyConfig{Expression: "criticalCount == 0", Cooldown: 7 * 24 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	result := maliciousResult()
	result.ScannedAt = time.Now()
	firstSeen := result.ScannedAt.Add(-time.Hour)
	result.FirstSeenAt = &firstSeen

	decision, err := engine.Evaluate(context.Background(), "img", result, nil)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Status != PolicyStatusFailed {
		t.Fatalf("status = %s, want failed during the cooldown", decision.Status)
	}
}
