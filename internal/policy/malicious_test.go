package policy

import (
	"context"
	"log/slog"
	"strings"
	"testing"

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
