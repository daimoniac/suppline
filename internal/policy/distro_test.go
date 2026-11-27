package policy

import (
	"context"
	"testing"

	"github.com/daimoniac/suppline/internal/scanner"
	"github.com/daimoniac/suppline/internal/types"
)

func TestDistroFactsAreOptIn(t *testing.T) {
	result := &scanner.ScanResult{
		OSEndOfLife: true,
		Vulnerabilities: []types.Vulnerability{{
			ID:             "CVE-2026-1",
			Severity:       "CRITICAL",
			PackageName:    "openssl",
			VendorStatus:   "will_not_fix",
			VendorSeverity: "LOW",
			AttackVector:   "LOCAL",
		}},
	}
	decide := func(expr string) *PolicyDecision {
		t.Helper()
		engine, err := NewEngine(nil, PolicyConfig{Expression: expr})
		if err != nil {
			t.Fatal(err)
		}
		decision, err := engine.Evaluate(context.Background(), "example/app:1", result, nil)
		if err != nil {
			t.Fatal(err)
		}
		return decision
	}

	if decide("").Passed {
		t.Fatal("default policy still fails a critical")
	}
	if !decide(`!vulnerabilities.exists(v, !v.exempted && v.severity == "CRITICAL" && (v.vendorSeverity == "" || v.vendorSeverity == "CRITICAL" || v.vendorSeverity == "UNKNOWN"))`).Passed {
		t.Fatal("a distro LOW rating can be opted out of the critical gate")
	}
	if !decide(`!vulnerabilities.exists(v, !v.exempted && v.severity == "CRITICAL" && (v.attackVector == "" || v.attackVector == "NETWORK"))`).Passed {
		t.Fatal("a LOCAL vector must pass a network-only critical gate")
	}
	if decide("criticalCount == 0 && !osEndOfLife").Passed {
		t.Fatal("osEndOfLife must fail an expression that reads it")
	}
	if !decide(`vulnerabilities.exists(v, v.vendorStatus == "will_not_fix" && v.attackVector == "LOCAL" && v.vendorSeverity == "LOW")`).Passed {
		t.Fatal("vendor status, severity, and attack vector must be readable together")
	}
}

func TestEmptyDistroFactsStayClosed(t *testing.T) {
	result := &scanner.ScanResult{
		Vulnerabilities: []types.Vulnerability{{
			ID: "CVE-2026-1", Severity: "CRITICAL", PackageName: "openssl",
		}},
	}
	engine, err := NewEngine(nil, PolicyConfig{Expression: `!vulnerabilities.exists(v, !v.exempted && v.severity == "CRITICAL" && (v.vendorSeverity == "" || v.vendorSeverity == "CRITICAL"))`})
	if err != nil {
		t.Fatal(err)
	}
	decision, err := engine.Evaluate(context.Background(), "example/app:1", result, nil)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Passed {
		t.Fatal("a missing vendor severity must still fail")
	}
	if len(decision.PolicyFailureFindings) != 1 || decision.PolicyFailureFindings[0].CVEID != "CVE-2026-1" {
		t.Fatalf("failure findings = %+v", decision.PolicyFailureFindings)
	}
}
