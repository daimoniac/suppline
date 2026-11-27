package policy

import (
	"context"
	"strings"
	"testing"

	"github.com/daimoniac/suppline/internal/kev"
	"github.com/daimoniac/suppline/internal/scanner"
	"github.com/daimoniac/suppline/internal/types"
)

func evaluateDefault(t *testing.T, vulns []types.Vulnerability, vex []types.VEXStatement) *PolicyDecision {
	t.Helper()
	// An empty expression takes the implicit default, as an unconfigured
	// repository does.
	engine, err := NewEngine(nil, PolicyConfig{}, WithKEV(kevSource(t, kev.StatusOK)))
	if err != nil {
		t.Fatal(err)
	}
	decision, err := engine.Evaluate(context.Background(), "test/image:v1", &scanner.ScanResult{
		ImageRef:        "test/image:v1",
		Vulnerabilities: vulns,
	}, vex)
	if err != nil {
		t.Fatal(err)
	}
	return decision
}

func TestDefaultPolicy(t *testing.T) {
	exemptCritical := []types.VEXStatement{{
		ID: "CVE-2024-1111", State: types.VEXStateNotAffected, Justification: types.VEXJustCodeNotPresent,
	}}
	tests := []struct {
		name  string
		vulns []types.Vulnerability
		vex   []types.VEXStatement
		pass  bool
	}{
		{"clean image", nil, nil, true},
		{"critical fails", []types.Vulnerability{{ID: "CVE-2024-1111", Severity: "CRITICAL", PackageName: "openssl"}}, nil, false},
		{"exempted critical passes", []types.Vulnerability{{ID: "CVE-2024-1111", Severity: "CRITICAL", PackageName: "openssl"}}, exemptCritical, true},
		{"known-exploited high fails", []types.Vulnerability{{ID: "CVE-2024-0001", Severity: "HIGH", PackageName: "libxslt"}}, nil, false},
		{"other high passes", []types.Vulnerability{{ID: "CVE-2024-0002", Severity: "HIGH", PackageName: "openssl"}}, nil, true},
		{"known-exploited medium passes", []types.Vulnerability{{ID: "CVE-2024-0009", Severity: "MEDIUM", PackageName: "libxslt"}}, nil, true},
		{"critical in a kernel header package passes", []types.Vulnerability{{ID: "CVE-2024-2222", Severity: "CRITICAL", PackageName: "linux-libc-dev"}}, nil, true},
		{"known-exploited high in a kernel header package passes", []types.Vulnerability{{ID: "CVE-2024-0001", Severity: "HIGH", PackageName: "linux-libc-dev"}}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decision := evaluateDefault(t, tt.vulns, tt.vex)
			if decision.Passed != tt.pass {
				t.Fatalf("passed = %v, want %v (reason %q)", decision.Passed, tt.pass, decision.Reason)
			}
			if !tt.pass && !strings.Contains(decision.Reason, DefaultFailureMessage) {
				t.Fatalf("reason = %q, want it to carry %q", decision.Reason, DefaultFailureMessage)
			}
		})
	}
}

func TestDefaultPolicyWithoutKEVCatalogOnlyBlocksCritical(t *testing.T) {
	engine, err := NewEngine(nil, DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	decision, err := engine.Evaluate(context.Background(), "test/image:v1", &scanner.ScanResult{
		ImageRef:        "test/image:v1",
		Vulnerabilities: []types.Vulnerability{{ID: "CVE-2024-0001", Severity: "HIGH", PackageName: "libxslt"}},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !decision.Passed {
		t.Fatalf("a high with no KEV catalog must pass: %s", decision.Reason)
	}
}

func TestDefaultPolicyIsDescribedInWords(t *testing.T) {
	want := "No critical or known-exploited high vulnerabilities (kernel header packages ignored)"
	if got := DescribeExpression(DefaultExpression); got != want {
		t.Fatalf("DescribeExpression(DefaultExpression) = %q, want %q", got, want)
	}
	// Whitespace does not matter, so the one-line form a config file might
	// carry reads the same.
	oneLine := `!vulnerabilities.exists(v, !v.exempted && !v.kernelHeaderPackage && (v.severity == "CRITICAL" || (v.severity == "HIGH" && v.kev)))`
	if got := DescribeExpression(oneLine); got != want {
		t.Fatalf("DescribeExpression(one-line default) = %q, want %q", got, want)
	}
	if got := DescribeExpression(`!vulnerabilities.exists(v, v.severity == "CRITICAL")`); got != customPolicyDescription {
		t.Fatalf("a changed expression must stay custom, got %q", got)
	}
}
