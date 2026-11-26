package policy

import (
	"context"
	"strings"
	"testing"

	"github.com/daimoniac/suppline/internal/kev"
	"github.com/daimoniac/suppline/internal/scanner"
	"github.com/daimoniac/suppline/internal/types"
)

type fixedKEV struct{ snapshot kev.Snapshot }

func (f fixedKEV) Snapshot() kev.Snapshot { return f.snapshot }

func kevSource(t *testing.T, status kev.Status) fixedKEV {
	t.Helper()
	catalog, err := kev.Parse([]byte(`{"catalogVersion":"t","vulnerabilities":[
		{"cveID":"CVE-2024-0001","dateAdded":"2024-03-01","knownRansomwareCampaignUse":"Known"},
		{"cveID":"CVE-2024-0009","dateAdded":"2024-04-02","knownRansomwareCampaignUse":"Unknown"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	return fixedKEV{kev.Snapshot{Catalog: catalog, Status: status}}
}

func kevScan() *scanner.ScanResult {
	return &scanner.ScanResult{
		ImageRef: "test/image:v1",
		Vulnerabilities: []types.Vulnerability{
			{ID: "CVE-2024-0001", Severity: "HIGH", PackageName: "libxslt"},
			{ID: "CVE-2024-0002", Severity: "HIGH", PackageName: "openssl"},
			{ID: "CVE-2024-0009", Severity: "MEDIUM", PackageName: "linux-libc-dev"},
		},
	}
}

func evaluate(t *testing.T, expr string, source KEVSource, vex []types.VEXStatement) *PolicyDecision {
	t.Helper()
	engine, err := NewEngine(nil, PolicyConfig{Expression: expr}, WithKEV(source))
	if err != nil {
		t.Fatal(err)
	}
	decision, err := engine.Evaluate(context.Background(), "test/image:v1", kevScan(), vex)
	if err != nil {
		t.Fatal(err)
	}
	return decision
}

func TestKEVCountFailsAndAttributesListedFindings(t *testing.T) {
	decision := evaluate(t, "kevCount == 0", kevSource(t, kev.StatusOK), nil)
	if decision.Passed {
		t.Fatal("two listed findings must fail kevCount == 0")
	}
	var got []string
	for _, finding := range decision.PolicyFailureFindings {
		got = append(got, finding.CVEID)
	}
	if strings.Join(got, ",") != "CVE-2024-0001,CVE-2024-0009" {
		t.Fatalf("failure findings = %v, want only the listed CVEs", got)
	}
	if !strings.Contains(decision.Reason, "known exploited=2") {
		t.Fatalf("reason = %q", decision.Reason)
	}
}

func TestKEVCountIgnoresExemptedFindings(t *testing.T) {
	vex := []types.VEXStatement{
		{ID: "CVE-2024-0001", State: types.VEXStateNotAffected, Justification: types.VEXJustCodeNotPresent},
		{ID: "CVE-2024-0009", State: types.VEXStateNotAffected, Justification: types.VEXJustCodeNotPresent},
	}
	if decision := evaluate(t, "kevCount == 0", kevSource(t, kev.StatusOK), vex); !decision.Passed {
		t.Fatalf("exempted KEV findings must not count: %s", decision.Reason)
	}
}

func TestKEVFieldsOnEachVulnerability(t *testing.T) {
	expr := `vulnerabilities.exists(v, v.id == "CVE-2024-0001" && v.kev && v.kevRansomware && v.kevDateAdded == "2024-03-01" && !v.kernelHeaderPackage) &&
		vulnerabilities.exists(v, v.id == "CVE-2024-0002" && !v.kev && !v.kevRansomware && v.kevDateAdded == "") &&
		vulnerabilities.exists(v, v.id == "CVE-2024-0009" && v.kev && !v.kevRansomware && v.kernelHeaderPackage)`
	if decision := evaluate(t, expr, kevSource(t, kev.StatusOK), nil); !decision.Passed {
		t.Fatalf("fields not as expected: %s", decision.Reason)
	}
}

func TestKEVPolicyCanSkipKernelHeaders(t *testing.T) {
	expr := `!vulnerabilities.exists(v, v.kev && !v.exempted && !v.kernelHeaderPackage)`
	vex := []types.VEXStatement{{ID: "CVE-2024-0001", State: types.VEXStateNotAffected, Justification: types.VEXJustCodeNotPresent}}
	if decision := evaluate(t, expr, kevSource(t, kev.StatusOK), vex); !decision.Passed {
		t.Fatalf("a KEV finding only in a kernel header package should pass this policy: %s", decision.Reason)
	}
	if decision := evaluate(t, expr, kevSource(t, kev.StatusOK), nil); decision.Passed {
		t.Fatal("the libxslt KEV finding must still fail it")
	}
}

func TestKEVStatusReachesExpression(t *testing.T) {
	for _, tc := range []struct {
		name   string
		source KEVSource
		want   string
	}{
		{"ok", kevSource(t, kev.StatusOK), "ok"},
		{"stale", kevSource(t, kev.StatusStale), "stale"},
		{"unavailable", fixedKEV{kev.Snapshot{Status: kev.StatusUnavailable}}, "unavailable"},
		{"no source", nil, "disabled"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if decision := evaluate(t, `kevStatus == "`+tc.want+`"`, tc.source, nil); !decision.Passed {
				t.Fatalf("kevStatus is not %q", tc.want)
			}
		})
	}
}

func TestWithoutKEVNothingIsListed(t *testing.T) {
	decision := evaluate(t, `kevCount == 0 && !vulnerabilities.exists(v, v.kev)`, nil, nil)
	if !decision.Passed || strings.Contains(decision.Reason, "known exploited") {
		t.Fatalf("without a source nothing may be listed: %s", decision.Reason)
	}
}

func TestStaleCatalogStillAnswers(t *testing.T) {
	// Fail closed only on unknown data, not on old data: a stale catalog
	// still marks the findings it lists.
	if decision := evaluate(t, "kevCount == 0", kevSource(t, kev.StatusStale), nil); decision.Passed {
		t.Fatal("a stale catalog must still count listed findings")
	}
}

func TestUsesKEV(t *testing.T) {
	for expr, want := range map[string]bool{
		"":                                 false,
		"criticalCount == 0":               false,
		"kevCount == 0":                    true,
		`kevStatus == "ok"`:                true,
		"vulnerabilities.exists(v, v.kev)": true,
		`vulnerabilities.exists(v, v.kevDateAdded > "2026-01-01")`: true,
		"vulnerabilities.exists(v, v.kevRansomware)":               true,
		"vulnerabilities.exists(v, v.kernelHeaderPackage)":         false,
		`imageRef.startsWith("kevlar/")`:                           false,
	} {
		if got := UsesKEV(expr); got != want {
			t.Errorf("UsesKEV(%q) = %v, want %v", expr, got, want)
		}
	}
}
