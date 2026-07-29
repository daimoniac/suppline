package policy

import "testing"

func TestDescribeExpression(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		expr string
		want string
	}{
		{
			name: "block critical only",
			expr: "criticalCount == 0",
			want: "No critical vulnerabilities",
		},
		{
			name: "block critical and high",
			expr: "criticalCount == 0 && highCount == 0",
			want: "No critical or high vulnerabilities",
		},
		{
			name: "block medium plus",
			expr: "criticalCount == 0 && highCount == 0 && mediumCount == 0",
			want: "No critical, high, or medium vulnerabilities",
		},
		{
			name: "allow up to 2 high",
			expr: "criticalCount == 0 && highCount <= 2",
			want: "No critical vulnerabilities and at most 2 high",
		},
		{
			name: "lenient critical budget",
			expr: "criticalCount <= 5",
			want: "At most 5 critical vulnerabilities",
		},
		{
			name: "whitespace normalized",
			expr: "  criticalCount   ==  0  &&\n highCount==0 ",
			want: "No critical or high vulnerabilities",
		},
		{
			name: "or of count clauses",
			expr: "criticalCount == 0 || highCount == 0",
			want: "No critical vulnerabilities or No high vulnerabilities",
		},
		{
			name: "fixable critical filter",
			expr: `vulnerabilities.filter(v, v.severity == "CRITICAL" && v.fixedVersion != "" && !v.exempted).size() == 0`,
			want: "No fixable critical vulnerabilities",
		},
		{
			name: "fixable critical multiline",
			expr: `
vulnerabilities.filter(v,
  v.severity == "CRITICAL" &&
  v.fixedVersion != "" &&
  !v.exempted
).size() == 0`,
			want: "No fixable critical vulnerabilities",
		},
		{
			name: "package prefix filter",
			expr: `
vulnerabilities.filter(v,
  v.severity == "CRITICAL" &&
  v.packageName.startsWith("openssl")
).size() == 0`,
			want: `No critical vulnerabilities in packages starting with "openssl"`,
		},
		{
			name: "cve allowlist filter",
			expr: `
vulnerabilities.filter(v,
  v.severity == "CRITICAL" &&
  !(v.id in ["CVE-2024-12345", "CVE-2024-67890"])
).size() == 0`,
			want: "No critical vulnerabilities (excluding CVE-2024-12345, CVE-2024-67890)",
		},
		{
			name: "complex mixed counts and filter",
			expr: `
criticalCount == 0 &&
highCount <= 3 &&
vulnerabilities.filter(v,
  v.severity == "HIGH" &&
  v.fixedVersion == ""
).size() == 0`,
			want: "No critical vulnerabilities, at most 3 high, and no unfixable high vulnerabilities",
		},
		{
			name: "parenthesized or",
			expr: `(criticalCount == 0 && highCount <= 2) || exemptedCount >= 5`,
			want: "No critical vulnerabilities and at most 2 high or At least 5 exempted vulnerabilities",
		},
		{
			name: "literal true",
			expr: "true",
			want: "Always passes (no constraints)",
		},
		{
			name: "literal true parenthesized",
			expr: " ( true ) ",
			want: "Always passes (no constraints)",
		},
		{
			name: "literal false",
			expr: "false",
			want: "Never passes (blocks everything)",
		},
		{
			name: "true drops out of conjunction",
			expr: "true && criticalCount == 0",
			want: "No critical vulnerabilities",
		},
		{
			name: "false short-circuits conjunction",
			expr: "criticalCount == 0 && false",
			want: "Never passes (blocks everything)",
		},
		{
			name: "true short-circuits disjunction",
			expr: "criticalCount == 0 || true",
			want: "Always passes (no constraints)",
		},
		{
			name: "false drops out of disjunction",
			expr: "false || criticalCount == 0",
			want: "No critical vulnerabilities",
		},
		{
			name: "all true conjunction",
			expr: "true && true",
			want: "Always passes (no constraints)",
		},
		{
			name: "empty expression",
			expr: "",
			want: "Custom vulnerability policy",
		},
		{
			name: "unrecognized expression",
			expr: `imageRef.startsWith("prod/") && criticalCount == 0`,
			want: "Custom vulnerability policy",
		},
		{
			name: "unrecognized filter body",
			expr: `vulnerabilities.filter(v, v.description.contains("rce")).size() == 0`,
			want: "Custom vulnerability policy",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := DescribeExpression(tt.expr)
			if got != tt.want {
				t.Fatalf("DescribeExpression(%q)\n got: %q\nwant: %q", tt.expr, got, tt.want)
			}
		})
	}
}
