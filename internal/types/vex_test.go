package types

import (
	"testing"

	"gopkg.in/yaml.v3"
)

func TestNormalizeVEXJustification_LegacyAliases(t *testing.T) {
	tests := []struct {
		name string
		in   VEXJustification
		want VEXJustification
	}{
		{name: "component_not_present", in: "component_not_present", want: VEXJustCodeNotPresent},
		{name: "vulnerable_code_not_present", in: "vulnerable_code_not_present", want: VEXJustCodeNotPresent},
		{name: "cannot_be_controlled", in: "vulnerable_code_cannot_be_controlled_by_adversary", want: VEXJustCodeNotReachable},
		{name: "not_in_execute_path", in: "vulnerable_code_not_in_execute_path", want: VEXJustCodeNotReachable},
		{name: "inline_mitigations", in: "inline_mitigations_already_exist", want: VEXJustProtectedByMitigations},
		{name: "protected_by_mitigating_control", in: "protected_by_mitigating_control", want: VEXJustProtectedByMitigations},
		{name: "already_canonical", in: VEXJustProtectedAtRuntime, want: VEXJustProtectedAtRuntime},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NormalizeVEXJustification(tt.in); got != tt.want {
				t.Fatalf("NormalizeVEXJustification() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestVEXStatementUnmarshalYAML_NormalizesLegacyJustification(t *testing.T) {
	var stmt VEXStatement
	err := yaml.Unmarshal([]byte(`
id: CVE-2026-23112
state: not_affected
justification: vulnerable_code_cannot_be_controlled_by_adversary
`), &stmt)
	if err != nil {
		t.Fatalf("yaml.Unmarshal() error = %v", err)
	}

	if stmt.Justification != VEXJustCodeNotReachable {
		t.Fatalf("Justification = %q, want %q", stmt.Justification, VEXJustCodeNotReachable)
	}

	if err := ValidateVEXStatement(stmt); err != nil {
		t.Fatalf("ValidateVEXStatement() error = %v", err)
	}
}
