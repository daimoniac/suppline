package types

import "testing"

func TestValidateMaliciousVEXStatement(t *testing.T) {
	cases := []struct {
		name      string
		stmt      VEXStatement
		automated bool
		ok        bool
	}{
		{"false_positive by hand", VEXStatement{ID: "MAL-2025-1", State: VEXStateFalsePositive}, false, true},
		{"not_affected", VEXStatement{ID: "MAL-2025-1", State: VEXStateNotAffected, Justification: VEXJustCodeNotReachable}, false, false},
		{"automated", VEXStatement{ID: "MAL-2025-1", State: VEXStateFalsePositive}, true, false},
		{"CVE unaffected", VEXStatement{ID: "CVE-1", State: VEXStateNotAffected}, true, true},
	}
	for _, tc := range cases {
		err := ValidateMaliciousVEXStatement(tc.stmt, tc.automated)
		if (err == nil) != tc.ok {
			t.Fatalf("%s: err = %v", tc.name, err)
		}
	}
}
