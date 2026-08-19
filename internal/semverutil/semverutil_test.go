package semverutil

import (
	"testing"

	semver "github.com/Masterminds/semver/v3"
)

func TestParseVersion(t *testing.T) {
	if _, ok := ParseVersion(""); ok {
		t.Fatal("empty tag should not parse")
	}
	v, ok := ParseVersion("1.2.3")
	if !ok || v.String() != "1.2.3" {
		t.Fatalf("expected 1.2.3, got %v ok=%v", v, ok)
	}
	if _, ok := ParseVersion("latest"); ok {
		t.Fatal("latest should not parse as semver for our purposes")
	}
}

func TestParseVersion_BitnamiRevisionOrdering(t *testing.T) {
	r9, ok := ParseVersion("0.17.2-debian-12-r9")
	if !ok {
		t.Fatal("expected r9 to parse")
	}
	r16, ok := ParseVersion("0.17.2-debian-12-r16")
	if !ok {
		t.Fatal("expected r16 to parse")
	}
	if !r16.GreaterThan(r9) {
		t.Fatalf("expected r16 > r9, compare=%d", r16.Compare(r9))
	}

	c, err := NewConstraint(">=0.17.2-debian-12-r9")
	if err != nil {
		t.Fatalf("constraint: %v", err)
	}
	if !c.Check(r16) {
		t.Fatal("r16 should satisfy >=...-r9 after Bitnami revision canonicalization")
	}
	if !c.Check(r9) {
		t.Fatal("r9 should satisfy >=...-r9")
	}
}

func TestCanonicalizeSemverText(t *testing.T) {
	if got := canonicalizeSemverText(">=0.17.2-debian-12-r9"); got != ">=0.17.2-debian-12.9" {
		t.Fatalf("got %q", got)
	}
	if got := canonicalizeSemverText("1.0.0-rc.1"); got != "1.0.0-rc.1" {
		t.Fatalf("should not rewrite -rc: got %q", got)
	}
}

func TestIsFlavorSuffix(t *testing.T) {
	flavors := []string{"4.1.3-management", "0.17.2-debian-12-r9", "3.20.1-alpine", "1.2.3-management-alpine"}
	for _, tag := range flavors {
		v, ok := ParseVersion(tag)
		if !ok {
			t.Fatalf("expected %q to parse", tag)
		}
		if !IsFlavorSuffix(v) {
			t.Errorf("%q should be a flavor suffix", tag)
		}
	}

	prereleases := []string{"1.2.3-rc.1", "1.2.3-rc1", "1.2.3-beta", "1.2.3-alpha.2", "1.2.3-0", "1.2.3-snapshot"}
	for _, tag := range prereleases {
		v, ok := ParseVersion(tag)
		if !ok {
			t.Fatalf("expected %q to parse", tag)
		}
		if IsFlavorSuffix(v) {
			t.Errorf("%q should be treated as a real pre-release", tag)
		}
	}

	stable, _ := ParseVersion("1.2.3")
	if IsFlavorSuffix(stable) {
		t.Error("version without a suffix is not a flavor")
	}
	if IsFlavorSuffix(nil) {
		t.Error("nil version is not a flavor")
	}
}

func TestSatisfies_FlavorSuffixStaysInRange(t *testing.T) {
	tests := []struct {
		constraint string
		tag        string
		want       bool
	}{
		{">=4.1.1", "4.1.3-management", true},
		{">=4.1.1", "4.1.0-management", false},
		{">=0.17.2", "0.17.2-debian-12-r9", true},
		{">=4.1.1 <4.2.0", "4.1.3-management", true},
		{">=4.1.1 <4.2.0", "4.2.0-management", false},
		{">=4.1.1", "4.1.3-rc.1", false},
		{">=4.1.1", "4.1.3", true},
	}

	for _, tc := range tests {
		c, err := NewConstraint(tc.constraint)
		if err != nil {
			t.Fatalf("constraint %q: %v", tc.constraint, err)
		}
		v, ok := ParseVersion(tc.tag)
		if !ok {
			t.Fatalf("expected %q to parse", tc.tag)
		}
		if got := Satisfies(c, v); got != tc.want {
			t.Errorf("Satisfies(%q, %q) = %v, want %v", tc.constraint, tc.tag, got, tc.want)
		}
	}

	if Satisfies(nil, nil) {
		t.Error("nil inputs should not satisfy")
	}
}

func TestMaxVersion(t *testing.T) {
	if MaxVersion(nil) != nil {
		t.Fatal("nil slice => nil")
	}
	a, _ := ParseVersion("1.0.0")
	b, _ := ParseVersion("2.0.0")
	c, _ := ParseVersion("1.5.0")
	if m := MaxVersion([]*semver.Version{a, b, c}); m == nil || !m.Equal(b) {
		t.Fatalf("expected 2.0.0 max, got %v", m)
	}
}
