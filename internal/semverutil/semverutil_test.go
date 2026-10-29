package semverutil

import (
	"testing"

	semver "github.com/Masterminds/semver/v3"
)

func TestParseVersion_Prefix(t *testing.T) {
	cases := []struct {
		tag          string
		major, minor uint64
		patch        uint64
		ok           bool
	}{
		{tag: "alpine-v18.10.0", major: 18, minor: 10, patch: 0, ok: true},
		{tag: "alpine3.18-x86_64-v17.8.0", major: 17, minor: 8, patch: 0, ok: true},
		{tag: "3.18-arm-v17.8.5", major: 17, minor: 8, patch: 5, ok: true},
		{tag: "v2", major: 2, minor: 0, patch: 0, ok: true},
		{tag: "alpine3.18", ok: false},
		{tag: "a1", ok: false},
		{tag: "b3", ok: false},
	}
	for _, tc := range cases {
		v, ok := ParseVersion(tc.tag)
		if ok != tc.ok {
			t.Fatalf("ParseVersion(%q) ok=%v, want %v", tc.tag, ok, tc.ok)
		}
		if !tc.ok {
			continue
		}
		if v.Major() != tc.major || v.Minor() != tc.minor || v.Patch() != tc.patch {
			t.Fatalf("ParseVersion(%q) = %d.%d.%d", tc.tag, v.Major(), v.Minor(), v.Patch())
		}
	}

	c, err := NewConstraint(">=18.9.0")
	if err != nil {
		t.Fatal(err)
	}
	low, ok := ParseVersion("alpine3.18-x86_64-v17.8.0")
	if !ok || Satisfies(c, low) {
		t.Fatal("runner 17.8 must not satisfy >=18.9.0")
	}
	high, ok := ParseVersion("alpine-v18.10.0")
	if !ok || !Satisfies(c, high) {
		t.Fatal("alpine-v18.10.0 must satisfy >=18.9.0")
	}
}

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
	if Compare(r16, r9) <= 0 {
		t.Fatalf("expected r16 > r9, compare=%d", Compare(r16, r9))
	}

	c, err := NewConstraint(">=0.17.2-debian-12-r9")
	if err != nil {
		t.Fatalf("constraint: %v", err)
	}
	if !Satisfies(c, r16) {
		t.Fatal("r16 should satisfy >=...-r9 after Bitnami revision canonicalization")
	}
	if !Satisfies(c, r9) {
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

func TestFourPartNumericVersion(t *testing.T) {
	// One constraint string is AND. Two semverRange entries would be OR, so
	// ">=15.8.1.060 <15.9" must stay a single string.
	c, err := NewConstraint(">=15.8.1.060 <15.9")
	if err != nil {
		t.Fatalf("constraint: %v", err)
	}
	cases := []struct {
		tag  string
		want bool
	}{
		{"15.8.0.060", false},
		{"15.8.1.059", false},
		{"15.8.1", false},
		{"15.8.1.060", true},
		{"15.8.1.60", true},
		{"15.8.1.085", true},
		{"15.8.2", true},
		{"15.8.2.001", true},
		{"15.9.0.001", false},
	}
	for _, tc := range cases {
		v, ok := ParseVersion(tc.tag)
		if !ok {
			t.Fatalf("expected %q to parse", tc.tag)
		}
		if got := Satisfies(c, v); got != tc.want {
			t.Errorf("Satisfies(>=15.8.1.060 <15.9, %q) = %v, want %v", tc.tag, got, tc.want)
		}
	}

	next, err := NewConstraint(">=15.14.1.037 <16")
	if err != nil {
		t.Fatalf("constraint: %v", err)
	}
	v, ok := ParseVersion("15.14.1.037")
	if !ok || !Satisfies(next, v) {
		t.Fatal("15.14.1.037 should satisfy >=15.14.1.037 <16")
	}
	low, ok := ParseVersion("17.6.1.036")
	upper, err := NewConstraint(">=17.6.1.037 <18")
	if err != nil || !ok || Satisfies(upper, low) {
		t.Fatal("17.6.1.036 should not satisfy >=17.6.1.037 <18")
	}

	sonar, err := NewConstraint(">=26.2.0-0")
	if err != nil {
		t.Fatalf("constraint: %v", err)
	}
	tag, ok := ParseVersion("26.10.0.133078-community")
	if !ok {
		t.Fatal("expected 26.10.0.133078-community to parse")
	}
	if !IsFlavorSuffix(tag) {
		t.Fatal("community should be a flavor suffix")
	}
	if !Satisfies(sonar, tag) {
		t.Fatal("26.10.0.133078-community should satisfy >=26.2.0-0")
	}
}

func TestCompareMatchesImageTagOrder(t *testing.T) {
	pairs := []struct {
		a, b string
		want int
	}{
		{"15.8.1.060", "15.8.2", -1},
		{"15.8.1", "15.8.1.060", -1},
		{"0.17.2-debian-12-r9", "0.17.2-debian-12-r16", -1},
		{"26.10.0.133078-community", "26.2.0", 1},
		{"4.1.3-rc.1", "4.1.3", -1},
	}
	for _, tc := range pairs {
		va, oka := ParseVersion(tc.a)
		vb, okb := ParseVersion(tc.b)
		if !oka || !okb {
			t.Fatalf("parse %q %q", tc.a, tc.b)
		}
		got := Compare(va, vb)
		if (tc.want < 0 && got >= 0) || (tc.want > 0 && got <= 0) || (tc.want == 0 && got != 0) {
			t.Fatalf("Compare(%q, %q) = %d, want sign %d", tc.a, tc.b, got, tc.want)
		}
		ord, ok := CompareImageTagOrder(tc.a, tc.b)
		if !ok || ord != got {
			t.Fatalf("CompareImageTagOrder(%q, %q) = %d ok=%v, Compare = %d", tc.a, tc.b, ord, ok, got)
		}
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
