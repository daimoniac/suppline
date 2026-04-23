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
