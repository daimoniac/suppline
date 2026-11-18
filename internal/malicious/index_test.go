package malicious

import (
	"testing"
)

func entry(id, ecosystem, name string, versions []string, ranges ...Range) *Entry {
	return &Entry{ID: id, Summary: "Malicious code in " + name, Affected: []Affected{{
		Package:  AffectedPackage{Ecosystem: ecosystem, Name: name},
		Versions: versions,
		Ranges:   ranges,
	}}}
}

func allVersions() Range {
	return Range{Type: "ECOSYSTEM", Events: []Event{{Introduced: "0"}}}
}

func TestIndexMatch(t *testing.T) {
	index := NewIndex(map[string]*Entry{
		"osv/malicious/npm/evil/MAL-1.json":    entry("MAL-1", EcosystemNPM, "evil", []string{"1.0.0"}),
		"osv/malicious/npm/@x/y/MAL-2.json":    entry("MAL-2", EcosystemNPM, "@x/y", nil, allVersions()),
		"osv/malicious/pypi/a/MAL-3.json":      entry("MAL-3", EcosystemPyPI, "Some_Pkg.Name", []string{"2.0"}),
		"osv/malicious/crates.io/b/MAL-4.json": entry("MAL-4", EcosystemCratesIO, "amzn-client", []string{"99.0.1"}),
		"osv/malicious/maven/c/MAL-5.json":     entry("MAL-5", EcosystemMaven, "io.evil:core", nil, allVersions()),
		"osv/malicious/go/d/MAL-6.json":        entry("MAL-6", EcosystemGo, "github.com/evil/mod", []string{"1.2.3"}),
		"osv/malicious/npm/r/MAL-7.json": entry("MAL-7", EcosystemNPM, "ranged", nil, Range{Type: "SEMVER", Events: []Event{
			{Fixed: "2.0.0"}, {Introduced: "1.0.0"}, {Introduced: "3.0.0"}, {LastAffected: "3.1.0"},
		}}),
		"osv/malicious/npm/w/MAL-8.json": {ID: "MAL-8", Withdrawn: "2026-01-01T00:00:00Z", Affected: []Affected{{
			Package: AffectedPackage{Ecosystem: EcosystemNPM, Name: "withdrawn"},
		}}},
		"osv/malicious/npm/n/MAL-9.json": entry("MAL-9", EcosystemNPM, "noversions", nil),
	}, nil)

	tests := []struct {
		name string
		pkg  Package
		want string
	}{
		{"exact version", Package{Ecosystem: EcosystemNPM, Name: "evil", Version: "1.0.0"}, "MAL-1"},
		{"other version", Package{Ecosystem: EcosystemNPM, Name: "evil", Version: "1.0.1"}, ""},
		{"scoped npm all versions", Package{Ecosystem: EcosystemNPM, Name: "@x/y", Version: "9.9.9"}, "MAL-2"},
		{"npm is case-insensitive", Package{Ecosystem: EcosystemNPM, Name: "EVIL", Version: "1.0.0"}, "MAL-1"},
		{"pypi PEP 503 name", Package{Ecosystem: EcosystemPyPI, Name: "some-pkg-name", Version: "2.0"}, "MAL-3"},
		{"crates underscore", Package{Ecosystem: EcosystemCratesIO, Name: "amzn_client", Version: "99.0.1"}, "MAL-4"},
		{"maven group:artifact", Package{Ecosystem: EcosystemMaven, Name: "io.evil:core", Version: "1.0"}, "MAL-5"},
		{"go v prefix", Package{Ecosystem: EcosystemGo, Name: "github.com/evil/mod", Version: "v1.2.3"}, "MAL-6"},
		{"ecosystem must match", Package{Ecosystem: EcosystemPyPI, Name: "evil", Version: "1.0.0"}, ""},
		{"below range", Package{Ecosystem: EcosystemNPM, Name: "ranged", Version: "0.9.0"}, ""},
		{"inside first range", Package{Ecosystem: EcosystemNPM, Name: "ranged", Version: "1.5.0"}, "MAL-7"},
		{"fixed is exclusive", Package{Ecosystem: EcosystemNPM, Name: "ranged", Version: "2.0.0"}, ""},
		{"last_affected is inclusive", Package{Ecosystem: EcosystemNPM, Name: "ranged", Version: "3.1.0"}, "MAL-7"},
		{"after last_affected", Package{Ecosystem: EcosystemNPM, Name: "ranged", Version: "3.1.1"}, ""},
		{"withdrawn is ignored", Package{Ecosystem: EcosystemNPM, Name: "withdrawn", Version: "1.0.0"}, ""},
		{"no versions means all", Package{Ecosystem: EcosystemNPM, Name: "noversions", Version: "4.0.0"}, "MAL-9"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := index.Match([]Package{tt.pkg})
			if tt.want == "" {
				if len(findings) != 0 {
					t.Fatalf("want no findings, got %+v", findings)
				}
				return
			}
			if len(findings) != 1 || findings[0].ID != tt.want {
				t.Fatalf("want %s, got %+v", tt.want, findings)
			}
			if findings[0].URL != "https://osv.dev/vulnerability/"+tt.want {
				t.Fatalf("unexpected url %q", findings[0].URL)
			}
		})
	}
}

func TestIndexEcosystemFilter(t *testing.T) {
	index := NewIndex(map[string]*Entry{
		"a": entry("MAL-1", EcosystemNPM, "evil", nil, allVersions()),
		"b": entry("MAL-2", EcosystemPyPI, "evil", nil, allVersions()),
	}, []string{EcosystemPyPI})
	if got := index.Match([]Package{{Ecosystem: EcosystemNPM, Name: "evil", Version: "1"}}); len(got) != 0 {
		t.Fatalf("npm should be filtered out, got %+v", got)
	}
	if got := index.Match([]Package{{Ecosystem: EcosystemPyPI, Name: "evil", Version: "1"}}); len(got) != 1 {
		t.Fatalf("pypi should match, got %+v", got)
	}
}

func TestIndexApply(t *testing.T) {
	base := NewIndex(map[string]*Entry{
		"a": entry("MAL-1", EcosystemNPM, "one", nil, allVersions()),
		"b": entry("MAL-2", EcosystemNPM, "two", nil, allVersions()),
	}, nil)
	next := base.Apply(map[string]*Entry{"c": entry("MAL-3", EcosystemNPM, "three", nil, allVersions())}, []string{"a"})

	pkgs := []Package{
		{Ecosystem: EcosystemNPM, Name: "one", Version: "1"},
		{Ecosystem: EcosystemNPM, Name: "three", Version: "1"},
	}
	if got := base.Match(pkgs); len(got) != 1 || got[0].ID != "MAL-1" {
		t.Fatalf("base must be unchanged, got %+v", got)
	}
	if got := next.Match(pkgs); len(got) != 1 || got[0].ID != "MAL-3" {
		t.Fatalf("next should only match MAL-3, got %+v", got)
	}
	if next.Len() != 2 {
		t.Fatalf("want 2 entries, got %d", next.Len())
	}
}

func TestNilIndex(t *testing.T) {
	var index *Index
	if index.Match([]Package{{Ecosystem: EcosystemNPM, Name: "x", Version: "1"}}) != nil {
		t.Fatal("nil index must match nothing")
	}
	if index.Len() != 0 {
		t.Fatal("nil index has no entries")
	}
}
