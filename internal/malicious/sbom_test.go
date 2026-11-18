package malicious

import (
	"reflect"
	"testing"
)

const trivySBOM = `{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "components": [
    {"type": "operating-system", "name": "debian"},
    {"type": "library", "name": "libc6", "purl": "pkg:deb/debian/libc6@2.36-9?arch=amd64&distro=debian-12.5"},
    {"type": "library", "name": "y", "purl": "pkg:npm/%40x/y@1.2.3"},
    {"type": "library", "name": "y", "purl": "pkg:npm/%40x/y@1.2.3"},
    {"type": "library", "name": "requests", "purl": "pkg:pypi/requests@2.31.0"},
    {"type": "application", "name": "app.jar", "components": [
      {"type": "library", "name": "core", "purl": "pkg:maven/io.evil/core@1.0?type=jar"}
    ]},
    {"type": "library", "name": "mod", "purl": "pkg:golang/github.com/evil/mod@v1.2.3"},
    {"type": "library", "name": "pkg", "purl": "pkg:composer/vendor/pkg@1.0.0"},
    {"type": "library", "name": "crate", "purl": "pkg:cargo/amzn_client@99.0.1"},
    {"type": "library", "name": "gem", "purl": "pkg:gem/rails@7.1.0"},
    {"type": "library", "name": "nuget", "purl": "pkg:nuget/Newtonsoft.Json@13.0.1"},
    {"type": "library", "name": "noversion", "purl": "pkg:npm/noversion"},
    {"type": "library", "name": "broken", "purl": "not a purl"}
  ]
}`

func TestPackagesFromCycloneDX(t *testing.T) {
	got, err := PackagesFromCycloneDX([]byte(trivySBOM))
	if err != nil {
		t.Fatal(err)
	}
	want := []Package{
		{Ecosystem: EcosystemNPM, Name: "@x/y", Version: "1.2.3", PURL: "pkg:npm/%40x/y@1.2.3"},
		{Ecosystem: EcosystemPyPI, Name: "requests", Version: "2.31.0", PURL: "pkg:pypi/requests@2.31.0"},
		{Ecosystem: EcosystemMaven, Name: "io.evil:core", Version: "1.0", PURL: "pkg:maven/io.evil/core@1.0?type=jar"},
		{Ecosystem: EcosystemGo, Name: "github.com/evil/mod", Version: "v1.2.3", PURL: "pkg:golang/github.com/evil/mod@v1.2.3"},
		{Ecosystem: EcosystemPackagist, Name: "vendor/pkg", Version: "1.0.0", PURL: "pkg:composer/vendor/pkg@1.0.0"},
		{Ecosystem: EcosystemCratesIO, Name: "amzn_client", Version: "99.0.1", PURL: "pkg:cargo/amzn_client@99.0.1"},
		{Ecosystem: EcosystemRubyGems, Name: "rails", Version: "7.1.0", PURL: "pkg:gem/rails@7.1.0"},
		{Ecosystem: EcosystemNuGet, Name: "Newtonsoft.Json", Version: "13.0.1", PURL: "pkg:nuget/Newtonsoft.Json@13.0.1"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("packages mismatch\n got: %+v\nwant: %+v", got, want)
	}
}

func TestPackagesFromCycloneDXInvalid(t *testing.T) {
	if _, err := PackagesFromCycloneDX([]byte("{")); err == nil {
		t.Fatal("want error for invalid json")
	}
}

func TestSBOMToMatch(t *testing.T) {
	packages, err := PackagesFromCycloneDX([]byte(trivySBOM))
	if err != nil {
		t.Fatal(err)
	}
	index := NewIndex(map[string]*Entry{
		"a": entry("MAL-1", EcosystemNPM, "@x/y", []string{"1.2.3"}),
		"b": entry("MAL-2", EcosystemCratesIO, "amzn-client", []string{"99.0.1"}),
		"c": entry("MAL-3", EcosystemGo, "github.com/evil/mod", []string{"1.2.3"}),
	}, nil)
	findings := index.Match(packages)
	var ids []string
	for _, f := range findings {
		ids = append(ids, f.ID)
	}
	if !reflect.DeepEqual(ids, []string{"MAL-1", "MAL-2", "MAL-3"}) {
		t.Fatalf("got %v", ids)
	}
}
