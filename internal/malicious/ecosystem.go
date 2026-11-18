package malicious

import (
	"regexp"
	"strings"
)

// OSV ecosystem names that ossf/malicious-packages publishes and that map to
// purl types found in container SBOMs.
const (
	EcosystemNPM       = "npm"
	EcosystemPyPI      = "PyPI"
	EcosystemRubyGems  = "RubyGems"
	EcosystemNuGet     = "NuGet"
	EcosystemCratesIO  = "crates.io"
	EcosystemGo        = "Go"
	EcosystemMaven     = "Maven"
	EcosystemPackagist = "Packagist"
)

// DefaultEcosystems is every ecosystem the matcher understands.
var DefaultEcosystems = []string{
	EcosystemNPM, EcosystemPyPI, EcosystemRubyGems, EcosystemNuGet,
	EcosystemCratesIO, EcosystemGo, EcosystemMaven, EcosystemPackagist,
}

// purlTypeEcosystem maps purl types to OSV ecosystems.
var purlTypeEcosystem = map[string]string{
	"npm":      EcosystemNPM,
	"pypi":     EcosystemPyPI,
	"gem":      EcosystemRubyGems,
	"nuget":    EcosystemNuGet,
	"cargo":    EcosystemCratesIO,
	"golang":   EcosystemGo,
	"maven":    EcosystemMaven,
	"composer": EcosystemPackagist,
}

// KnownEcosystem reports whether name is an ecosystem the matcher supports.
func KnownEcosystem(name string) bool {
	for _, known := range DefaultEcosystems {
		if known == name {
			return true
		}
	}
	return false
}

// ecosystemDir is the directory under osv/malicious that holds an ecosystem.
func ecosystemDir(ecosystem string) string {
	return strings.ToLower(ecosystem)
}

var pypiSeparators = regexp.MustCompile(`[-_.]+`)

// normalizeName folds a package name to the form both sides are compared in,
// following each registry's own equivalence rules.
func normalizeName(ecosystem, name string) string {
	name = strings.TrimSpace(name)
	switch ecosystem {
	case EcosystemPyPI:
		// PEP 503.
		return pypiSeparators.ReplaceAllString(strings.ToLower(name), "-")
	case EcosystemCratesIO:
		// crates.io treats - and _ as the same name.
		return strings.ReplaceAll(strings.ToLower(name), "_", "-")
	case EcosystemNPM, EcosystemNuGet, EcosystemPackagist:
		return strings.ToLower(name)
	default:
		return name
	}
}

// normalizeVersion strips prefixes that the SBOM carries but OSV does not.
func normalizeVersion(ecosystem, version string) string {
	version = strings.TrimSpace(version)
	if ecosystem == EcosystemGo {
		return strings.TrimPrefix(version, "v")
	}
	return version
}
