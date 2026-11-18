package malicious

import (
	"encoding/json"
	"fmt"

	"github.com/package-url/packageurl-go"
)

type cycloneDXDocument struct {
	Components []cycloneDXComponent `json:"components"`
}

type cycloneDXComponent struct {
	PURL       string               `json:"purl"`
	Components []cycloneDXComponent `json:"components"`
}

// PackagesFromCycloneDX returns the language packages in a CycloneDX JSON SBOM
// whose purl type maps to a supported ecosystem. OS packages and components
// without a usable purl are skipped. Duplicates are dropped.
func PackagesFromCycloneDX(data []byte) ([]Package, error) {
	var doc cycloneDXDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("decode cyclonedx sbom: %w", err)
	}
	seen := make(map[string]bool)
	var packages []Package
	var walk func([]cycloneDXComponent)
	walk = func(components []cycloneDXComponent) {
		for _, component := range components {
			if pkg, ok := packageFromPURL(component.PURL); ok && !seen[pkg.PURL] {
				seen[pkg.PURL] = true
				packages = append(packages, pkg)
			}
			walk(component.Components)
		}
	}
	walk(doc.Components)
	return packages, nil
}

// packageFromPURL converts a purl to a Package in OSV naming.
func packageFromPURL(raw string) (Package, bool) {
	if raw == "" {
		return Package{}, false
	}
	purl, err := packageurl.FromString(raw)
	if err != nil {
		return Package{}, false
	}
	ecosystem, ok := purlTypeEcosystem[purl.Type]
	if !ok || purl.Name == "" || purl.Version == "" {
		return Package{}, false
	}
	name := purl.Name
	if purl.Namespace != "" {
		switch ecosystem {
		case EcosystemMaven:
			name = purl.Namespace + ":" + purl.Name
		case EcosystemNPM, EcosystemGo, EcosystemPackagist:
			name = purl.Namespace + "/" + purl.Name
		}
	}
	return Package{Ecosystem: ecosystem, Name: name, Version: purl.Version, PURL: raw}, true
}
