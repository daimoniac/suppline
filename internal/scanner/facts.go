package scanner

import (
	"encoding/json"
	"strings"

	"github.com/daimoniac/suppline/internal/types"
	"github.com/daimoniac/suppline/internal/vulnurl"
)

// trivyVendorSeverity accepts Trivy VendorSeverity values as either a severity
// name or the numeric code Trivy uses internally (0 unknown … 4 critical).
type trivyVendorSeverity map[string]string

func (s *trivyVendorSeverity) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		return nil
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	out := make(map[string]string, len(raw))
	for key, value := range raw {
		severity, ok := decodeTrivySeverity(value)
		if !ok || severity == "" {
			continue
		}
		out[strings.ToLower(key)] = severity
	}
	*s = out
	return nil
}

func decodeTrivySeverity(value json.RawMessage) (string, bool) {
	var name string
	if err := json.Unmarshal(value, &name); err == nil {
		return normalizeSeverity(name), true
	}
	var code int
	if err := json.Unmarshal(value, &code); err != nil {
		return "", false
	}
	switch code {
	case 1:
		return "LOW", true
	case 2:
		return "MEDIUM", true
	case 3:
		return "HIGH", true
	case 4:
		return "CRITICAL", true
	default:
		return "UNKNOWN", true
	}
}

func normalizeSeverity(name string) string {
	switch strings.ToUpper(strings.TrimSpace(name)) {
	case "LOW", "MEDIUM", "HIGH", "CRITICAL", "UNKNOWN":
		return strings.ToUpper(strings.TrimSpace(name))
	default:
		return ""
	}
}

type trivyCVSSInfo struct {
	V2Vector  string `json:"V2Vector"`
	V3Vector  string `json:"V3Vector"`
	V40Vector string `json:"V40Vector"`
}

// vendorSeverityAliases maps a Trivy OS family to other VendorSeverity keys
// that publish the same distro rating. NVD is never an alias: it restates the
// scanner severity.
var vendorSeverityAliases = map[string][]string{
	"centos":              {"redhat"},
	"rocky":               {"redhat"},
	"alma":                {"redhat"},
	"fedora":              {"redhat"},
	"amzn":                {"amazon"},
	"amazon":              {"amzn"},
	"opensuse":            {"suse"},
	"opensuse.leap":       {"suse"},
	"opensuse.tumbleweed": {"suse"},
	"sles":                {"suse"},
	"azure":               {"cbl-mariner", "redhat"},
	"mariner":             {"cbl-mariner"},
}

func findingsFromTrivy(response trivyScanResponse) ([]types.Vulnerability, bool) {
	family := response.Metadata.OS.Family
	vulns := make([]types.Vulnerability, 0)
	for _, result := range response.Results {
		for _, vuln := range result.Vulnerabilities {
			vulns = append(vulns, vulnerabilityFromTrivy(vuln, family))
		}
	}
	return vulns, response.Metadata.OS.EOSL
}

func vulnerabilityFromTrivy(vuln trivyVulnerability, osFamily string) types.Vulnerability {
	primaryURL := vuln.PrimaryURL
	if primaryURL == "" && len(vuln.References) > 0 {
		primaryURL = vuln.References[0]
	}
	return types.Vulnerability{
		ID:             vuln.VulnerabilityID,
		Severity:       vuln.Severity,
		PackageName:    vuln.PkgName,
		Version:        vuln.InstalledVersion,
		FixedVersion:   vuln.FixedVersion,
		Title:          vuln.Title,
		Description:    vuln.Description,
		PrimaryURL:     vulnurl.NormalizeRefURL(primaryURL),
		VendorStatus:   strings.TrimSpace(vuln.Status),
		VendorSeverity: distroSeverity(osFamily, vuln.VendorSeverity),
		AttackVector:   attackVector(osFamily, vuln.CVSS),
	}
}

func distroSeverity(osFamily string, vendors trivyVendorSeverity) string {
	if len(vendors) == 0 {
		return ""
	}
	family := strings.ToLower(strings.TrimSpace(osFamily))
	if family == "" || family == "nvd" || family == "ghsa" {
		return ""
	}
	if severity, ok := vendors[family]; ok {
		return severity
	}
	for _, alias := range vendorSeverityAliases[family] {
		if severity, ok := vendors[alias]; ok {
			return severity
		}
	}
	return ""
}

func attackVector(osFamily string, sources map[string]trivyCVSSInfo) string {
	if len(sources) == 0 {
		return ""
	}
	lower := make(map[string]trivyCVSSInfo, len(sources))
	for key, info := range sources {
		lower[strings.ToLower(key)] = info
	}
	family := strings.ToLower(strings.TrimSpace(osFamily))
	if vector := attackVectorOf(lower[family]); vector != "" {
		return vector
	}
	for _, alias := range vendorSeverityAliases[family] {
		if vector := attackVectorOf(lower[alias]); vector != "" {
			return vector
		}
	}
	return attackVectorOf(lower["nvd"])
}

func attackVectorOf(info trivyCVSSInfo) string {
	for _, vector := range []string{info.V3Vector, info.V40Vector, info.V2Vector} {
		if parsed := parseAttackVector(vector); parsed != "" {
			return parsed
		}
	}
	return ""
}

func parseAttackVector(vector string) string {
	for _, part := range strings.Split(vector, "/") {
		part = strings.TrimSpace(part)
		if !strings.HasPrefix(part, "AV:") || len(part) < 4 {
			continue
		}
		switch strings.ToUpper(part[3:]) {
		case "N":
			return "NETWORK"
		case "A":
			return "ADJACENT"
		case "L":
			return "LOCAL"
		case "P":
			return "PHYSICAL"
		default:
			return ""
		}
	}
	return ""
}
