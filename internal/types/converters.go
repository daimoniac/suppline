package types

import (
	"time"
)

// VulnerabilityConverter provides conversion methods for Vulnerability types.
type VulnerabilityConverter struct{}

// NewVulnerabilityConverter creates a new VulnerabilityConverter instance.
func NewVulnerabilityConverter() *VulnerabilityConverter {
	return &VulnerabilityConverter{}
}

// ToVulnerabilityRecord converts a Vulnerability to a VulnerabilityRecord with image context.
func (c *VulnerabilityConverter) ToVulnerabilityRecord(
	vuln Vulnerability,
	repository, tag, digest string,
	scannedAt time.Time,
) VulnerabilityRecord {
	return VulnerabilityRecord{
		CVEID:            vuln.ID,
		Severity:         vuln.Severity,
		PackageName:      vuln.PackageName,
		InstalledVersion: vuln.Version,
		FixedVersion:     vuln.FixedVersion,
		Title:            vuln.Title,
		Description:      vuln.Description,
		PrimaryURL:       vuln.PrimaryURL,
		Repository:       repository,
		Tag:              tag,
		Digest:           digest,
		ScannedAt:        scannedAt,
	}
}

// ToVulnerabilityRecords converts a slice of Vulnerabilities to VulnerabilityRecords.
func (c *VulnerabilityConverter) ToVulnerabilityRecords(
	vulns []Vulnerability,
	repository, tag, digest string,
	scannedAt time.Time,
) []VulnerabilityRecord {
	records := make([]VulnerabilityRecord, len(vulns))
	for i, vuln := range vulns {
		records[i] = c.ToVulnerabilityRecord(vuln, repository, tag, digest, scannedAt)
	}
	return records
}

// TolerationConverter provides conversion methods for CVEToleration types.
type TolerationConverter struct{}

// NewTolerationConverter creates a new TolerationConverter instance.
func NewTolerationConverter() *TolerationConverter {
	return &TolerationConverter{}
}

// ToToleratedCVE converts a CVEToleration to a ToleratedCVE with timestamp.
func (c *TolerationConverter) ToToleratedCVE(
	toleration CVEToleration,
	toleratedAt time.Time,
) ToleratedCVE {
	return ToleratedCVE{
		CVEID:       toleration.ID,
		Statement:   toleration.Statement,
		ToleratedAt: toleratedAt,
		ExpiresAt:   toleration.ExpiresAt,
	}
}

// ToToleratedCVEs converts a slice of CVETolerations to ToleratedCVEs.
func (c *TolerationConverter) ToToleratedCVEs(
	tolerations []CVEToleration,
	toleratedAt time.Time,
) []ToleratedCVE {
	records := make([]ToleratedCVE, len(tolerations))
	for i, toleration := range tolerations {
		records[i] = c.ToToleratedCVE(toleration, toleratedAt)
	}
	return records
}

// FilterToleratedCVEs filters tolerations based on a set of tolerated IDs.
// Only tolerations whose IDs are in the toleratedSet will be included.
func (c *TolerationConverter) FilterToleratedCVEs(
	tolerations []CVEToleration,
	toleratedSet map[string]bool,
	toleratedAt time.Time,
) []ToleratedCVE {
	filtered := make([]ToleratedCVE, 0, len(tolerations))
	for _, toleration := range tolerations {
		if toleratedSet[toleration.ID] {
			filtered = append(filtered, c.ToToleratedCVE(toleration, toleratedAt))
		}
	}
	return filtered
}

// ToTolerationInfo converts a ToleratedCVE to TolerationInfo with repository context.
func (c *TolerationConverter) ToTolerationInfo(
	tolerated ToleratedCVE,
	repository string,
) TolerationInfo {
	return TolerationInfo{
		CVEID:       tolerated.CVEID,
		Statement:   tolerated.Statement,
		ToleratedAt: tolerated.ToleratedAt,
		ExpiresAt:   tolerated.ExpiresAt,
		Repository:  repository,
	}
}
