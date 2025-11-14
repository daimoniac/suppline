package types

import (
	"time"
)

// ToVulnerabilityRecord converts a Vulnerability to a VulnerabilityRecord with image context.
func ToVulnerabilityRecord(
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
func ToVulnerabilityRecords(
	vulns []Vulnerability,
	repository, tag, digest string,
	scannedAt time.Time,
) []VulnerabilityRecord {
	records := make([]VulnerabilityRecord, len(vulns))
	for i, vuln := range vulns {
		records[i] = ToVulnerabilityRecord(vuln, repository, tag, digest, scannedAt)
	}
	return records
}

// ToToleratedCVE converts a CVEToleration to a ToleratedCVE with timestamp.
func ToToleratedCVE(
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
func ToToleratedCVEs(
	tolerations []CVEToleration,
	toleratedAt time.Time,
) []ToleratedCVE {
	records := make([]ToleratedCVE, len(tolerations))
	for i, toleration := range tolerations {
		records[i] = ToToleratedCVE(toleration, toleratedAt)
	}
	return records
}

// FilterToleratedCVEs filters tolerations based on a set of tolerated IDs.
// Only tolerations whose IDs are in the toleratedSet will be included.
func FilterToleratedCVEs(
	tolerations []CVEToleration,
	toleratedSet map[string]bool,
	toleratedAt time.Time,
) []ToleratedCVE {
	filtered := make([]ToleratedCVE, 0, len(tolerations))
	for _, toleration := range tolerations {
		if toleratedSet[toleration.ID] {
			filtered = append(filtered, ToToleratedCVE(toleration, toleratedAt))
		}
	}
	return filtered
}

// ToTolerationInfo converts a ToleratedCVE to TolerationInfo with repository context.
func ToTolerationInfo(
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
