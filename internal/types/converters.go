package types

import "github.com/daimoniac/suppline/internal/vulnurl"

// ToVulnerabilityRecord converts a Vulnerability to a VulnerabilityRecord with image context.
func ToVulnerabilityRecord(
	vuln Vulnerability,
	repository, tag, digest string,
	scannedAt int64,
) VulnerabilityRecord {
	return VulnerabilityRecord{
		CVEID:            vuln.ID,
		Severity:         vuln.Severity,
		PackageName:      vuln.PackageName,
		InstalledVersion: vuln.Version,
		FixedVersion:     vuln.FixedVersion,
		Title:            vuln.Title,
		Description:      vuln.Description,
		PrimaryURL:       vulnurl.NormalizeRefURL(vuln.PrimaryURL),
		Repository:       repository,
		Tag:              tag,
		Digest:           digest,
		ScannedAt:        scannedAt,
	}
}
