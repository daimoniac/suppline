package types

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
		PrimaryURL:       vuln.PrimaryURL,
		Repository:       repository,
		Tag:              tag,
		Digest:           digest,
		ScannedAt:        scannedAt,
	}
}

// FilterToleratedCVEs filters tolerations based on a set of tolerated IDs.
// Only tolerations whose IDs are in the toleratedSet will be included.
func FilterToleratedCVEs(
	tolerations []CVEToleration,
	toleratedSet map[string]bool,
	toleratedAt int64,
) []ToleratedCVE {
	filtered := make([]ToleratedCVE, 0, len(tolerations))
	for _, toleration := range tolerations {
		if toleratedSet[toleration.ID] {
			filtered = append(filtered, ToleratedCVE{
				CVEID:       toleration.ID,
				Statement:   toleration.Statement,
				ToleratedAt: toleratedAt,
				ExpiresAt:   toleration.ExpiresAt,
			})
		}
	}
	return filtered
}
