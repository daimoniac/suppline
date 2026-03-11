package worker

import (
	"strings"
	"time"

	"github.com/daimoniac/suppline/internal/policy"
	"github.com/daimoniac/suppline/internal/queue"
	"github.com/daimoniac/suppline/internal/scanner"
	"github.com/daimoniac/suppline/internal/statestore"
	"github.com/daimoniac/suppline/internal/types"
)

// buildScanRecord constructs a ScanRecord from workflow results using canonical types.
func buildScanRecord(
	task *queue.ScanTask,
	scanResult *scanner.ScanResult,
	policyDecision *policy.PolicyDecision,
	scannedAt time.Time,
) *statestore.ScanRecord {
	// Count vulnerabilities by severity and convert to records
	var criticalCount, highCount, mediumCount, lowCount int
	scannedAtUnix := scannedAt.Unix()
	vulnerabilityRecords := make([]types.VulnerabilityRecord, 0, len(scanResult.Vulnerabilities))

	for _, vuln := range scanResult.Vulnerabilities {
		// Count by severity
		switch vuln.Severity {
		case "CRITICAL":
			criticalCount++
		case "HIGH":
			highCount++
		case "MEDIUM":
			mediumCount++
		case "LOW":
			lowCount++
		}

		// Convert to VulnerabilityRecord with image context
		vulnerabilityRecords = append(vulnerabilityRecords, types.ToVulnerabilityRecord(
			vuln,
			task.Repository,
			task.Tag,
			task.Digest,
			scannedAtUnix,
		))
	}

	// Build tolerated set from policy decision
	toleratedSet := make(map[string]bool)
	for _, toleratedID := range policyDecision.ToleratedCVEs {
		toleratedSet[toleratedID] = true
	}

	// Filter and convert tolerations
	toleratedCVEs := types.FilterToleratedCVEs(
		task.Tolerations,
		toleratedSet,
		scannedAtUnix,
	)

	return &statestore.ScanRecord{
		Digest:            task.Digest,
		Repository:        task.Repository,
		Tag:               task.Tag,
		CreatedAt:         scannedAtUnix,
		ScanDurationMs:    0, // Will be calculated by pipeline
		CriticalVulnCount: criticalCount,
		HighVulnCount:     highCount,
		MediumVulnCount:   mediumCount,
		LowVulnCount:      lowCount,
		PolicyPassed:      policyDecision.Passed,
		SBOMAttested:      true,
		VulnAttested:      true,
		SCAIAttested:      false, // Will be set by pipeline if SCAI attestation succeeds
		Vulnerabilities:   vulnerabilityRecords,
		ToleratedCVEs:     toleratedCVEs,
		ErrorMessage:      "",
	}
}

// extractRepository extracts the repository from an image reference
func extractRepository(imageRef string) string {
	// Format: repository@digest
	parts := strings.Split(imageRef, "@")
	if len(parts) > 0 {
		return parts[0]
	}
	return imageRef
}

// extractDigest extracts the digest from an image reference
func extractDigest(imageRef string) string {
	// Format: repository@digest
	parts := strings.Split(imageRef, "@")
	if len(parts) > 1 {
		return parts[1]
	}
	return ""
}
