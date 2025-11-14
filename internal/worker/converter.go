package worker

import (
	"strings"
	"time"

	"github.com/suppline/suppline/internal/policy"
	"github.com/suppline/suppline/internal/queue"
	"github.com/suppline/suppline/internal/scanner"
	"github.com/suppline/suppline/internal/statestore"
	"github.com/suppline/suppline/internal/types"
)

// ScanRecordBuilder constructs StateStore ScanRecords from workflow results.
// This replaces the scattered buildScanRecord logic with a centralized builder.
type ScanRecordBuilder struct {
	vulnConverter       *types.VulnerabilityConverter
	tolerationConverter *types.TolerationConverter
}

// NewScanRecordBuilder creates a new ScanRecordBuilder instance.
func NewScanRecordBuilder() *ScanRecordBuilder {
	return &ScanRecordBuilder{
		vulnConverter:       types.NewVulnerabilityConverter(),
		tolerationConverter: types.NewTolerationConverter(),
	}
}

// Build constructs a ScanRecord from workflow results using canonical types.
func (b *ScanRecordBuilder) Build(
	task *queue.ScanTask,
	scanResult *scanner.ScanResult,
	policyDecision *policy.PolicyDecision,
	signed bool,
	scannedAt time.Time,
) *statestore.ScanRecord {
	// Scanner vulnerabilities are already canonical types (via type alias)
	// No conversion needed!
	canonicalVulns := scanResult.Vulnerabilities

	// Count vulnerabilities by severity and convert to records
	var criticalCount, highCount, mediumCount, lowCount int
	vulnerabilityRecords := make([]statestore.VulnerabilityRecord, 0, len(canonicalVulns))

	for _, vuln := range canonicalVulns {
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
		// Since statestore now uses canonical types, we can use it directly
		vulnerabilityRecords = append(vulnerabilityRecords, b.vulnConverter.ToVulnerabilityRecord(
			vuln,
			task.Repository,
			task.Tag,
			task.Digest,
			scannedAt,
		))
	}

	// Queue tolerations are already canonical types (via type alias)
	// No conversion needed!
	canonicalTolerations := task.Tolerations

	// Build tolerated set from policy decision
	toleratedSet := make(map[string]bool)
	for _, toleratedID := range policyDecision.ToleratedCVEs {
		toleratedSet[toleratedID] = true
	}

	// Filter and convert tolerations
	// Since statestore now uses canonical types, we can use them directly
	toleratedCVEs := b.tolerationConverter.FilterToleratedCVEs(
		canonicalTolerations,
		toleratedSet,
		scannedAt,
	)

	return &statestore.ScanRecord{
		Digest:            task.Digest,
		Repository:        task.Repository,
		Tag:               task.Tag,
		ScannedAt:         scannedAt,
		CriticalVulnCount: criticalCount,
		HighVulnCount:     highCount,
		MediumVulnCount:   mediumCount,
		LowVulnCount:      lowCount,
		PolicyPassed:      policyDecision.Passed,
		Signed:            signed,
		SBOMAttested:      true,
		VulnAttested:      true,
		Vulnerabilities:   vulnerabilityRecords,
		ToleratedCVEs:     toleratedCVEs,
		ErrorMessage:      "",
	}
}

// Note: No conversion functions needed anymore!
// Since scanner.Vulnerability = types.Vulnerability (type alias)
// and queue.CVEToleration = types.CVEToleration (type alias),
// we can use them directly without any conversion.

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
