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
// attestResult may be nil when no attestation phase was run (e.g. error-record paths);
// in that case the attestation flags default to false.
func buildScanRecord(
	task *queue.ScanTask,
	scanResult *scanner.ScanResult,
	policyDecision *policy.PolicyDecision,
	attestResult *attestationResult,
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

	// Build exempted set from policy decision
	exemptedSet := make(map[string]bool)
	for _, exemptedID := range policyDecision.ExemptedCVEs {
		exemptedSet[exemptedID] = true
	}

	imageCreatedAt := int64(0)
	if scanResult.ImageCreatedAt != nil {
		imageCreatedAt = scanResult.ImageCreatedAt.Unix()
	}

	// Filter and convert VEX statements
	appliedVEX := types.FilterAppliedVEXStatements(
		task.VEXStatements,
		exemptedSet,
		scannedAtUnix,
	)

	// Attestation flags reflect the actual outcome of the attestation phase.
	// SBOM and Vuln attestation failures abort the pipeline before persistence,
	// so reaching here with ShouldAttest=true means those two succeeded. SCAI
	// and VEX are optional/conditional, so we read their actual success from
	// attestResult to avoid recording false negatives/positives.
	sbomAttested := policyDecision.ShouldAttest
	vulnAttested := policyDecision.ShouldAttest
	var scaiAttested, vexAttested bool
	if attestResult != nil {
		scaiAttested = attestResult.SCAIAttested
		vexAttested = attestResult.VEXAttested
	}

	return &statestore.ScanRecord{
		Digest:                   task.Digest,
		Repository:               task.Repository,
		Tag:                      task.Tag,
		CreatedAt:                scannedAtUnix,
		ImageCreatedAt:           imageCreatedAt,
		ScanDurationMs:           0, // Will be calculated by pipeline
		CriticalVulnCount:        criticalCount,
		HighVulnCount:            highCount,
		MediumVulnCount:          mediumCount,
		LowVulnCount:             lowCount,
		PolicyPassed:             policyDecision.Passed,
		PolicyStatus:             policyDecision.Status,
		PolicyReason:             policyDecision.Reason,
		ReleaseAgeSeconds:        policyDecision.ReleaseAgeSeconds,
		MinimumReleaseAgeSeconds: policyDecision.MinimumReleaseAgeSeconds,
		ReleaseAgeSource:         policyDecision.ReleaseAgeSource,
		SBOMAttested:             sbomAttested,
		VulnAttested:             vulnAttested,
		SCAIAttested:             scaiAttested,
		VEXAttested:              vexAttested,
		Vulnerabilities:          vulnerabilityRecords,
		AppliedVEXStatements:     appliedVEX,
		PolicyFailureFindings:    policyDecision.PolicyFailureFindings,
		ErrorMessage:             "",
	}
}

// buildErrorScanRecord constructs a ScanRecord representing a permanently failed scan.
// This is used when the scan phase itself fails (e.g. Trivy error after all retries) so
// the image still appears in the UI with a visible error state.
func buildErrorScanRecord(task *queue.ScanTask, scanErr error) *statestore.ScanRecord {
	return &statestore.ScanRecord{
		Digest:     task.Digest,
		Repository: task.Repository,
		Tag:        task.Tag,
		CreatedAt:  time.Now().Unix(),
		// Zero vuln counts – we never got results
		PolicyPassed: false,
		PolicyStatus: policy.PolicyStatusFailed,
		PolicyReason: scanErr.Error(),
		ErrorMessage: scanErr.Error(),
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
