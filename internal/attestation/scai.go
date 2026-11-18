package attestation

import (
	"context"
	"log/slog"
	"strings"
	"time"

	"github.com/daimoniac/suppline/internal/config"
	"github.com/daimoniac/suppline/internal/errors"
	"github.com/daimoniac/suppline/internal/policy"
	"github.com/daimoniac/suppline/internal/policy/catalog"
	"github.com/daimoniac/suppline/internal/scanner"
	"github.com/daimoniac/suppline/internal/types"
)

// SCAIGenerator creates SCAI attestation predicates
type SCAIGenerator struct {
	config  config.Source
	catalog catalog.Catalog
	logger  *slog.Logger
}

// NewSCAIGenerator creates a new SCAI generator
func NewSCAIGenerator(cfg *config.RegsyncConfig, logger *slog.Logger) *SCAIGenerator {
	return NewSCAIGeneratorWithCatalog(config.Static(cfg), catalog.NewConfigCatalog(cfg), logger)
}

// NewSCAIGeneratorWithCatalog creates an SCAI generator with a shared policy catalog.
func NewSCAIGeneratorWithCatalog(currentConfig config.Source, policyCatalog catalog.Catalog, logger *slog.Logger) *SCAIGenerator {
	if logger == nil {
		logger = slog.Default()
	}

	return &SCAIGenerator{
		config:  currentConfig,
		catalog: policyCatalog,
		logger:  logger,
	}
}

// convertToPURL converts an OCI image reference to PURL format
// Input:  myprivateregistry/nginx@sha256:abc123...
// Output: pkg:docker/myprivateregistry/nginx@sha256:abc123...
// Input:  registry.example.com/myorg/app@sha256:def456...
// Output: pkg:docker/registry.example.com/myorg/app@sha256:def456...
func convertToPURL(imageRef string) (string, error) {
	// Image reference should contain @ for digest
	if !strings.Contains(imageRef, "@") {
		return "", errors.NewPermanentf("image reference must contain digest: %s", imageRef)
	}

	// Simply prepend pkg:docker/ to the image reference
	return "pkg:docker/" + imageRef, nil
}

// calculateValidityWindow calculates the validUntil timestamp by adding the rescan interval
// plus the validity extension to the scan timestamp.
// The validity extension provides a grace period beyond the next scheduled scan.
// Falls back to 7d rescan interval + 1d extension if values cannot be determined.
func (g *SCAIGenerator) calculateValidityWindow(scanTime time.Time, target string) time.Time {
	interval, err := g.config().GetRescanInterval(target)
	if err != nil {
		g.logger.Warn("failed to get rescan interval, using default 7d",
			"target", target,
			"error", err)
		interval = 7 * 24 * time.Hour
	}

	extension, err := g.config().GetSCAIValidityExtension(target)
	if err != nil {
		g.logger.Warn("failed to get SCAI validity extension, using default 1d",
			"target", target,
			"error", err)
		extension = 24 * time.Hour
	}

	validUntil := scanTime.Add(interval).Add(extension)

	g.logger.Debug("calculated SCAI validity window",
		"target", target,
		"rescan_interval", interval,
		"validity_extension", extension,
		"valid_until", validUntil.Format(time.RFC3339))

	return validUntil
}

// matchExemptedVulnerabilities filters scan results against configured VEX statements
// and builds a list of VEX-exempted vulnerabilities with full details
func (g *SCAIGenerator) matchExemptedVulnerabilities(scanResult *scanner.ScanResult, target string) []SCAIAttributeItem {
	var attributes []SCAIAttributeItem

	for _, vuln := range scanResult.Vulnerabilities {
		exempted, stmt := g.catalog.IsExempted(target, vuln.ID, time.Now())
		if exempted && stmt != nil {
			evidence := SCAIExemptedVulnEvidence{
				CVEID:         vuln.ID,
				Severity:      vuln.Severity,
				PackageName:   vuln.PackageName,
				Version:       vuln.Version,
				FixedVersion:  vuln.FixedVersion,
				Description:   vuln.Description,
				State:         string(stmt.State),
				Justification: string(stmt.Justification),
				Detail:        stmt.Detail,
			}

			if stmt.ExpiresAt != nil {
				evidence.ExpiresAt = stmt.ExpiresAt
			}

			attributes = append(attributes, SCAIAttributeItem{
				Attribute: SCAIAttributeExemptedVulnerability,
				Evidence:  evidence,
			})
		}
	}

	return attributes
}

// GenerateSCAI creates an SCAI attestation predicate from scan results
// Parameters:
//   - ctx: context for cancellation
//   - imageRef: full image reference with digest
//   - scanResult: vulnerability scan results
//   - target: target repository from regsync config (for VEX lookup)
//   - policyDecision: policy evaluation result to determine scan status
//
// Returns: SCAI attestation structure ready for JSON serialization
func (g *SCAIGenerator) GenerateSCAI(
	ctx context.Context,
	imageRef string,
	scanResult *scanner.ScanResult,
	target string,
	policyDecision *policy.PolicyDecision,
) (*SCAIAttestation, error) {
	if scanResult == nil {
		return nil, errors.NewPermanentf("scan result is nil")
	}

	// Convert image reference to PURL format
	purl, err := convertToPURL(imageRef)
	if err != nil {
		return nil, errors.NewPermanentf("failed to convert image reference to PURL: %w", err)
	}

	// Calculate validity window
	validUntil := g.calculateValidityWindow(scanResult.ScannedAt, target)

	// Match VEX-exempted vulnerabilities
	attributes := g.matchExemptedVulnerabilities(scanResult, target)
	exemptedCount := len(attributes)

	// Determine scan status based on policy decision
	scanStatus := "passed"
	if policyDecision != nil {
		if !policyDecision.Passed {
			scanStatus = "failed"
		} else if exemptedCount > 0 {
			scanStatus = "passed-with-exceptions"
		}
	} else if exemptedCount > 0 {
		scanStatus = "passed-with-exceptions"
	}

	var exemptedIDs []string
	if policyDecision != nil {
		exemptedIDs = policyDecision.ExemptedCVEs
	}
	maliciousCheck := policy.MarkExemptedMalicious(scanResult.Malicious, exemptedIDs)
	if policyDecision != nil && policyDecision.Passed && scanStatus == "passed" && hasExemptedMalicious(maliciousCheck) {
		scanStatus = "passed-with-exceptions"
	}
	if check := maliciousCheckAttribute(maliciousCheck); check != nil {
		attributes = append(attributes, *check)
	}

	// Assemble complete SCAI attestation
	scai := &SCAIAttestation{
		Attribute: "container-security-assessment",
		Target: SCAITarget{
			URI: purl,
		},
		Evidence: SCAIEvidence{
			LastScanned: scanResult.ScannedAt,
			ValidUntil:  validUntil,
			ScanStatus:  scanStatus,
		},
		Attributes: attributes,
	}

	g.logger.Info("generated SCAI attestation",
		"image_ref", imageRef,
		"scan_status", scanStatus,
		"exempted_count", exemptedCount,
		"valid_until", validUntil.Format(time.RFC3339))

	return scai, nil
}

// maliciousCheckAttribute records the malicious-package check, or nil when
// the check is disabled. A clean result is recorded too: "checked, nothing
// found, as of this snapshot" is evidence worth signing.
func maliciousCheckAttribute(check *types.MaliciousCheck) *SCAIAttributeItem {
	if check == nil {
		return nil
	}
	evidence := SCAIMaliciousCheckEvidence{
		Status:         check.Status,
		SnapshotCommit: check.Commit,
		Findings:       make([]SCAIMaliciousFinding, 0, len(check.Findings)),
	}
	if check.SnapshotAt > 0 {
		at := time.Unix(check.SnapshotAt, 0).UTC()
		evidence.SnapshotAt = &at
	}
	for _, finding := range check.Findings {
		evidence.Findings = append(evidence.Findings, SCAIMaliciousFinding{
			ID:          finding.ID,
			Ecosystem:   finding.Ecosystem,
			PackageName: finding.PackageName,
			Version:     finding.Version,
			PURL:        finding.PURL,
			URL:         finding.URL,
			Exempted:    finding.Exempted,
		})
	}
	return &SCAIAttributeItem{Attribute: SCAIAttributeMaliciousPackageCheck, Evidence: evidence}
}

func hasExemptedMalicious(check *types.MaliciousCheck) bool {
	if check == nil {
		return false
	}
	for _, finding := range check.Findings {
		if finding.Exempted {
			return true
		}
	}
	return false
}
