package attestation

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/suppline/suppline/internal/regsync"
	"github.com/suppline/suppline/internal/scanner"
)

// SCAIGenerator creates SCAI attestation predicates
type SCAIGenerator struct {
	config *regsync.Config
	logger *slog.Logger
}

// NewSCAIGenerator creates a new SCAI generator
func NewSCAIGenerator(config *regsync.Config) *SCAIGenerator {
	return &SCAIGenerator{
		config: config,
		logger: slog.Default(),
	}
}

// convertToPURL converts an OCI image reference to PURL format
// Input:  hostingmaloonde/nginx@sha256:abc123...
// Output: pkg:docker/hostingmaloonde/nginx@sha256:abc123...
// Input:  registry.example.com/myorg/app@sha256:def456...
// Output: pkg:docker/registry.example.com/myorg/app@sha256:def456...
func convertToPURL(imageRef string) (string, error) {
	// Image reference should contain @ for digest
	if !strings.Contains(imageRef, "@") {
		return "", fmt.Errorf("image reference must contain digest: %s", imageRef)
	}

	// Simply prepend pkg:docker/ to the image reference
	return "pkg:docker/" + imageRef, nil
}

// calculateValidityWindow calculates the validUntil timestamp by adding the rescan interval
// plus the validity extension to the scan timestamp.
// The validity extension provides a grace period beyond the next scheduled scan.
// Falls back to 7d rescan interval + 1d extension if values cannot be determined.
func (g *SCAIGenerator) calculateValidityWindow(scanTime time.Time, target string) time.Time {
	interval, err := g.config.GetRescanInterval(target)
	if err != nil {
		g.logger.Warn("failed to get rescan interval, using default 7d",
			"target", target,
			"error", err)
		interval = 7 * 24 * time.Hour
	}

	extension, err := g.config.GetSCAIValidityExtension(target)
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

// matchToleratedVulnerabilities filters scan results against configured tolerations
// and builds a list of tolerated vulnerabilities with full details including
// vulnerability description and fixed version information
func (g *SCAIGenerator) matchToleratedVulnerabilities(scanResult *scanner.ScanResult, target string) []SCAIAttributeItem {
	var attributes []SCAIAttributeItem

	for _, vuln := range scanResult.Vulnerabilities {
		tolerated, toleration := g.config.IsToleratedCVE(target, vuln.ID)
		if tolerated && toleration != nil {
			evidence := SCAIToleratedVulnEvidence{
				CVEID:        vuln.ID,
				Severity:     vuln.Severity,
				PackageName:  vuln.PackageName,
				Version:      vuln.Version,
				FixedVersion: vuln.FixedVersion,
				Description:  vuln.Description,
				Statement:    toleration.Statement,
			}

			// Include expiry date if present
			if toleration.ExpiresAt != nil {
				evidence.ToleratedUntil = toleration.ExpiresAt
			}

			attributes = append(attributes, SCAIAttributeItem{
				Attribute: "tolerated-vulnerability",
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
//   - target: target repository from regsync config (for toleration lookup)
// Returns: SCAI attestation structure ready for JSON serialization
func (g *SCAIGenerator) GenerateSCAI(
	ctx context.Context,
	imageRef string,
	scanResult *scanner.ScanResult,
	target string,
) (*SCAIAttestation, error) {
	if scanResult == nil {
		return nil, fmt.Errorf("scan result is nil")
	}

	// Convert image reference to PURL format
	purl, err := convertToPURL(imageRef)
	if err != nil {
		return nil, fmt.Errorf("failed to convert image reference to PURL: %w", err)
	}

	// Calculate validity window
	validUntil := g.calculateValidityWindow(scanResult.ScannedAt, target)

	// Match tolerated vulnerabilities
	attributes := g.matchToleratedVulnerabilities(scanResult, target)

	// Determine scan status based on whether tolerations exist
	scanStatus := "passed"
	if len(attributes) > 0 {
		scanStatus = "passed-with-exceptions"
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
		"tolerated_count", len(attributes),
		"valid_until", validUntil.Format(time.RFC3339))

	return scai, nil
}
