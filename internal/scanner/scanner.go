package scanner

import (
	"context"
	"time"

	"github.com/suppline/suppline/internal/types"
)

// Scanner defines the interface for vulnerability scanning and SBOM generation
type Scanner interface {
	// GenerateSBOM creates CycloneDX SBOM via Trivy server
	GenerateSBOM(ctx context.Context, imageRef string) (*SBOM, error)

	// ScanVulnerabilities performs vulnerability analysis via Trivy server
	ScanVulnerabilities(ctx context.Context, imageRef string) (*ScanResult, error)

	// HealthCheck reports Trivy connectivity status for health endpoint integration
	HealthCheck(ctx context.Context) error
}

// SBOM represents a Software Bill of Materials
type SBOM struct {
	Format  string    // "cyclonedx"
	Version string    // CycloneDX version (e.g., "1.5")
	Data    []byte    // CycloneDX JSON
	Created time.Time // When the SBOM was generated
}

// ScanResult contains vulnerability scan results
type ScanResult struct {
	ImageRef        string
	Vulnerabilities []types.Vulnerability // Using canonical type from internal/types
	ScannedAt       time.Time
	CosignVulnData  []byte // Pre-generated cosign-vuln format for attestation (avoids redundant Trivy call)
	SBOM            *SBOM  // Optional: SBOM generated during the same scan (avoids separate SBOM call)
}
