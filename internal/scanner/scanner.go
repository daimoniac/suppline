package scanner

import (
	"context"
	"time"
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
	Vulnerabilities []Vulnerability
	ScannedAt       time.Time
}

// Vulnerability represents a single security vulnerability
type Vulnerability struct {
	ID           string // CVE ID
	Severity     string // CRITICAL, HIGH, MEDIUM, LOW
	PackageName  string
	Version      string // Installed version
	FixedVersion string // Version with fix (empty if no fix available)
	Title        string
	Description  string
	PrimaryURL   string // Reference URL
}
