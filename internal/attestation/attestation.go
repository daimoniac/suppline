package attestation

import (
	"context"
	"time"

	"github.com/daimoniac/suppline/internal/scanner"
)

// Attestor defines the interface for creating attestations and signing images
type Attestor interface {
	// AttestSBOM creates and pushes SBOM attestation using sigstore-go
	AttestSBOM(ctx context.Context, imageRef string, sbom *scanner.SBOM) error

	// AttestVulnerabilities creates and pushes vulnerability attestation using sigstore-go
	AttestVulnerabilities(ctx context.Context, imageRef string, result *scanner.ScanResult) error

	// AttestSCAI creates and pushes SCAI attestation using sigstore-go
	AttestSCAI(ctx context.Context, imageRef string, scai *SCAIAttestation) error
}

// AttestationResult represents the result of an attestation operation
type AttestationResult struct {
	ImageRef        string
	AttestationType string // "sbom" or "vulnerability"
	Success         bool
	Error           error
	Timestamp       time.Time
	DigestAttested  string // The digest that was attested
}

// SBOMAttestation represents SBOM attestation data
type SBOMAttestation struct {
	ImageRef    string
	SBOM        *scanner.SBOM
	Timestamp   time.Time
	Predicate   SBOMPredicate
}

// SBOMPredicate contains the SBOM attestation predicate
type SBOMPredicate struct {
	Format      string    `json:"format"`      // "cyclonedx"
	Version     string    `json:"version"`     // CycloneDX version
	Content     []byte    `json:"content"`     // SBOM data
	GeneratedAt time.Time `json:"generatedAt"`
}

// VulnerabilityAttestation represents vulnerability scan attestation data
type VulnerabilityAttestation struct {
	ImageRef    string
	ScanResult  *scanner.ScanResult
	Timestamp   time.Time
	Predicate   VulnerabilityPredicate
}

// VulnerabilityPredicate contains the vulnerability attestation predicate
type VulnerabilityPredicate struct {
	Scanner         ScannerInfo        `json:"scanner"`
	Vulnerabilities []VulnerabilityInfo `json:"vulnerabilities"`
	Summary         VulnerabilitySummary `json:"summary"`
	ScannedAt       time.Time          `json:"scannedAt"`
}

// ScannerInfo contains information about the scanner used
type ScannerInfo struct {
	Name    string `json:"name"`    // "trivy"
	Version string `json:"version"` // Scanner version
}

// VulnerabilityInfo represents a vulnerability in the attestation
type VulnerabilityInfo struct {
	ID           string `json:"id"`           // CVE ID
	Severity     string `json:"severity"`     // CRITICAL, HIGH, MEDIUM, LOW
	PackageName  string `json:"packageName"`
	Version      string `json:"version"`      // Installed version
	FixedVersion string `json:"fixedVersion"` // Version with fix
	Title        string `json:"title"`
	Description  string `json:"description"`
	PrimaryURL   string `json:"primaryUrl"`
}

// VulnerabilitySummary provides a summary of vulnerabilities by severity
type VulnerabilitySummary struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Total    int `json:"total"`
}

// KeyBasedConfig contains configuration for key-based signing
type KeyBasedConfig struct {
	Key      string // Base64-encoded private key content
	CertPath string // Path to the certificate file (optional)
	// Note: Key password is read from ATTESTATION_KEY_PASSWORD environment variable
}

// AttestationConfig contains configuration for the attestation service
type AttestationConfig struct {
	// Key-based signing configuration
	KeyBased KeyBasedConfig

	// Future: Keyless signing configuration
	// UseKeyless  bool
	// RekorURL    string
	// FulcioURL   string
	// OIDCIssuer  string
	// OIDCClientID string
}

// SCAIAttestation represents the complete SCAI attestation structure
// following the in-toto SCAI v0.3 specification
type SCAIAttestation struct {
	Attribute  string              `json:"attribute"`
	Target     SCAITarget          `json:"target"`
	Evidence   SCAIEvidence        `json:"evidence"`
	Attributes []SCAIAttributeItem `json:"attributes"`
}

// SCAITarget identifies the container image being assessed
type SCAITarget struct {
	URI string `json:"uri"` // PURL format: pkg:docker/repo@sha256:digest
}

// SCAIEvidence contains the primary security assessment metadata
type SCAIEvidence struct {
	LastScanned time.Time `json:"lastScanned"` // RFC 3339 format
	ValidUntil  time.Time `json:"validUntil"`  // RFC 3339 format
	ScanStatus  string    `json:"scanStatus"`  // "passed-with-exceptions" or "passed"
}

// SCAIAttributeItem represents a single tolerated vulnerability
type SCAIAttributeItem struct {
	Attribute string                    `json:"attribute"` // "tolerated-vulnerability"
	Evidence  SCAIToleratedVulnEvidence `json:"evidence"`
}

// SCAIToleratedVulnEvidence contains details about a tolerated vulnerability
type SCAIToleratedVulnEvidence struct {
	CVEID          string `json:"cveId"`
	Severity       string `json:"severity"`
	PackageName    string `json:"packageName"`
	Version        string `json:"version"`
	FixedVersion   string `json:"fixedVersion,omitempty"`   // Version with fix (empty if no fix available)
	Description    string `json:"description,omitempty"`    // Short description of the vulnerability
	Statement      string `json:"statement"`
	ToleratedUntil *int64 `json:"toleratedUntil,omitempty"` // Unix timestamp in seconds, nil if no expiry
}
