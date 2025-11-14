package attestation

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/suppline/suppline/internal/attestation/cosign"
	"github.com/suppline/suppline/internal/scanner"
)

// SigstoreAttestor implements the Attestor interface using cosign CLI
// It coordinates attestation operations by delegating to the cosign client
type SigstoreAttestor struct {
	cosignClient *cosign.Client
	logger       *slog.Logger
}

// NewSigstoreAttestor creates a new Sigstore attestor
// Registry authentication should be handled separately during initialization
func NewSigstoreAttestor(config AttestationConfig, logger *slog.Logger) (*SigstoreAttestor, error) {
	if logger == nil {
		logger = slog.Default()
	}

	// Validate configuration
	if config.KeyBased.KeyPath == "" {
		return nil, fmt.Errorf("key path is required for key-based signing")
	}

	// Create cosign client
	cosignClient := cosign.NewClient(
		config.KeyBased.KeyPath,
		config.KeyBased.KeyPassword,
		logger,
	)

	return &SigstoreAttestor{
		cosignClient: cosignClient,
		logger:       logger,
	}, nil
}

// AttestSBOM creates and pushes SBOM attestation using cosign CLI
// This method uses pre-generated SBOM data directly to avoid redundant Trivy invocations
func (a *SigstoreAttestor) AttestSBOM(ctx context.Context, imageRef string, sbom *scanner.SBOM) error {
	startTime := time.Now()
	a.logger.Debug("starting SBOM attestation", "image_ref", imageRef)

	if sbom == nil {
		return fmt.Errorf("SBOM is nil")
	}

	// Validate SBOM data is valid JSON before creating attestation
	if len(sbom.Data) == 0 {
		return fmt.Errorf("SBOM data is empty")
	}

	var jsonCheck interface{}
	if err := json.Unmarshal(sbom.Data, &jsonCheck); err != nil {
		return fmt.Errorf("SBOM data is not valid JSON: %w", err)
	}

	// Write SBOM data to temporary file
	tmpFile, err := cosign.NewTempFile("sbom-*.json", sbom.Data)
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}
	defer tmpFile.Cleanup()

	// Attest using cosign client
	if err := a.cosignClient.Attest(ctx, cosign.AttestOptions{
		ImageRef:      imageRef,
		PredicatePath: tmpFile.Path(),
		PredicateType: "https://cyclonedx.org/bom",
		Replace:       true,
		TlogUpload:    false,
	}); err != nil {
		return err
	}

	a.logger.Debug("SBOM attestation completed",
		"image_ref", imageRef,
		"duration", time.Since(startTime))

	return nil
}

// AttestVulnerabilities creates and pushes vulnerability attestation using cosign CLI
// Uses pre-generated cosign-vuln format from ScanResult to avoid redundant Trivy call
func (a *SigstoreAttestor) AttestVulnerabilities(ctx context.Context, imageRef string, result *scanner.ScanResult) error {
	startTime := time.Now()
	a.logger.Debug("starting vulnerability attestation", "image_ref", imageRef)

	if result == nil {
		return fmt.Errorf("scan result is nil")
	}

	// Require pre-generated cosign-vuln data
	if len(result.CosignVulnData) == 0 {
		return fmt.Errorf("cosign-vuln data is missing from scan result")
	}

	a.logger.Debug("using pre-generated cosign-vuln data",
		"image_ref", imageRef,
		"size_bytes", len(result.CosignVulnData))

	// Write cosign-vuln data to temporary file
	tmpFile, err := cosign.NewTempFile("vuln-*.json", result.CosignVulnData)
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}
	defer tmpFile.Cleanup()

	// Attest using cosign client
	if err := a.cosignClient.Attest(ctx, cosign.AttestOptions{
		ImageRef:      imageRef,
		PredicatePath: tmpFile.Path(),
		PredicateType: "vuln",
		Replace:       true,
		TlogUpload:    false,
	}); err != nil {
		return err
	}

	a.logger.Debug("vulnerability attestation completed",
		"image_ref", imageRef,
		"duration", time.Since(startTime))

	return nil
}

// AttestSCAI creates and pushes SCAI attestation using cosign CLI
func (a *SigstoreAttestor) AttestSCAI(ctx context.Context, imageRef string, scai *SCAIAttestation) error {
	startTime := time.Now()
	a.logger.Debug("starting SCAI attestation", "image_ref", imageRef)

	if scai == nil {
		return fmt.Errorf("SCAI attestation is nil")
	}

	// Write SCAI attestation to temporary file
	tmpFile, err := cosign.NewTempFileJSON("scai-*.json", scai)
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}
	defer tmpFile.Cleanup()

	// Attest using cosign client
	if err := a.cosignClient.Attest(ctx, cosign.AttestOptions{
		ImageRef:      imageRef,
		PredicatePath: tmpFile.Path(),
		PredicateType: "https://in-toto.io/attestation/scai/attribute-report/v0.3",
		Replace:       true,
		TlogUpload:    false,
	}); err != nil {
		return err
	}

	a.logger.Info("SCAI attestation completed",
		"image_ref", imageRef,
		"duration", time.Since(startTime))

	return nil
}

// SignImage signs the image if policy passes using cosign CLI
func (a *SigstoreAttestor) SignImage(ctx context.Context, imageRef string) error {
	return a.cosignClient.Sign(ctx, cosign.SignOptions{
		ImageRef:      imageRef,
		TlogUpload:    false,
		AllowInsecure: true,
	})
}


