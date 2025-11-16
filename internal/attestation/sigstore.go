package attestation

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"time"

	"github.com/daimoniac/suppline/internal/errors"
	"github.com/daimoniac/suppline/internal/scanner"
)

// SigstoreAttestor implements the Attestor interface using cosign CLI
type SigstoreAttestor struct {
	keyPath     string
	keyPassword string
	logger      *slog.Logger
}

// NewSigstoreAttestor creates a new Sigstore attestor
// Note: Registry authentication should be handled separately during initialization
func NewSigstoreAttestor(config AttestationConfig, logger *slog.Logger) (*SigstoreAttestor, error) {
	if logger == nil {
		logger = slog.Default()
	}

	// Validate configuration
	if config.KeyBased.KeyPath == "" {
		return nil, errors.NewPermanentf("key path is required for key-based signing")
	}

	return &SigstoreAttestor{
		keyPath:     config.KeyBased.KeyPath,
		keyPassword: config.KeyBased.KeyPassword,
		logger:      logger,
	}, nil
}

// AttestSBOM creates and pushes SBOM attestation using cosign CLI
func (a *SigstoreAttestor) AttestSBOM(ctx context.Context, imageRef string, sbom *scanner.SBOM) error {
	startTime := time.Now()
	a.logger.Debug("starting SBOM attestation", "image_ref", imageRef)

	if sbom == nil {
		return errors.NewPermanentf("SBOM is nil")
	}

	if len(sbom.Data) == 0 {
		return errors.NewPermanentf("SBOM data is empty")
	}

	var jsonCheck interface{}
	if err := json.Unmarshal(sbom.Data, &jsonCheck); err != nil {
		return errors.NewPermanentf("SBOM data is not valid JSON: %w", err)
	}

	// Write SBOM data to temporary file
	tmpFile, err := os.CreateTemp("", "sbom-*.json")
	if err != nil {
		return errors.NewTransientf("failed to create temp file: %w", err)
	}
	defer os.Remove(tmpFile.Name())
	defer tmpFile.Close()

	if _, err := tmpFile.Write(sbom.Data); err != nil {
		return errors.NewTransientf("failed to write SBOM to temp file: %w", err)
	}
	tmpFile.Close()

	// Use cosign CLI to attest
	cmd := exec.CommandContext(ctx, "cosign", "attest",
		"--key", a.keyPath,
		"--type", "https://cyclonedx.org/bom",
		"--predicate", tmpFile.Name(),
		"--replace=true",
		"--yes",
		"--tlog-upload=false",
		imageRef,
	)
	cmd.Env = append(os.Environ(), fmt.Sprintf("COSIGN_PASSWORD=%s", a.keyPassword))

	output, err := cmd.CombinedOutput()
	if err != nil {
		a.logger.Error("cosign SBOM attestation failed",
			"image_ref", imageRef,
			"error", err)
		// Cosign failures are typically transient (network, registry issues)
		return errors.NewTransientf("failed to attest SBOM: %w (output: %s)", err, string(output))
	}

	a.logger.Debug("SBOM attestation completed",
		"image_ref", imageRef,
		"duration", time.Since(startTime))

	return nil
}

// AttestVulnerabilities creates and pushes vulnerability attestation using cosign CLI
func (a *SigstoreAttestor) AttestVulnerabilities(ctx context.Context, imageRef string, result *scanner.ScanResult) error {
	startTime := time.Now()
	a.logger.Debug("starting vulnerability attestation", "image_ref", imageRef)

	if result == nil {
		return errors.NewPermanentf("scan result is nil")
	}

	if len(result.CosignVulnData) == 0 {
		return errors.NewPermanentf("cosign-vuln data is missing from scan result")
	}

	// Write cosign-vuln data to temp file
	tmpFile, err := os.CreateTemp("", "vuln-*.json")
	if err != nil {
		return errors.NewTransientf("failed to create temp file: %w", err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.Write(result.CosignVulnData); err != nil {
		tmpFile.Close()
		return errors.NewTransientf("failed to write cosign-vuln data: %w", err)
	}
	tmpFile.Close()

	// Use cosign CLI to attest
	cmd := exec.CommandContext(ctx, "cosign", "attest",
		"--key", a.keyPath,
		"--type", "vuln",
		"--predicate", tmpFile.Name(),
		"--replace=true",
		"--yes",
		"--tlog-upload=false",
		imageRef,
	)
	cmd.Env = append(os.Environ(), fmt.Sprintf("COSIGN_PASSWORD=%s", a.keyPassword))

	output, err := cmd.CombinedOutput()
	if err != nil {
		a.logger.Error("cosign vulnerability attestation failed",
			"image_ref", imageRef,
			"error", err)
		// Cosign failures are typically transient (network, registry issues)
		return errors.NewTransientf("failed to attest vulnerabilities: %w (output: %s)", err, string(output))
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
		return errors.NewPermanentf("SCAI attestation is nil")
	}

	// Serialize SCAI to JSON
	scaiJSON, err := json.MarshalIndent(scai, "", "  ")
	if err != nil {
		return errors.NewPermanentf("failed to serialize SCAI: %w", err)
	}

	// Write to temp file
	tmpFile, err := os.CreateTemp("", "scai-*.json")
	if err != nil {
		return errors.NewTransientf("failed to create temp file: %w", err)
	}
	defer os.Remove(tmpFile.Name())
	defer tmpFile.Close()

	if _, err := tmpFile.Write(scaiJSON); err != nil {
		return errors.NewTransientf("failed to write SCAI to temp file: %w", err)
	}
	tmpFile.Close()

	// Use cosign CLI to attest
	cmd := exec.CommandContext(ctx, "cosign", "attest",
		"--key", a.keyPath,
		"--type", "https://in-toto.io/attestation/scai/attribute-report/v0.3",
		"--predicate", tmpFile.Name(),
		"--replace=true",
		"--yes",
		"--tlog-upload=false",
		imageRef,
	)
	cmd.Env = append(os.Environ(), fmt.Sprintf("COSIGN_PASSWORD=%s", a.keyPassword))

	output, err := cmd.CombinedOutput()
	if err != nil {
		a.logger.Error("cosign SCAI attestation failed",
			"image_ref", imageRef,
			"error", err)
		// Cosign failures are typically transient (network, registry issues)
		return errors.NewTransientf("failed to attest SCAI: %w (output: %s)", err, string(output))
	}

	a.logger.Info("SCAI attestation completed",
		"image_ref", imageRef,
		"duration", time.Since(startTime))

	return nil
}

// SignImage signs the image using cosign CLI
func (a *SigstoreAttestor) SignImage(ctx context.Context, imageRef string) error {
	cmd := exec.CommandContext(ctx, "cosign", "sign",
		"--key", a.keyPath,
		"--yes",
		"--tlog-upload=false",
		"--allow-insecure-registry",
		imageRef,
	)
	cmd.Env = append(os.Environ(), fmt.Sprintf("COSIGN_PASSWORD=%s", a.keyPassword))

	output, err := cmd.CombinedOutput()
	if err != nil {
		// Cosign signing failures are typically transient (network, registry issues)
		return errors.NewTransientf("failed to sign image: %w (output: %s)", err, string(output))
	}

	return nil
}
