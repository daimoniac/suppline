package attestation

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/suppline/suppline/internal/regsync"
	"github.com/suppline/suppline/internal/scanner"
)

// SigstoreAttestor implements the Attestor interface using cosign CLI
type SigstoreAttestor struct {
	config     AttestationConfig
	authConfig map[string]authn.Authenticator
	logger     *slog.Logger
}

// NewSigstoreAttestor creates a new Sigstore attestor
func NewSigstoreAttestor(config AttestationConfig, authConfig map[string]authn.Authenticator, logger *slog.Logger, regsyncPath string) (*SigstoreAttestor, error) {
	if logger == nil {
		logger = slog.Default()
	}
	
	attestor := &SigstoreAttestor{
		config:     config,
		authConfig: authConfig,
		logger:     logger,
	}

	// Validate configuration
	if config.KeyBased.KeyPath == "" {
		return nil, fmt.Errorf("key path is required for key-based signing")
	}

	// Authenticate cosign with registry credentials from suppline.yml
	if err := attestor.authenticateRegistries(regsyncPath); err != nil {
		return nil, fmt.Errorf("failed to authenticate registries for cosign: %w", err)
	}

	return attestor, nil
}

// authenticateRegistries logs into registries using credentials from suppline.yml
func (a *SigstoreAttestor) authenticateRegistries(regsyncPath string) error {
	// Parse regsync config
	regsyncCfg, err := regsync.Parse(regsyncPath)
	if err != nil {
		return fmt.Errorf("failed to parse regsync config: %w", err)
	}

	// Authenticate with each registry
	for _, cred := range regsyncCfg.Creds {
		if cred.Registry == "" || cred.User == "" || cred.Pass == "" {
			a.logger.Warn("skipping incomplete registry credential", "registry", cred.Registry)
			continue
		}

		a.logger.Info("authenticating cosign with registry", "registry", cred.Registry)

		// Execute cosign login
		cmd := exec.Command("cosign", "login", cred.Registry,
			"--username", cred.User,
			"--password", cred.Pass)

		var stderr bytes.Buffer
		cmd.Stderr = &stderr

		if err := cmd.Run(); err != nil {
			a.logger.Error("failed to authenticate cosign with registry",
				"registry", cred.Registry,
				"error", err,
				"stderr", stderr.String())
			return fmt.Errorf("failed to login cosign to registry %s: %w", cred.Registry, err)
		}

		a.logger.Info("successfully authenticated cosign with registry", "registry", cred.Registry)
	}

	return nil
}

// AttestSBOM creates and pushes SBOM attestation using cosign CLI
// This method uses pre-generated SBOM data directly to avoid redundant Trivy invocations
func (a *SigstoreAttestor) AttestSBOM(ctx context.Context, imageRef string, sbom *scanner.SBOM) error {
	startTime := time.Now()
	a.logger.Debug("starting SBOM attestation", "image_ref", imageRef, "start_time", startTime)
	
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

	// Write SBOM data directly to a temporary file as the predicate content
	tmpFile, err := os.CreateTemp("", "sbom-*.json")
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}
	defer os.Remove(tmpFile.Name())
	defer tmpFile.Close()

	if _, err := tmpFile.Write([]byte(sbom.Data)); err != nil {
		return fmt.Errorf("failed to write SBOM to temp file: %w", err)
	}
	tmpFile.Close()

	// Use cosign CLI to attest with pre-generated SBOM predicate
	cosignStartTime := time.Now()
	a.logger.Debug("invoking cosign for SBOM attestation", "image_ref", imageRef, "cosign_start_time", cosignStartTime)
	
	cmd := exec.CommandContext(ctx, "cosign", "attest",
		"--key", a.config.KeyBased.KeyPath,
		"--type", "https://cyclonedx.org/bom",
		"--predicate", tmpFile.Name(),
		"--replace=true",
		"--yes",
		"--tlog-upload=false",
		imageRef,
	)

	// Set password via environment variable
	cmd.Env = append(os.Environ(), fmt.Sprintf("COSIGN_PASSWORD=%s", a.config.KeyBased.KeyPassword))

	output, err := cmd.CombinedOutput()
	cosignDuration := time.Since(cosignStartTime)
	
	if err != nil {
		a.logger.Error("cosign SBOM attestation failed", 
			"image_ref", imageRef, 
			"cosign_duration", cosignDuration,
			"error", err)
		return fmt.Errorf("failed to attest SBOM with cosign: %w (output: %s)", err, string(output))
	}

	totalDuration := time.Since(startTime)
	a.logger.Debug("SBOM attestation completed", 
		"image_ref", imageRef, 
		"total_duration", totalDuration,
		"cosign_duration", cosignDuration)

	return nil
}

// AttestVulnerabilities creates and pushes vulnerability attestation using cosign CLI
// Uses Trivy's native cosign-vuln format for proper attestation structure
func (a *SigstoreAttestor) AttestVulnerabilities(ctx context.Context, imageRef string, result *scanner.ScanResult) error {
	startTime := time.Now()
	a.logger.Debug("starting vulnerability attestation", "image_ref", imageRef, "start_time", startTime)
	
	if result == nil {
		return fmt.Errorf("scan result is nil")
	}

	// Generate vulnerability report in cosign-vuln format using Trivy
	// This ensures proper format with all required fields populated
	trivyStartTime := time.Now()
	a.logger.Debug("invoking Trivy for cosign-vuln format", "image_ref", imageRef, "trivy_start_time", trivyStartTime)
	
	tmpFile, err := os.CreateTemp("", "vuln-*.json")
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}
	defer os.Remove(tmpFile.Name())
	tmpFile.Close()

	// Run trivy with cosign-vuln format
	trivyCmd := exec.CommandContext(ctx, "trivy", "image",
		"--format", "cosign-vuln",
		"--output", tmpFile.Name(),
		"--quiet",
		imageRef,
	)

	trivyOutput, err := trivyCmd.CombinedOutput()
	trivyDuration := time.Since(trivyStartTime)
	
	if err != nil {
		a.logger.Error("Trivy cosign-vuln generation failed", 
			"image_ref", imageRef, 
			"trivy_duration", trivyDuration,
			"error", err)
		return fmt.Errorf("failed to generate cosign-vuln format: %w (output: %s)", err, string(trivyOutput))
	}

	a.logger.Debug("Trivy cosign-vuln generation completed", 
		"image_ref", imageRef, 
		"trivy_duration", trivyDuration)

	// Use cosign CLI to attest with Trivy-generated predicate
	cosignStartTime := time.Now()
	a.logger.Debug("invoking cosign for vulnerability attestation", "image_ref", imageRef, "cosign_start_time", cosignStartTime)
	
	cmd := exec.CommandContext(ctx, "cosign", "attest",
		"--key", a.config.KeyBased.KeyPath,
		"--type", "vuln",
		"--predicate", tmpFile.Name(),
		"--replace=true",
		"--yes",
		"--tlog-upload=false",
		imageRef,
	)

	// Set password via environment variable
	cmd.Env = append(os.Environ(), fmt.Sprintf("COSIGN_PASSWORD=%s", a.config.KeyBased.KeyPassword))

	output, err := cmd.CombinedOutput()
	cosignDuration := time.Since(cosignStartTime)
	
	if err != nil {
		a.logger.Error("cosign vulnerability attestation failed", 
			"image_ref", imageRef, 
			"cosign_duration", cosignDuration,
			"error", err)
		return fmt.Errorf("failed to attest vulnerabilities with cosign: %w (output: %s)", err, string(output))
	}

	totalDuration := time.Since(startTime)
	a.logger.Debug("vulnerability attestation completed", 
		"image_ref", imageRef, 
		"total_duration", totalDuration,
		"trivy_duration", trivyDuration,
		"cosign_duration", cosignDuration)

	return nil
}

// AttestSCAI creates and pushes SCAI attestation using cosign CLI
func (a *SigstoreAttestor) AttestSCAI(ctx context.Context, imageRef string, scai *SCAIAttestation) error {
	startTime := time.Now()
	a.logger.Debug("starting SCAI attestation", "image_ref", imageRef, "start_time", startTime)
	
	if scai == nil {
		return fmt.Errorf("SCAI attestation is nil")
	}

	// Serialize SCAI attestation to JSON
	scaiJSON, err := json.MarshalIndent(scai, "", "  ")
	if err != nil {
		a.logger.Error("failed to serialize SCAI attestation", 
			"image_ref", imageRef, 
			"error", err)
		return fmt.Errorf("failed to serialize SCAI attestation: %w", err)
	}

	// Write JSON to temporary file
	tmpFile, err := os.CreateTemp("", "scai-*.json")
	if err != nil {
		a.logger.Error("failed to create temp file for SCAI attestation", 
			"image_ref", imageRef, 
			"error", err)
		return fmt.Errorf("failed to create temp file: %w", err)
	}
	defer os.Remove(tmpFile.Name())
	defer tmpFile.Close()

	if _, err := tmpFile.Write(scaiJSON); err != nil {
		a.logger.Error("failed to write SCAI to temp file", 
			"image_ref", imageRef, 
			"error", err)
		return fmt.Errorf("failed to write SCAI to temp file: %w", err)
	}
	tmpFile.Close()

	// Use cosign CLI to attest with SCAI predicate
	cosignStartTime := time.Now()
	a.logger.Debug("invoking cosign for SCAI attestation", "image_ref", imageRef, "cosign_start_time", cosignStartTime)
	
	cmd := exec.CommandContext(ctx, "cosign", "attest",
		"--key", a.config.KeyBased.KeyPath,
		"--type", "https://in-toto.io/attestation/scai/attribute-report/v0.3",
		"--predicate", tmpFile.Name(),
		"--replace=true",
		"--yes",
		"--tlog-upload=false",
		imageRef,
	)

	// Set password via environment variable
	cmd.Env = append(os.Environ(), fmt.Sprintf("COSIGN_PASSWORD=%s", a.config.KeyBased.KeyPassword))

	output, err := cmd.CombinedOutput()
	cosignDuration := time.Since(cosignStartTime)
	
	if err != nil {
		a.logger.Error("cosign SCAI attestation failed", 
			"image_ref", imageRef, 
			"cosign_duration", cosignDuration,
			"error", err,
			"output", string(output))
		return fmt.Errorf("failed to attest SCAI with cosign: %w (output: %s)", err, string(output))
	}

	totalDuration := time.Since(startTime)
	a.logger.Info("SCAI attestation completed successfully", 
		"image_ref", imageRef, 
		"timestamp", time.Now().Format(time.RFC3339),
		"total_duration", totalDuration,
		"cosign_duration", cosignDuration)

	return nil
}

// SignImage signs the image if policy passes using cosign CLI
func (a *SigstoreAttestor) SignImage(ctx context.Context, imageRef string) error {
	cmd := exec.CommandContext(ctx, "cosign", "sign",
		"--key", a.config.KeyBased.KeyPath,
		"--yes",
		"--tlog-upload=false",
		"--allow-insecure-registry",
		imageRef,
	)

	// Set password via environment variable
	cmd.Env = append(os.Environ(), fmt.Sprintf("COSIGN_PASSWORD=%s", a.config.KeyBased.KeyPassword))

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to sign image with cosign: %w (output: %s)", err, string(output))
	}

	return nil
}


