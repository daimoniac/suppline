package attestation

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"os/exec"
	"strings"
	"time"

	apperrors "github.com/daimoniac/suppline/internal/errors"
	"github.com/daimoniac/suppline/internal/scanner"
	"github.com/daimoniac/suppline/internal/types"
)

const defaultCosignAttestTimeout = 2 * time.Minute

// SigstoreAttestor implements the Attestor interface using cosign CLI
type SigstoreAttestor struct {
	keyPath       string // Path to temporary key file
	logger        *slog.Logger
	cleanup       func() // Cleanup function to remove temp key file
	attestTimeout time.Duration
}

func ensureCosignSupportsNewBundleFormat() error {
	helpCmd := exec.Command("cosign", "attest", "--help")
	output, err := helpCmd.CombinedOutput()
	if err != nil {
		return apperrors.NewPermanentf("failed to check cosign attest capabilities: %w (output: %s)", err, string(output))
	}

	if !strings.Contains(string(output), "--new-bundle-format") {
		return apperrors.NewPermanentf("cosign attest does not support --new-bundle-format; install cosign v3.0.6 or newer")
	}

	return nil
}

func resolveCosignAttestTimeout(logger *slog.Logger) time.Duration {
	timeoutStr := strings.TrimSpace(os.Getenv("ATTESTATION_COMMAND_TIMEOUT"))
	if timeoutStr == "" {
		return defaultCosignAttestTimeout
	}

	timeout, err := time.ParseDuration(timeoutStr)
	if err != nil || timeout <= 0 {
		logger.Warn("invalid ATTESTATION_COMMAND_TIMEOUT, using default",
			"value", timeoutStr,
			"default", defaultCosignAttestTimeout,
			"error", err)
		return defaultCosignAttestTimeout
	}

	return timeout
}

func (a *SigstoreAttestor) buildCosignAttestArgs(predicateType, predicatePath, imageRef string) []string {
	return []string{
		"attest",
		"--key", a.keyPath,
		"--type", predicateType,
		"--predicate", predicatePath,
		"--replace=true",
		"--new-bundle-format",
		"--yes",
		imageRef,
	}
}

func (a *SigstoreAttestor) runCosignAttest(ctx context.Context, operation string, args []string) ([]byte, error) {
	attestCtx, cancel := context.WithTimeout(ctx, a.attestTimeout)
	defer cancel()

	cmd := exec.CommandContext(attestCtx, "cosign", args...)
	cmd.Env = os.Environ()
	if password := os.Getenv("ATTESTATION_KEY_PASSWORD"); password != "" {
		cmd.Env = append(cmd.Env, "COSIGN_PASSWORD="+password)
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		if errors.Is(attestCtx.Err(), context.DeadlineExceeded) {
			return nil, apperrors.NewTransientf("%s timed out after %s: %w (output: %s)", operation, a.attestTimeout, err, string(output))
		}
		return nil, apperrors.NewTransientf("failed to %s: %w (output: %s)", operation, err, string(output))
	}

	return output, nil
}

// NewSigstoreAttestor creates a new Sigstore attestor
// Note: Registry authentication should be handled separately during initialization
func NewSigstoreAttestor(config AttestationConfig, logger *slog.Logger) (*SigstoreAttestor, error) {
	if logger == nil {
		logger = slog.Default()
	}

	if err := ensureCosignSupportsNewBundleFormat(); err != nil {
		return nil, err
	}

	// Validate configuration
	if config.KeyBased.Key == "" {
		return nil, apperrors.NewPermanentf("attestation key is required for key-based signing")
	}

	// Decode base64 key
	keyData, err := base64.StdEncoding.DecodeString(config.KeyBased.Key)
	if err != nil {
		return nil, apperrors.NewPermanentf("failed to decode base64 attestation key: %w", err)
	}

	// Write key to temporary file
	tmpFile, err := os.CreateTemp("", "cosign-key-*.key")
	if err != nil {
		return nil, apperrors.NewPermanentf("failed to create temp key file: %w", err)
	}

	if _, err := tmpFile.Write(keyData); err != nil {
		tmpFile.Close()
		os.Remove(tmpFile.Name())
		return nil, apperrors.NewPermanentf("failed to write key to temp file: %w", err)
	}
	tmpFile.Close()

	// Set restrictive permissions on key file
	if err := os.Chmod(tmpFile.Name(), 0600); err != nil {
		os.Remove(tmpFile.Name())
		return nil, apperrors.NewPermanentf("failed to set key file permissions: %w", err)
	}

	logger.Debug("created temporary key file", "path", tmpFile.Name())

	return &SigstoreAttestor{
		keyPath:       tmpFile.Name(),
		logger:        logger,
		attestTimeout: resolveCosignAttestTimeout(logger),
		cleanup: func() {
			os.Remove(tmpFile.Name())
		},
	}, nil
}

// AttestSBOM creates and pushes SBOM attestation using cosign CLI
func (a *SigstoreAttestor) AttestSBOM(ctx context.Context, imageRef string, sbom *scanner.SBOM) error {
	startTime := time.Now()
	a.logger.Debug("starting SBOM attestation", "image_ref", imageRef)

	if sbom == nil {
		return apperrors.NewPermanentf("SBOM is nil")
	}

	if len(sbom.Data) == 0 {
		return apperrors.NewPermanentf("SBOM data is empty")
	}

	var jsonCheck interface{}
	if err := json.Unmarshal(sbom.Data, &jsonCheck); err != nil {
		return apperrors.NewPermanentf("SBOM data is not valid JSON: %w", err)
	}

	// Write SBOM data to temporary file
	tmpFile, err := os.CreateTemp("", "sbom-*.json")
	if err != nil {
		return apperrors.NewTransientf("failed to create temp file: %w", err)
	}
	defer os.Remove(tmpFile.Name())
	defer tmpFile.Close()

	if _, err := tmpFile.Write(sbom.Data); err != nil {
		return apperrors.NewTransientf("failed to write SBOM to temp file: %w", err)
	}
	tmpFile.Close()

	// Use cosign CLI to attest
	_, err = a.runCosignAttest(ctx, "attest SBOM", a.buildCosignAttestArgs("https://cyclonedx.org/bom", tmpFile.Name(), imageRef))
	if err != nil {
		a.logger.Error("cosign SBOM attestation failed",
			"image_ref", imageRef,
			"error", err)
		return err
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
		return apperrors.NewPermanentf("scan result is nil")
	}

	if len(result.CosignVulnData) == 0 {
		return apperrors.NewPermanentf("cosign-vuln data is missing from scan result")
	}

	// Write cosign-vuln data to temp file
	tmpFile, err := os.CreateTemp("", "vuln-*.json")
	if err != nil {
		return apperrors.NewTransientf("failed to create temp file: %w", err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.Write(result.CosignVulnData); err != nil {
		tmpFile.Close()
		return apperrors.NewTransientf("failed to write cosign-vuln data: %w", err)
	}
	tmpFile.Close()

	// Use cosign CLI to attest
	_, err = a.runCosignAttest(ctx, "attest vulnerabilities", a.buildCosignAttestArgs("vuln", tmpFile.Name(), imageRef))
	if err != nil {
		a.logger.Error("cosign vulnerability attestation failed",
			"image_ref", imageRef,
			"error", err)
		return err
	}

	a.logger.Debug("vulnerability attestation completed",
		"image_ref", imageRef,
		"duration", time.Since(startTime))

	return nil
}

// AttestVEX creates and pushes VEX attestation using cosign CLI
func (a *SigstoreAttestor) AttestVEX(ctx context.Context, imageRef string, statements []types.AppliedVEXStatement) error {
	startTime := time.Now()
	a.logger.Debug("starting VEX attestation", "image_ref", imageRef, "statement_count", len(statements))

	if len(statements) == 0 {
		a.logger.Debug("no VEX statements to attest, skipping", "image_ref", imageRef)
		return nil
	}

	// Build VEX predicate
	predicate := VEXPredicate{
		CreatedAt: time.Now().UTC(),
	}
	for _, s := range statements {
		predicate.Statements = append(predicate.Statements, VEXStatementInfo{
			CVEID:         s.CVEID,
			State:         string(s.State),
			Justification: string(s.Justification),
			Detail:        s.Detail,
			ExpiresAt:     s.ExpiresAt,
		})
		predicate.Summary.TotalStatements++
		switch s.State {
		case types.VEXStateNotAffected:
			predicate.Summary.NotAffected++
		case types.VEXStateAffected:
			predicate.Summary.Affected++
		case types.VEXStateInTriage:
			predicate.Summary.InTriage++
		case types.VEXStateFalsePositive:
			predicate.Summary.FalsePositive++
		case types.VEXStateResolved, types.VEXStateResolvedWithPedigree:
			predicate.Summary.Resolved++
		}
	}

	// Serialize predicate to JSON
	vexJSON, err := json.MarshalIndent(predicate, "", "  ")
	if err != nil {
		return apperrors.NewPermanentf("failed to serialize VEX predicate: %w", err)
	}

	// Write to temp file
	tmpFile, err := os.CreateTemp("", "vex-*.json")
	if err != nil {
		return apperrors.NewTransientf("failed to create temp file: %w", err)
	}
	defer os.Remove(tmpFile.Name())
	defer tmpFile.Close()

	if _, err := tmpFile.Write(vexJSON); err != nil {
		return apperrors.NewTransientf("failed to write VEX to temp file: %w", err)
	}
	tmpFile.Close()

	// Use cosign CLI to attest with CycloneDX VEX type
	_, err = a.runCosignAttest(ctx, "attest VEX", a.buildCosignAttestArgs("https://cyclonedx.org/vex", tmpFile.Name(), imageRef))
	if err != nil {
		a.logger.Error("cosign VEX attestation failed",
			"image_ref", imageRef,
			"error", err)
		return err
	}

	a.logger.Info("VEX attestation completed",
		"image_ref", imageRef,
		"statement_count", len(statements),
		"duration", time.Since(startTime))

	return nil
}

// AttestSCAI creates and pushes SCAI attestation using cosign CLI
func (a *SigstoreAttestor) AttestSCAI(ctx context.Context, imageRef string, scai *SCAIAttestation) error {
	startTime := time.Now()
	a.logger.Debug("starting SCAI attestation", "image_ref", imageRef)

	if scai == nil {
		return apperrors.NewPermanentf("SCAI attestation is nil")
	}

	// Serialize SCAI to JSON
	scaiJSON, err := json.MarshalIndent(scai, "", "  ")
	if err != nil {
		return apperrors.NewPermanentf("failed to serialize SCAI: %w", err)
	}

	// Write to temp file
	tmpFile, err := os.CreateTemp("", "scai-*.json")
	if err != nil {
		return apperrors.NewTransientf("failed to create temp file: %w", err)
	}
	defer os.Remove(tmpFile.Name())
	defer tmpFile.Close()

	if _, err := tmpFile.Write(scaiJSON); err != nil {
		return apperrors.NewTransientf("failed to write SCAI to temp file: %w", err)
	}
	tmpFile.Close()

	// Use cosign CLI to attest
	_, err = a.runCosignAttest(ctx, "attest SCAI", a.buildCosignAttestArgs("https://in-toto.io/attestation/scai/attribute-report/v0.3", tmpFile.Name(), imageRef))
	if err != nil {
		a.logger.Error("cosign SCAI attestation failed",
			"image_ref", imageRef,
			"error", err)
		return err
	}

	a.logger.Info("SCAI attestation completed",
		"image_ref", imageRef,
		"duration", time.Since(startTime))

	return nil
}

// Close cleans up temporary resources
func (a *SigstoreAttestor) Close() error {
	if a.cleanup != nil {
		a.cleanup()
	}
	return nil
}
