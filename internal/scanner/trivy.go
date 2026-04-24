package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"time"

	"github.com/daimoniac/suppline/internal/config"
	"github.com/daimoniac/suppline/internal/errors"
	"github.com/daimoniac/suppline/internal/types"
	"github.com/daimoniac/suppline/internal/vulnurl"
)

// TrivyScanner implements Scanner using Trivy CLI in client-server mode
type TrivyScanner struct {
	serverAddr       string
	token            string
	customHeaders    map[string]string
	timeout          time.Duration
	insecure         bool
	localFallback    bool // retry without --server when server-mode scan fails
	dockerConfigPath string
	logger           *slog.Logger
}

// NewTrivyScanner creates a new Trivy scanner client
func NewTrivyScanner(cfg config.ScannerConfig) (*TrivyScanner, error) {
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	scanner := &TrivyScanner{
		serverAddr:    cfg.ServerAddr,
		token:         cfg.Token,
		customHeaders: cfg.CustomHeaders,
		timeout:       cfg.Timeout,
		insecure:      cfg.Insecure,
		localFallback: cfg.LocalFallback,
		logger:        logger,
	}

	// Generate Docker config from suppline.yml if registry credentials are needed
	if cfg.RegsyncPath != "" {
		dockerConfigPath, err := GenerateDockerConfigFromRegsync(cfg.RegsyncPath)
		if err != nil {
			scanner.logger.Warn("failed to generate docker config from regsync", "error", err)
		} else {
			scanner.dockerConfigPath = dockerConfigPath
			scanner.logger.Info("generated docker config for registry authentication", "path", dockerConfigPath)
		}
	}

	return scanner, nil
}

// HealthCheck reports Trivy connectivity status
func (s *TrivyScanner) HealthCheck(ctx context.Context) error {
	// Check if trivy command is available
	cmd := exec.CommandContext(ctx, "trivy", "version")
	if err := cmd.Run(); err != nil {
		return errors.NewPermanentf("trivy command not available: %w", err)
	}
	return nil
}

// GenerateSBOM creates CycloneDX SBOM via Trivy
func (s *TrivyScanner) GenerateSBOM(ctx context.Context, imageRef string) (*SBOM, error) {
	startTime := time.Now()
	s.logger.Debug("invoking Trivy for SBOM generation", "image_ref", imageRef, "start_time", startTime)

	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	// Build trivy command for SBOM generation
	args := []string{
		"image",
		"--format", "cyclonedx",
		"--server", fmt.Sprintf("http://%s", s.serverAddr), // Trivy server is mandatory
	}

	// Add token if configured
	if s.token != "" {
		args = append(args, "--token", s.token)
	}

	args = append(args, imageRef)

	// Execute trivy command
	cmd := exec.CommandContext(ctx, "trivy", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	// Set DOCKER_CONFIG environment variable if we have a config path
	if s.dockerConfigPath != "" {
		cmd.Env = append(os.Environ(), fmt.Sprintf("DOCKER_CONFIG=%s", s.dockerConfigPath))
	}

	if err := cmd.Run(); err != nil {
		duration := time.Since(startTime)
		s.logger.Error("Trivy SBOM generation failed",
			"image_ref", imageRef,
			"duration", duration,
			"error", err)
		serverStderr := stderr.String()

		// If local fallback is enabled, retry without --server using local Trivy DB
		if s.localFallback {
			s.logger.Warn("retrying SBOM generation without server (local fallback)",
				"image_ref", imageRef,
				"server_stderr", serverStderr)
			result, fallbackErr := s.generateSBOMLocal(ctx, imageRef)
			if fallbackErr != nil {
				s.logger.Error("local fallback SBOM generation also failed",
					"image_ref", imageRef,
					"error", fallbackErr)
				// Return original server error so the error message reflects the root cause
				return nil, errors.NewTransientf("failed to generate SBOM for %s: %w, stderr: %s", imageRef, err, serverStderr)
			}
			s.logger.Info("SBOM generation succeeded via local fallback", "image_ref", imageRef)
			return result, nil
		}

		// SBOM generation failures are typically transient (network, timeout, registry issues)
		return nil, errors.NewTransientf("failed to generate SBOM for %s: %w, stderr: %s", imageRef, err, serverStderr)
	}

	duration := time.Since(startTime)
	s.logger.Debug("Trivy SBOM generation completed",
		"image_ref", imageRef,
		"duration", duration,
		"sbom_size_bytes", len(stdout.Bytes()))

	return &SBOM{
		Format:  "cyclonedx",
		Version: "1.5",
		Data:    stdout.Bytes(),
		Created: time.Now(),
	}, nil
}

// trivyScanResponse represents the JSON output from trivy
type trivyScanResponse struct {
	Results []trivyResult `json:"Results"`
}

type trivyResult struct {
	Target          string               `json:"Target"`
	Vulnerabilities []trivyVulnerability `json:"Vulnerabilities"`
}

type trivyVulnerability struct {
	VulnerabilityID  string   `json:"VulnerabilityID"`
	PkgName          string   `json:"PkgName"`
	InstalledVersion string   `json:"InstalledVersion"`
	FixedVersion     string   `json:"FixedVersion"`
	Severity         string   `json:"Severity"`
	Title            string   `json:"Title"`
	Description      string   `json:"Description"`
	References       []string `json:"References"`
	PrimaryURL       string   `json:"PrimaryURL"`
}

// ScanVulnerabilities performs vulnerability analysis via Trivy
// This method now generates BOTH JSON and cosign-vuln formats in a single scan to avoid redundant calls.
// When useVEXRepo is true, --vex repo is passed to Trivy to apply the Aqua VEX Hub.
func (s *TrivyScanner) ScanVulnerabilities(ctx context.Context, imageRef string, useVEXRepo bool) (*ScanResult, error) {
	startTime := time.Now()
	s.logger.Debug("invoking Trivy for vulnerability scan (JSON + cosign-vuln)", "image_ref", imageRef, "start_time", startTime)

	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	// Create temp file for cosign-vuln format output
	tmpFile, err := os.CreateTemp("", "trivy-cosign-vuln-*.json")
	if err != nil {
		// Temp file creation failure is typically transient (disk space, permissions)
		return nil, errors.NewTransientf("failed to create temp file for cosign-vuln: %w", err)
	}
	defer os.Remove(tmpFile.Name())
	tmpFile.Close()

	// Build trivy command for vulnerability scanning (JSON format for parsing)
	args := []string{
		"image",
		"--format", "json",
		"--quiet",
		"--scanners", "vuln",
		"--server", fmt.Sprintf("http://%s", s.serverAddr), // Trivy server is mandatory
	}

	// Add token if configured
	if s.token != "" {
		args = append(args, "--token", s.token)
	}

	if useVEXRepo {
		args = append(args, "--vex", "repo")
	}

	args = append(args, imageRef)

	// Execute trivy command for JSON output
	cmd := exec.CommandContext(ctx, "trivy", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	// Set DOCKER_CONFIG environment variable if we have a config path
	if s.dockerConfigPath != "" {
		cmd.Env = append(os.Environ(), fmt.Sprintf("DOCKER_CONFIG=%s", s.dockerConfigPath))
	}

	if err := cmd.Run(); err != nil {
		duration := time.Since(startTime)
		s.logger.Error("Trivy vulnerability scan failed",
			"image_ref", imageRef,
			"duration", duration,
			"error", err)
		serverStderr := stderr.String()

		// If local fallback is enabled, retry without --server using local Trivy DB
		if s.localFallback {
			s.logger.Warn("retrying vulnerability scan without server (local fallback)",
				"image_ref", imageRef,
				"server_stderr", serverStderr)
			result, fallbackErr := s.scanVulnerabilitiesLocal(ctx, imageRef, tmpFile.Name(), useVEXRepo)
			if fallbackErr != nil {
				s.logger.Error("local fallback vulnerability scan also failed",
					"image_ref", imageRef,
					"error", fallbackErr)
				// Return original server error so the error message reflects the root cause
				return nil, errors.NewTransientf("failed to scan vulnerabilities for %s: %w, stderr: %s", imageRef, err, serverStderr)
			}
			s.logger.Info("vulnerability scan succeeded via local fallback", "image_ref", imageRef)
			return result, nil
		}

		// Vulnerability scan failures are typically transient (network, timeout, registry issues)
		return nil, errors.NewTransientf("failed to scan vulnerabilities for %s: %w, stderr: %s", imageRef, err, serverStderr)
	}

	// Parse JSON response
	var response trivyScanResponse
	if err := json.Unmarshal(stdout.Bytes(), &response); err != nil {
		// JSON parsing failure is permanent (bad trivy output format)
		return nil, errors.NewPermanentf("failed to parse trivy output: %w", err)
	}

	// Extract vulnerabilities
	var vulnerabilities []types.Vulnerability
	for _, result := range response.Results {
		for _, vuln := range result.Vulnerabilities {
			primaryURL := vuln.PrimaryURL
			if primaryURL == "" && len(vuln.References) > 0 {
				primaryURL = vuln.References[0]
			}
			primaryURL = vulnurl.NormalizeRefURL(primaryURL)

			vulnerabilities = append(vulnerabilities, types.Vulnerability{
				ID:           vuln.VulnerabilityID,
				Severity:     vuln.Severity,
				PackageName:  vuln.PkgName,
				Version:      vuln.InstalledVersion,
				FixedVersion: vuln.FixedVersion,
				Title:        vuln.Title,
				Description:  vuln.Description,
				PrimaryURL:   primaryURL,
			})
		}
	}

	// Now generate cosign-vuln format (reuses cached scan data from Trivy)
	trivyArgs := []string{
		"image",
		"--format", "cosign-vuln",
		"--output", tmpFile.Name(),
		"--quiet",
		"--scanners", "vuln",
		"--server", fmt.Sprintf("http://%s", s.serverAddr), // Trivy server is mandatory
	}

	if s.token != "" {
		trivyArgs = append(trivyArgs, "--token", s.token)
	}

	if useVEXRepo {
		trivyArgs = append(trivyArgs, "--vex", "repo")
	}

	trivyArgs = append(trivyArgs, imageRef)

	cosignCmd := exec.CommandContext(ctx, "trivy", trivyArgs...)
	var cosignStderr bytes.Buffer
	cosignCmd.Stderr = &cosignStderr

	if s.dockerConfigPath != "" {
		cosignCmd.Env = append(os.Environ(), fmt.Sprintf("DOCKER_CONFIG=%s", s.dockerConfigPath))
	}

	if err := cosignCmd.Run(); err != nil {
		s.logger.Warn("failed to generate cosign-vuln format (continuing without it)",
			"image_ref", imageRef,
			"error", err,
			"stderr", cosignStderr.String())
		// Don't fail the entire scan if cosign-vuln generation fails
	}

	// Read cosign-vuln data
	var cosignVulnData []byte
	if data, err := os.ReadFile(tmpFile.Name()); err == nil {
		cosignVulnData = data
		s.logger.Debug("cosign-vuln format generated",
			"image_ref", imageRef,
			"size_bytes", len(cosignVulnData))
	}

	duration := time.Since(startTime)
	s.logger.Debug("Trivy vulnerability scan completed",
		"image_ref", imageRef,
		"duration", duration,
		"vulnerability_count", len(vulnerabilities),
		"cosign_vuln_generated", len(cosignVulnData) > 0)

	return &ScanResult{
		ImageRef:        imageRef,
		Vulnerabilities: vulnerabilities,
		ScannedAt:       time.Now(),
		CosignVulnData:  cosignVulnData,
	}, nil
}

// generateSBOMLocal retries SBOM generation without --server, using the local Trivy DB.
func (s *TrivyScanner) generateSBOMLocal(ctx context.Context, imageRef string) (*SBOM, error) {
	args := []string{
		"image",
		"--format", "cyclonedx",
	}
	if s.insecure {
		args = append(args, "--insecure")
	}
	args = append(args, imageRef)

	cmd := exec.CommandContext(ctx, "trivy", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if s.dockerConfigPath != "" {
		cmd.Env = append(os.Environ(), fmt.Sprintf("DOCKER_CONFIG=%s", s.dockerConfigPath))
	}

	if err := cmd.Run(); err != nil {
		return nil, errors.NewTransientf("local fallback SBOM failed for %s: %w, stderr: %s", imageRef, err, stderr.String())
	}

	return &SBOM{
		Format:  "cyclonedx",
		Version: "1.5",
		Data:    stdout.Bytes(),
		Created: time.Now(),
	}, nil
}

// scanVulnerabilitiesLocal retries vulnerability scanning without --server, using the local Trivy DB.
// cosignOutPath is the temp file path to write cosign-vuln output to.
func (s *TrivyScanner) scanVulnerabilitiesLocal(ctx context.Context, imageRef string, cosignOutPath string, useVEXRepo bool) (*ScanResult, error) {
	// JSON scan (no --quiet so Trivy can print DB download progress if needed)
	args := []string{
		"image",
		"--format", "json",
		"--scanners", "vuln",
	}
	if s.insecure {
		args = append(args, "--insecure")
	}
	if useVEXRepo {
		args = append(args, "--vex", "repo")
	}
	args = append(args, imageRef)

	cmd := exec.CommandContext(ctx, "trivy", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if s.dockerConfigPath != "" {
		cmd.Env = append(os.Environ(), fmt.Sprintf("DOCKER_CONFIG=%s", s.dockerConfigPath))
	}

	if err := cmd.Run(); err != nil {
		return nil, errors.NewTransientf("local fallback vuln scan failed for %s: %w, stderr: %s", imageRef, err, stderr.String())
	}

	var response trivyScanResponse
	if err := json.Unmarshal(stdout.Bytes(), &response); err != nil {
		return nil, errors.NewPermanentf("failed to parse local fallback trivy output: %w", err)
	}

	var vulnerabilities []types.Vulnerability
	for _, result := range response.Results {
		for _, vuln := range result.Vulnerabilities {
			primaryURL := vuln.PrimaryURL
			if primaryURL == "" && len(vuln.References) > 0 {
				primaryURL = vuln.References[0]
			}
			primaryURL = vulnurl.NormalizeRefURL(primaryURL)
			vulnerabilities = append(vulnerabilities, types.Vulnerability{
				ID:           vuln.VulnerabilityID,
				Severity:     vuln.Severity,
				PackageName:  vuln.PkgName,
				Version:      vuln.InstalledVersion,
				FixedVersion: vuln.FixedVersion,
				Title:        vuln.Title,
				Description:  vuln.Description,
				PrimaryURL:   primaryURL,
			})
		}
	}

	// cosign-vuln format (best-effort)
	cosignArgs := []string{
		"image",
		"--format", "cosign-vuln",
		"--output", cosignOutPath,
		"--scanners", "vuln",
	}
	if s.insecure {
		cosignArgs = append(cosignArgs, "--insecure")
	}
	if useVEXRepo {
		cosignArgs = append(cosignArgs, "--vex", "repo")
	}
	cosignArgs = append(cosignArgs, imageRef)

	cosignCmd := exec.CommandContext(ctx, "trivy", cosignArgs...)
	var cosignStderr bytes.Buffer
	cosignCmd.Stderr = &cosignStderr
	if s.dockerConfigPath != "" {
		cosignCmd.Env = append(os.Environ(), fmt.Sprintf("DOCKER_CONFIG=%s", s.dockerConfigPath))
	}
	if err := cosignCmd.Run(); err != nil {
		s.logger.Warn("local fallback cosign-vuln generation failed (continuing without it)",
			"image_ref", imageRef,
			"error", err,
			"stderr", cosignStderr.String())
	}

	var cosignVulnData []byte
	if data, err := os.ReadFile(cosignOutPath); err == nil {
		cosignVulnData = data
	}

	return &ScanResult{
		ImageRef:        imageRef,
		Vulnerabilities: vulnerabilities,
		ScannedAt:       time.Now(),
		CosignVulnData:  cosignVulnData,
	}, nil
}
