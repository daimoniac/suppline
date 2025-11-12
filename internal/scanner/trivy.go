package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os/exec"
	"time"

	"github.com/suppline/suppline/internal/config"
)

// TrivyScanner implements Scanner using Trivy CLI in client-server mode
type TrivyScanner struct {
	serverAddr    string
	token         string
	customHeaders map[string]string
	timeout       time.Duration
	insecure      bool
	logger        *slog.Logger
}

// NewTrivyScanner creates a new Trivy scanner client
func NewTrivyScanner(cfg config.ScannerConfig) (*TrivyScanner, error) {
	scanner := &TrivyScanner{
		serverAddr:    cfg.ServerAddr,
		token:         cfg.Token,
		customHeaders: cfg.CustomHeaders,
		timeout:       cfg.Timeout,
		insecure:      cfg.Insecure,
		logger:        slog.Default(),
	}

	return scanner, nil
}

// HealthCheck reports Trivy connectivity status
func (s *TrivyScanner) HealthCheck(ctx context.Context) error {
	// Check if trivy command is available
	cmd := exec.CommandContext(ctx, "trivy", "version")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("trivy command not available: %w", err)
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
		"--quiet",
	}

	// Add server address if configured
	if s.serverAddr != "" {
		args = append(args, "--server", fmt.Sprintf("http://%s", s.serverAddr))
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

	if err := cmd.Run(); err != nil {
		duration := time.Since(startTime)
		s.logger.Error("Trivy SBOM generation failed", 
			"image_ref", imageRef, 
			"duration", duration,
			"error", err)
		return nil, fmt.Errorf("failed to generate SBOM for %s: %w, stderr: %s", imageRef, err, stderr.String())
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
	Target          string                `json:"Target"`
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
func (s *TrivyScanner) ScanVulnerabilities(ctx context.Context, imageRef string) (*ScanResult, error) {
	startTime := time.Now()
	s.logger.Debug("invoking Trivy for vulnerability scan", "image_ref", imageRef, "start_time", startTime)
	
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	// Build trivy command for vulnerability scanning
	args := []string{
		"image",
		"--format", "json",
		"--quiet",
		"--scanners", "vuln",
	}

	// Add server address if configured
	if s.serverAddr != "" {
		args = append(args, "--server", fmt.Sprintf("http://%s", s.serverAddr))
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

	if err := cmd.Run(); err != nil {
		duration := time.Since(startTime)
		s.logger.Error("Trivy vulnerability scan failed", 
			"image_ref", imageRef, 
			"duration", duration,
			"error", err)
		return nil, fmt.Errorf("failed to scan vulnerabilities for %s: %w, stderr: %s", imageRef, err, stderr.String())
	}

	// Parse JSON response
	var response trivyScanResponse
	if err := json.Unmarshal(stdout.Bytes(), &response); err != nil {
		return nil, fmt.Errorf("failed to parse trivy output: %w", err)
	}

	// Extract vulnerabilities
	var vulnerabilities []Vulnerability
	for _, result := range response.Results {
		for _, vuln := range result.Vulnerabilities {
			primaryURL := vuln.PrimaryURL
			if primaryURL == "" && len(vuln.References) > 0 {
				primaryURL = vuln.References[0]
			}

			vulnerabilities = append(vulnerabilities, Vulnerability{
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

	duration := time.Since(startTime)
	s.logger.Debug("Trivy vulnerability scan completed", 
		"image_ref", imageRef, 
		"duration", duration,
		"vulnerability_count", len(vulnerabilities))

	return &ScanResult{
		ImageRef:        imageRef,
		Vulnerabilities: vulnerabilities,
		ScannedAt:       time.Now(),
	}, nil
}


