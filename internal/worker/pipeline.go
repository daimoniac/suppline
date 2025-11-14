package worker

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/suppline/suppline/internal/errors"
	"github.com/suppline/suppline/internal/policy"
	"github.com/suppline/suppline/internal/queue"
	"github.com/suppline/suppline/internal/scanner"
)

// Pipeline orchestrates the complete scan workflow
type Pipeline struct {
	worker *ImageWorker
	logger *slog.Logger
}

// NewPipeline creates a new pipeline instance
func NewPipeline(worker *ImageWorker, logger *slog.Logger) *Pipeline {
	return &Pipeline{
		worker: worker,
		logger: logger,
	}
}

// Execute runs the complete scan workflow for a single image
func (p *Pipeline) Execute(ctx context.Context, task *queue.ScanTask) error {
	startTime := time.Now()
	imageRef := fmt.Sprintf("%s@%s", task.Repository, task.Digest)

	p.logger.Info("starting scan workflow",
		"task_id", task.ID,
		"image_ref", imageRef,
		"is_rescan", task.IsRescan)

	// Validate dependencies
	if err := p.validateDependencies(); err != nil {
		return err
	}

	// Phase 1: Scan (SBOM + Vulnerabilities)
	sbom, scanResult, scanDurations, err := p.scanPhase(ctx, imageRef)
	if err != nil {
		return err
	}

	// Phase 2: Policy Evaluation
	policyDecision, err := p.policyPhase(ctx, task, imageRef, scanResult)
	if err != nil {
		return err
	}

	// Phase 3: Attestations (SBOM, Vulnerabilities, SCAI)
	attestDurations, scaiAttested, err := p.attestationPhase(ctx, task, imageRef, sbom, scanResult)
	if err != nil {
		return err
	}

	// Phase 4: Signing (conditional)
	signed, err := p.signingPhase(ctx, imageRef, policyDecision)
	if err != nil {
		return err
	}

	// Phase 5: Persistence
	if err := p.persistencePhase(ctx, task, scanResult, policyDecision, signed, startTime); err != nil {
		// Log error but don't fail - attestations and signatures are already created
		p.logger.Error("failed to persist scan results", "image_ref", imageRef, "error", err)
	}

	// Log completion
	p.logCompletion(task, imageRef, startTime, scanDurations, attestDurations, scaiAttested, policyDecision, signed)

	return nil
}

// validateDependencies ensures all required components are configured
func (p *Pipeline) validateDependencies() error {
	if p.worker.registry == nil {
		return errors.NewPermanentf("registry client is not configured")
	}
	if p.worker.scanner == nil {
		return errors.NewPermanentf("scanner is not configured")
	}
	if p.worker.policy == nil {
		return errors.NewPermanentf("policy engine is not configured")
	}
	if p.worker.attestor == nil {
		return errors.NewPermanentf("attestor is not configured")
	}
	if p.worker.stateStore == nil {
		return errors.NewPermanentf("state store is not configured")
	}
	return nil
}

// scanPhase performs SBOM generation and vulnerability scanning
func (p *Pipeline) scanPhase(ctx context.Context, imageRef string) (*scanner.SBOM, *scanner.ScanResult, map[string]time.Duration, error) {
	durations := make(map[string]time.Duration)

	// Fetch image metadata
	p.logger.Debug("fetching image metadata", "image_ref", imageRef)
	manifest, err := p.worker.registry.GetManifest(ctx, extractRepository(imageRef), extractDigest(imageRef))
	if err != nil {
		// Error already classified in registry package
		return nil, nil, nil, fmt.Errorf("failed to fetch image metadata: %w", err)
	}
	p.logger.Debug("image metadata fetched",
		"digest", manifest.Digest,
		"architecture", manifest.Architecture,
		"os", manifest.OS)

	// Generate SBOM
	sbomStart := time.Now()
	p.logger.Debug("generating SBOM", "image_ref", imageRef)
	sbom, err := p.worker.scanner.GenerateSBOM(ctx, imageRef)
	if err != nil {
		// Error already classified in scanner package
		return nil, nil, nil, fmt.Errorf("failed to generate SBOM: %w", err)
	}
	durations["sbom"] = time.Since(sbomStart)
	p.logger.Info("SBOM generated",
		"image_ref", imageRef,
		"format", sbom.Format,
		"version", sbom.Version,
		"size_bytes", len(sbom.Data),
		"duration", durations["sbom"])

	// Scan vulnerabilities
	vulnStart := time.Now()
	p.logger.Debug("scanning vulnerabilities", "image_ref", imageRef)
	scanResult, err := p.worker.scanner.ScanVulnerabilities(ctx, imageRef)
	if err != nil {
		// Error already classified in scanner package
		return nil, nil, nil, fmt.Errorf("failed to scan vulnerabilities: %w", err)
	}
	durations["vuln_scan"] = time.Since(vulnStart)
	p.logger.Info("vulnerability scan completed",
		"image_ref", imageRef,
		"total_vulnerabilities", len(scanResult.Vulnerabilities),
		"duration", durations["vuln_scan"])

	return sbom, scanResult, durations, nil
}

// policyPhase evaluates policy with CVE tolerations
func (p *Pipeline) policyPhase(ctx context.Context, task *queue.ScanTask, imageRef string, scanResult *scanner.ScanResult) (*policy.PolicyDecision, error) {
	// Get policy engine for this repository
	policyEngine, err := p.getPolicyEngineForRepository(task.Repository)
	if err != nil {
		return nil, errors.NewPermanentf("failed to create policy engine: %w", err)
	}

	// Evaluate policy
	p.logger.Debug("evaluating policy", "image_ref", imageRef, "tolerations", len(task.Tolerations))
	policyDecision, err := policyEngine.Evaluate(ctx, imageRef, scanResult, task.Tolerations)
	if err != nil {
		return nil, errors.NewPermanentf("failed to evaluate policy: %w", err)
	}

	p.logger.Info("policy evaluation completed",
		"image_ref", imageRef,
		"passed", policyDecision.Passed,
		"reason", policyDecision.Reason)

	// Log expiring tolerations
	for _, expiring := range policyDecision.ExpiringTolerations {
		p.logger.Warn("toleration expiring soon",
			"cve_id", expiring.CVEID,
			"statement", expiring.Statement,
			"expires_at", expiring.ExpiresAt,
			"days_until_expiry", expiring.DaysUntil,
			"image_ref", imageRef)
	}

	return policyDecision, nil
}

// attestationPhase creates all attestations (SBOM, vulnerabilities, SCAI)
func (p *Pipeline) attestationPhase(ctx context.Context, task *queue.ScanTask, imageRef string, sbom *scanner.SBOM, scanResult *scanner.ScanResult) (map[string]time.Duration, bool, error) {
	durations := make(map[string]time.Duration)

	// SBOM attestation
	sbomStart := time.Now()
	p.logger.Debug("creating SBOM attestation", "image_ref", imageRef)
	if err := p.worker.attestor.AttestSBOM(ctx, imageRef, sbom); err != nil {
		// Error already classified in attestation package
		return nil, false, fmt.Errorf("failed to create SBOM attestation: %w", err)
	}
	durations["sbom_attest"] = time.Since(sbomStart)
	p.logger.Info("SBOM attestation created", "image_ref", imageRef, "duration", durations["sbom_attest"])

	// Vulnerability attestation
	vulnStart := time.Now()
	p.logger.Debug("creating vulnerability attestation", "image_ref", imageRef)
	if err := p.worker.attestor.AttestVulnerabilities(ctx, imageRef, scanResult); err != nil {
		// Error already classified in attestation package
		return nil, false, fmt.Errorf("failed to create vulnerability attestation: %w", err)
	}
	durations["vuln_attest"] = time.Since(vulnStart)
	p.logger.Info("vulnerability attestation created", "image_ref", imageRef, "duration", durations["vuln_attest"])

	// SCAI attestation (optional)
	scaiAttested := false
	if p.worker.scaiGenerator != nil {
		scaiStart := time.Now()
		p.logger.Debug("generating SCAI attestation", "image_ref", imageRef)

		scai, err := p.worker.scaiGenerator.GenerateSCAI(ctx, imageRef, scanResult, task.Repository)
		if err != nil {
			p.logger.Error("failed to generate SCAI attestation", "image_ref", imageRef, "error", err)
		} else {
			if err := p.worker.attestor.AttestSCAI(ctx, imageRef, scai); err != nil {
				p.logger.Error("failed to attest SCAI", "image_ref", imageRef, "error", err)
			} else {
				scaiAttested = true
				durations["scai_attest"] = time.Since(scaiStart)
				p.logger.Info("SCAI attestation created", "image_ref", imageRef, "duration", durations["scai_attest"])
			}
		}
	} else {
		p.logger.Debug("SCAI generator not configured, skipping SCAI attestation", "image_ref", imageRef)
	}

	return durations, scaiAttested, nil
}

// signingPhase signs the image if policy passes
func (p *Pipeline) signingPhase(ctx context.Context, imageRef string, policyDecision *policy.PolicyDecision) (bool, error) {
	if !policyDecision.ShouldSign {
		p.logger.Info("image not signed due to policy failure",
			"image_ref", imageRef,
			"reason", policyDecision.Reason)
		return false, nil
	}

	p.logger.Debug("signing image", "image_ref", imageRef)
	if err := p.worker.attestor.SignImage(ctx, imageRef); err != nil {
		// Error already classified in attestation package
		return false, fmt.Errorf("failed to sign image: %w", err)
	}
	p.logger.Info("image signed", "image_ref", imageRef)
	return true, nil
}

// persistencePhase records scan results to state store
func (p *Pipeline) persistencePhase(ctx context.Context, task *queue.ScanTask, scanResult *scanner.ScanResult, policyDecision *policy.PolicyDecision, signed bool, scannedAt time.Time) error {
	// Build scan record from workflow results
	scanRecord := buildScanRecord(task, scanResult, policyDecision, signed, scannedAt)

	p.logger.Debug("recording scan results", "image_ref", fmt.Sprintf("%s@%s", task.Repository, task.Digest))
	if err := p.worker.stateStore.RecordScan(ctx, scanRecord); err != nil {
		return err
	}

	p.logger.Info("scan results recorded", "image_ref", fmt.Sprintf("%s@%s", task.Repository, task.Digest))

	// Check for policy failures and alerts
	p.checkPolicyFailures(ctx, task, policyDecision)

	return nil
}

// checkPolicyFailures logs warnings and alerts for policy failures
func (p *Pipeline) checkPolicyFailures(ctx context.Context, task *queue.ScanTask, policyDecision *policy.PolicyDecision) {
	if !policyDecision.Passed {
		p.logger.Warn("image failed policy evaluation",
			"digest", task.Digest,
			"repository", task.Repository,
			"tag", task.Tag,
			"critical_vulns", policyDecision.CriticalVulnCount,
			"tolerated_vulns", policyDecision.ToleratedVulnCount,
			"reason", policyDecision.Reason)
	}

	// Alert if rescan shows previously signed image now fails
	if task.IsRescan && !policyDecision.Passed {
		lastScan, err := p.worker.stateStore.GetLastScan(ctx, task.Digest)
		if err == nil && lastScan != nil && lastScan.Signed {
			p.logger.Error("ALERT: previously signed image now fails policy",
				"digest", task.Digest,
				"repository", task.Repository,
				"tag", task.Tag,
				"previous_scan", lastScan.ScannedAt,
				"critical_vulns", policyDecision.CriticalVulnCount,
				"reason", policyDecision.Reason)
		}
	}
}

// logCompletion logs the final workflow completion with all durations
func (p *Pipeline) logCompletion(task *queue.ScanTask, imageRef string, startTime time.Time, scanDurations, attestDurations map[string]time.Duration, scaiAttested bool, policyDecision *policy.PolicyDecision, signed bool) {
	duration := time.Since(startTime)
	p.logger.Info("scan workflow completed",
		"task_id", task.ID,
		"image_ref", imageRef,
		"total_duration", duration,
		"sbom_generation_duration", scanDurations["sbom"],
		"vulnerability_scan_duration", scanDurations["vuln_scan"],
		"sbom_attestation_duration", attestDurations["sbom_attest"],
		"vulnerability_attestation_duration", attestDurations["vuln_attest"],
		"scai_attestation_duration", attestDurations["scai_attest"],
		"scai_attested", scaiAttested,
		"policy_passed", policyDecision.Passed,
		"signed", signed)
}

// getPolicyEngineForRepository returns a policy engine for the given repository
func (p *Pipeline) getPolicyEngineForRepository(repository string) (policy.PolicyEngine, error) {
	var policyConfig policy.PolicyConfig

	// Try to get policy from regsync config
	if p.worker.regsyncCfg != nil {
		if regsyncPolicy := p.worker.regsyncCfg.GetPolicyForTarget(repository); regsyncPolicy != nil {
			policyConfig = policy.PolicyConfig{
				Expression:     regsyncPolicy.Expression,
				FailureMessage: regsyncPolicy.FailureMessage,
			}
			p.logger.Debug("using repository-specific policy",
				"repository", repository,
				"expression", policyConfig.Expression)
		}
	}

	// If no policy configured, use default from worker
	if policyConfig.Expression == "" {
		return p.worker.policy, nil
	}

	// Create a new policy engine with the repository-specific config
	return policy.NewEngine(p.logger, policyConfig)
}

