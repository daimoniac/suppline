package worker

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/daimoniac/suppline/internal/errors"
	"github.com/daimoniac/suppline/internal/observability"
	"github.com/daimoniac/suppline/internal/policy"
	"github.com/daimoniac/suppline/internal/queue"
	"github.com/daimoniac/suppline/internal/registry"
	"github.com/daimoniac/suppline/internal/scanner"
	"github.com/daimoniac/suppline/internal/statestore"
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

	p.logger.Debug("starting scan workflow",
		"task_id", task.ID,
		"image_ref", imageRef,
		"is_rescan", task.IsRescan)

	// Validate dependencies
	if err := p.validateDependencies(); err != nil {
		return err
	}

	// Phase 1: Scan (SBOM + Vulnerabilities)
	sbom, scanResult, scanDurations, err := p.scanPhase(ctx, task, imageRef)
	if err != nil {
		metrics := observability.GetMetrics()
		metrics.ScansFailed.Inc()
		// Check if this is a MANIFEST_UNKNOWN error that requires cleanup
		if errors.IsManifestNotFound(err) {
			p.logger.Info("manifest not found, performing cleanup",
				"image_ref", imageRef,
				"digest", task.Digest)

			// Perform cleanup before returning error
			if cleanupErr := p.performManifestCleanup(ctx, task.Digest); cleanupErr != nil {
				// If cleanup fails with transient error, return cleanup error for retry
				if errors.IsTransient(cleanupErr) {
					p.logger.Error("transient cleanup error after manifest not found",
						"image_ref", imageRef,
						"digest", task.Digest,
						"cleanup_error", cleanupErr)
					return cleanupErr
				}
				// Permanent cleanup errors are already logged in performManifestCleanup
			}
		}
		return err
	}

	// Phase 2: Policy Evaluation
	policyDecision, err := p.policyPhase(ctx, task, imageRef, scanResult)
	if err != nil {
		metrics := observability.GetMetrics()
		metrics.PolicyFailed.Inc()
		return err
	}

	// Phase 3: Attestations (SBOM, Vulnerabilities, SCAI)
	attestDurations, scaiAttested, err := p.attestationPhase(ctx, task, imageRef, sbom, scanResult, policyDecision)
	if err != nil {
		return err
	}

	// Phase 4: Persistence
	if err := p.persistencePhase(ctx, task, scanResult, policyDecision, startTime); err != nil {
		// Check if persistence or cleanup failed with transient error
		if errors.IsTransient(err) {
			// Return transient errors to allow retry
			return err
		}
		// Log permanent errors but don't fail - attestations and signatures are already created
		p.logger.Error("permanent error during persistence phase", "image_ref", imageRef, "error", err)
	}

	// Log completion
	totalDuration := time.Since(startTime)
	p.logCompletion(task, imageRef, startTime, scanDurations, attestDurations, scaiAttested, policyDecision, totalDuration)

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
func (p *Pipeline) scanPhase(ctx context.Context, task *queue.ScanTask, imageRef string) (*scanner.SBOM, *scanner.ScanResult, map[string]time.Duration, error) {
	durations := make(map[string]time.Duration)
	metrics := observability.GetMetrics()

	// Fetch image metadata with tag verification if available
	p.logger.Debug("fetching image metadata", "image_ref", imageRef)
	manifest, err := p.fetchImageMetadata(ctx, task, imageRef)
	if err != nil {
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
		// Classify scanner errors to detect MANIFEST_UNKNOWN
		classifiedErr := errors.ClassifyRegistryError(err)
		return nil, nil, nil, fmt.Errorf("failed to generate SBOM: %w", classifiedErr)
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
		// Classify scanner errors to detect MANIFEST_UNKNOWN
		classifiedErr := errors.ClassifyRegistryError(err)
		return nil, nil, nil, fmt.Errorf("failed to scan vulnerabilities: %w", classifiedErr)
	}
	durations["vuln_scan"] = time.Since(vulnStart)
	p.logger.Info("vulnerability scan completed",
		"image_ref", imageRef,
		"total_vulnerabilities", len(scanResult.Vulnerabilities),
		"duration", durations["vuln_scan"])

	// Record scan metrics
	metrics.ScansTotal.Inc()
	metrics.ScanDuration.Observe(durations["vuln_scan"].Seconds())

	// Count vulnerabilities by severity
	severityCounts := make(map[string]int)
	for _, vuln := range scanResult.Vulnerabilities {
		severityCounts[vuln.Severity]++
	}
	for severity, count := range severityCounts {
		metrics.VulnerabilitiesFound.WithLabelValues(severity).Add(float64(count))
	}

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

	// Record policy metrics
	metrics := observability.GetMetrics()
	if policyDecision.Passed {
		metrics.PolicyPassed.Inc()
	} else {
		metrics.PolicyFailed.Inc()
	}

	// Record tolerated CVE count
	if policyDecision.ToleratedVulnCount > 0 {
		metrics.ToleratedCVEs.Add(float64(policyDecision.ToleratedVulnCount))
	}

	// Record toleration expiry metrics
	expiredCount := 0
	expiringCount := 0
	now := time.Now()

	for _, toleration := range task.Tolerations {
		if toleration.ExpiresAt == nil {
			// No expiry set, skip
			continue
		}
		expiresAt := time.Unix(*toleration.ExpiresAt, 0)
		if expiresAt.Before(now) {
			// Toleration has already expired
			expiredCount++
		} else {
			// Check if expiring within 7 days
			daysUntilExpiry := expiresAt.Sub(now).Hours() / 24
			if daysUntilExpiry <= 7 {
				expiringCount++
			}
		}
	}

	// Update gauges with per-repository metrics
	if expiredCount > 0 || expiringCount > 0 {
		metrics.ExpiredTolerations.WithLabelValues(task.Repository).Set(float64(expiredCount))
		metrics.ExpiringTolerationsSoon.WithLabelValues(task.Repository).Set(float64(expiringCount))
	}

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
func (p *Pipeline) attestationPhase(ctx context.Context, task *queue.ScanTask, imageRef string, sbom *scanner.SBOM, scanResult *scanner.ScanResult, policyDecision *policy.PolicyDecision) (map[string]time.Duration, bool, error) {
	durations := make(map[string]time.Duration)
	metrics := observability.GetMetrics()

	// SBOM attestation
	sbomStart := time.Now()
	p.logger.Debug("creating SBOM attestation", "image_ref", imageRef)
	if err := p.worker.attestor.AttestSBOM(ctx, imageRef, sbom); err != nil {
		// Error already classified in attestation package
		metrics.AttestationsFailed.WithLabelValues("sbom").Inc()
		return nil, false, fmt.Errorf("failed to create SBOM attestation: %w", err)
	}
	durations["sbom_attest"] = time.Since(sbomStart)
	metrics.AttestationsCreated.WithLabelValues("sbom").Inc()
	p.logger.Info("SBOM attestation created", "image_ref", imageRef, "duration", durations["sbom_attest"])

	// Vulnerability attestation
	vulnStart := time.Now()
	p.logger.Debug("creating vulnerability attestation", "image_ref", imageRef)
	if err := p.worker.attestor.AttestVulnerabilities(ctx, imageRef, scanResult); err != nil {
		// Error already classified in attestation package
		metrics.AttestationsFailed.WithLabelValues("vulnerability").Inc()
		return nil, false, fmt.Errorf("failed to create vulnerability attestation: %w", err)
	}
	durations["vuln_attest"] = time.Since(vulnStart)
	metrics.AttestationsCreated.WithLabelValues("vulnerability").Inc()
	p.logger.Info("vulnerability attestation created", "image_ref", imageRef, "duration", durations["vuln_attest"])

	// SCAI attestation (optional)
	scaiAttested := false
	if p.worker.scaiGenerator != nil {
		scaiStart := time.Now()
		p.logger.Debug("generating SCAI attestation", "image_ref", imageRef)

		scai, err := p.worker.scaiGenerator.GenerateSCAI(ctx, imageRef, scanResult, task.Repository, policyDecision)
		if err != nil {
			p.logger.Error("failed to generate SCAI attestation", "image_ref", imageRef, "error", err)
			metrics.AttestationsFailed.WithLabelValues("scai").Inc()
		} else {
			if err := p.worker.attestor.AttestSCAI(ctx, imageRef, scai); err != nil {
				p.logger.Error("failed to attest SCAI", "image_ref", imageRef, "error", err)
				metrics.AttestationsFailed.WithLabelValues("scai").Inc()
			} else {
				scaiAttested = true
				durations["scai_attest"] = time.Since(scaiStart)
				metrics.AttestationsCreated.WithLabelValues("scai").Inc()
				p.logger.Info("SCAI attestation created", "image_ref", imageRef, "duration", durations["scai_attest"])
			}
		}
	} else {
		p.logger.Debug("SCAI generator not configured, skipping SCAI attestation", "image_ref", imageRef)
	}

	return durations, scaiAttested, nil
}

// persistencePhase records scan results to state store
func (p *Pipeline) persistencePhase(ctx context.Context, task *queue.ScanTask, scanResult *scanner.ScanResult, policyDecision *policy.PolicyDecision, scannedAt time.Time) error {
	// Build scan record from workflow results
	scanRecord := buildScanRecord(task, scanResult, policyDecision, scannedAt)

	// Calculate and update scan duration
	scanDuration := time.Since(scannedAt)
	updateScanRecordWithDuration(scanRecord, scanDuration)

	p.logger.Debug("recording scan results", "image_ref", fmt.Sprintf("%s@%s", task.Repository, task.Digest))
	if err := p.worker.stateStore.RecordScan(ctx, scanRecord); err != nil {
		return err
	}

	p.logger.Info("scan results recorded", "image_ref", fmt.Sprintf("%s@%s", task.Repository, task.Digest))

	// Perform cleanup of excess scans after recording (regardless of success/failure)
	if err := p.performScanCleanup(ctx, task.Digest); err != nil {
		// If cleanup fails with transient error, return error for retry
		if errors.IsTransient(err) {
			p.logger.Error("transient cleanup error after scan recording",
				"image_ref", fmt.Sprintf("%s@%s", task.Repository, task.Digest),
				"digest", task.Digest,
				"cleanup_error", err)
			return err
		}
		// Permanent cleanup errors are already logged in performScanCleanup
	}

	// Check for policy failures and alerts
	p.checkPolicyFailures(ctx, task, policyDecision)

	return nil
}

// updateScanRecordWithDuration updates the scan record with calculated duration
func updateScanRecordWithDuration(scanRecord *statestore.ScanRecord, duration time.Duration) {
	scanRecord.ScanDurationMs = int(duration.Milliseconds())
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

	// Alert if rescan shows policy failure
	if task.IsRescan && !policyDecision.Passed {
		lastScan, err := p.worker.stateStore.GetLastScan(ctx, task.Digest)
		if err == nil && lastScan != nil && lastScan.PolicyPassed {
			p.logger.Error("ALERT: previously passing image now fails policy",
				"digest", task.Digest,
				"repository", task.Repository,
				"tag", task.Tag,
				"previous_scan", lastScan.CreatedAt,
				"critical_vulns", policyDecision.CriticalVulnCount,
				"reason", policyDecision.Reason)
		}
	}
}

// logCompletion logs the final workflow completion with all durations
func (p *Pipeline) logCompletion(task *queue.ScanTask, imageRef string, startTime time.Time, scanDurations, attestDurations map[string]time.Duration, scaiAttested bool, policyDecision *policy.PolicyDecision, totalDuration time.Duration) {
	p.logger.Info("scan workflow completed",
		"task_id", task.ID,
		"image_ref", imageRef,
		"total_duration", totalDuration,
		"sbom_generation_duration", scanDurations["sbom"],
		"vulnerability_scan_duration", scanDurations["vuln_scan"],
		"sbom_attestation_duration", attestDurations["sbom_attest"],
		"vulnerability_attestation_duration", attestDurations["vuln_attest"],
		"scai_attestation_duration", attestDurations["scai_attest"],
		"scai_attested", scaiAttested,
		"policy_passed", policyDecision.Passed)
}

// performManifestCleanup handles cleanup when MANIFEST_UNKNOWN errors occur
func (p *Pipeline) performManifestCleanup(ctx context.Context, digest string) error {
	// Cast to cleanup interface
	cleanupStore, ok := p.worker.stateStore.(statestore.StateStoreCleanup)
	if !ok {
		p.logger.Warn("state store does not support cleanup operations", "digest", digest)
		return nil // Not an error - just log and continue
	}

	p.logger.Info("cleaning up artifact scans due to manifest not found", "digest", digest)

	// Cleanup all scans for this artifact
	if err := cleanupStore.CleanupArtifactScans(ctx, digest); err != nil {
		// Classify cleanup error for proper retry behavior
		if errors.IsTransient(err) {
			// Transient cleanup errors should allow retry
			return fmt.Errorf("failed to cleanup artifact scans: %w", err)
		}
		// Permanent cleanup errors should be logged but not fail the pipeline
		p.logger.Error("permanent error during artifact cleanup",
			"digest", digest,
			"error", err)
		// Continue with repository cleanup despite permanent error
	} else {
		p.logger.Info("artifact cleanup completed", "digest", digest)
	}

	// Cleanup orphaned repositories after artifact cleanup
	if err := p.performRepositoryCleanup(ctx, cleanupStore); err != nil {
		// Repository cleanup errors are handled within performRepositoryCleanup
		// Transient errors are returned, permanent errors are logged
		if errors.IsTransient(err) {
			return fmt.Errorf("repository cleanup failed: %w", err)
		}
	}

	return nil
}

// performScanCleanup handles cleanup after scan recording (success or failure)
func (p *Pipeline) performScanCleanup(ctx context.Context, digest string) error {
	// Cast to cleanup interface
	cleanupStore, ok := p.worker.stateStore.(statestore.StateStoreCleanup)
	if !ok {
		p.logger.Warn("state store does not support cleanup operations", "digest", digest)
		return nil // Not an error - just log and continue
	}

	// Get the most recent scan to use as the keepScanID
	lastScan, err := p.worker.stateStore.GetLastScan(ctx, digest)
	if err != nil {
		// Classify GetLastScan error for proper retry behavior
		if errors.IsTransient(err) {
			return fmt.Errorf("failed to get last scan for cleanup: %w", err)
		}
		// Permanent errors should be logged but not fail the pipeline
		p.logger.Error("permanent error getting last scan for cleanup",
			"digest", digest,
			"error", err)
		return nil
	}

	p.logger.Info("cleaning up excess scans after scan recording",
		"digest", digest,
		"keep_scan_id", lastScan.ID)

	// Cleanup excess scans, keeping only the most recent scan (maxScansToKeep = 1)
	if err := cleanupStore.CleanupExcessScans(ctx, digest, 1); err != nil {
		// Classify cleanup error for proper retry behavior
		if errors.IsTransient(err) {
			// Transient cleanup errors should allow retry
			return fmt.Errorf("failed to cleanup excess scans: %w", err)
		}
		// Permanent cleanup errors should be logged but not fail the pipeline
		p.logger.Error("permanent error during excess scan cleanup",
			"digest", digest,
			"error", err)
		// Continue with repository cleanup despite permanent error
	} else {
		p.logger.Info("excess scan cleanup completed", "digest", digest)
	}

	// Cleanup orphaned repositories after scan cleanup
	if err := p.performRepositoryCleanup(ctx, cleanupStore); err != nil {
		// Repository cleanup errors are handled within performRepositoryCleanup
		// Transient errors are returned, permanent errors are logged
		if errors.IsTransient(err) {
			return fmt.Errorf("repository cleanup failed: %w", err)
		}
	}

	return nil
}

// performRepositoryCleanup handles cleanup of orphaned repositories
func (p *Pipeline) performRepositoryCleanup(ctx context.Context, cleanupStore statestore.StateStoreCleanup) error {
	p.logger.Debug("cleaning up orphaned repositories")

	deletedRepos, err := cleanupStore.CleanupOrphanedRepositories(ctx)
	if err != nil {
		// Classify cleanup errors appropriately
		if errors.IsTransient(err) {
			// Return transient errors to allow retry
			return fmt.Errorf("transient error during repository cleanup: %w", err)
		}
		// Log permanent errors but don't fail the pipeline
		p.logger.Error("permanent error during repository cleanup", "error", err)
		return nil
	}

	if len(deletedRepos) > 0 {
		p.logger.Info("orphaned repositories cleaned up",
			"deleted_count", len(deletedRepos),
			"repositories", deletedRepos)
	} else {
		p.logger.Debug("no orphaned repositories found")
	}

	return nil
}

// fetchImageMetadata retrieves image metadata with optional tag verification
func (p *Pipeline) fetchImageMetadata(ctx context.Context, task *queue.ScanTask, imageRef string) (*registry.Manifest, error) {
	repo := extractRepository(imageRef)
	digest := extractDigest(imageRef)

	// If we have both tag and digest, use verification to detect deleted tags
	if task.Tag != "" && task.Tag != "latest" {
		p.logger.Debug("fetching image metadata with tag verification",
			"image_ref", imageRef,
			"tag", task.Tag,
			"digest", digest)

		manifest, err := p.worker.registry.GetManifestWithTagVerification(ctx, repo, task.Tag, digest)
		if err != nil {
			// Error is already classified in registry client
			return nil, err
		}
		return manifest, nil
	}

	// Fallback to digest-only fetch (for latest tags or when tag is unavailable)
	p.logger.Debug("fetching image metadata by digest only",
		"image_ref", imageRef,
		"digest", digest)

	manifest, err := p.worker.registry.GetManifest(ctx, repo, digest)
	if err != nil {
		// Classify registry errors to detect MANIFEST_UNKNOWN
		classifiedErr := errors.ClassifyRegistryError(err)
		return nil, classifiedErr
	}
	return manifest, nil
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
