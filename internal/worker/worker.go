package worker

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/suppline/suppline/internal/attestation"
	"github.com/suppline/suppline/internal/policy"
	"github.com/suppline/suppline/internal/queue"
	"github.com/suppline/suppline/internal/registry"
	"github.com/suppline/suppline/internal/regsync"
	"github.com/suppline/suppline/internal/scanner"
	"github.com/suppline/suppline/internal/statestore"
)

// Worker defines the interface for processing scan tasks
type Worker interface {
	// Start begins processing tasks from the queue
	Start(ctx context.Context) error

	// ProcessTask executes the complete workflow for one image
	ProcessTask(ctx context.Context, task *queue.ScanTask) error
}

// Config contains configuration for the worker
type Config struct {
	RetryAttempts int
	RetryBackoff  time.Duration
}

// DefaultConfig returns default worker configuration
func DefaultConfig() Config {
	return Config{
		RetryAttempts: 3,
		RetryBackoff:  10 * time.Second,
	}
}

// ImageWorker implements the Worker interface
type ImageWorker struct {
	queue        queue.TaskQueue
	scanner      scanner.Scanner
	policy       policy.PolicyEngine
	attestor     attestation.Attestor
	registry     registry.Client
	stateStore   statestore.StateStore
	config       Config
	logger       *slog.Logger
	wg           sync.WaitGroup
	stopOnce     sync.Once
	regsyncCfg   *regsync.Config
	scaiGenerator *attestation.SCAIGenerator
}

// NewImageWorker creates a new worker instance
func NewImageWorker(
	queue queue.TaskQueue,
	scanner scanner.Scanner,
	policy policy.PolicyEngine,
	attestor attestation.Attestor,
	registry registry.Client,
	stateStore statestore.StateStore,
	config Config,
	logger *slog.Logger,
	regsyncCfg *regsync.Config,
) *ImageWorker {
	if logger == nil {
		logger = slog.Default()
	}

	var scaiGenerator *attestation.SCAIGenerator
	if regsyncCfg != nil {
		scaiGenerator = attestation.NewSCAIGenerator(regsyncCfg, logger)
	}

	return &ImageWorker{
		queue:         queue,
		scanner:       scanner,
		policy:        policy,
		attestor:      attestor,
		registry:      registry,
		stateStore:    stateStore,
		config:        config,
		logger:        logger,
		regsyncCfg:    regsyncCfg,
		scaiGenerator: scaiGenerator,
	}
}

// Start begins processing tasks from the queue
func (w *ImageWorker) Start(ctx context.Context) error {
	w.logger.Info("worker starting")

	// Create a cancellable context for the worker
	workerCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Start the main processing loop
	w.wg.Add(1)
	go func() {
		defer w.wg.Done()
		w.processLoop(workerCtx)
	}()

	// Wait for context cancellation
	<-workerCtx.Done()

	w.logger.Info("worker shutting down, waiting for in-flight tasks to complete")

	// Wait for in-flight tasks to complete with timeout
	done := make(chan struct{})
	go func() {
		w.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		w.logger.Info("worker shutdown complete")
		return nil
	case <-time.After(30 * time.Second):
		w.logger.Warn("worker shutdown timeout, some tasks may not have completed")
		return fmt.Errorf("shutdown timeout")
	}
}

// processLoop is the main task processing loop
func (w *ImageWorker) processLoop(ctx context.Context) {
	w.logger.Info("worker processing loop started")

	for {
		select {
		case <-ctx.Done():
			w.logger.Info("worker processing loop stopping")
			return
		default:
			// Dequeue a task (blocking with context)
			task, err := w.queue.Dequeue(ctx)
			if err != nil {
				if ctx.Err() != nil {
					// Context cancelled, exit gracefully
					w.logger.Info("worker dequeue cancelled", "error", err)
					return
				}
				w.logger.Error("failed to dequeue task", "error", err)
				// Brief sleep to avoid tight loop on persistent errors
				time.Sleep(time.Second)
				continue
			}

			// Process the task
			w.logger.Info("processing task",
				"task_id", task.ID,
				"digest", task.Digest,
				"repository", task.Repository,
				"tag", task.Tag,
				"is_rescan", task.IsRescan)

			if err := w.ProcessTask(ctx, task); err != nil {
				w.logger.Error("task processing failed",
					"task_id", task.ID,
					"digest", task.Digest,
					"repository", task.Repository,
					"error", err)
				_ = w.queue.Fail(ctx, task.ID, err)
			} else {
				w.logger.Info("task processing completed",
					"task_id", task.ID,
					"digest", task.Digest,
					"repository", task.Repository)
				_ = w.queue.Complete(ctx, task.ID)
			}
		}
	}
}

// ProcessTask executes the complete workflow for one image
func (w *ImageWorker) ProcessTask(ctx context.Context, task *queue.ScanTask) error {
	if task == nil {
		return fmt.Errorf("task is nil")
	}

	// Execute the workflow with retry logic
	var lastErr error
	for attempt := 1; attempt <= w.config.RetryAttempts; attempt++ {
		err := w.executeWorkflow(ctx, task)
		if err == nil {
			// Success
			return nil
		}

		lastErr = err

		// Check if error is transient and should be retried
		if !isTransientError(err) {
			w.logger.Error("permanent error, not retrying",
				"task_id", task.ID,
				"digest", task.Digest,
				"error", err)
			return err
		}

		// Don't retry if this was the last attempt
		if attempt >= w.config.RetryAttempts {
			break
		}

		// Calculate backoff delay with exponential backoff
		backoff := w.config.RetryBackoff * time.Duration(attempt)
		w.logger.Warn("transient error, retrying",
			"task_id", task.ID,
			"digest", task.Digest,
			"attempt", attempt,
			"max_attempts", w.config.RetryAttempts,
			"backoff", backoff,
			"error", err)

		// Wait before retrying
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff):
			// Continue to next attempt
		}
	}

	// All retries exhausted
	w.logger.Error("all retry attempts exhausted",
		"task_id", task.ID,
		"digest", task.Digest,
		"attempts", w.config.RetryAttempts,
		"error", lastErr)
	return fmt.Errorf("max retries exceeded: %w", lastErr)
}

// executeWorkflow performs the complete scan workflow for a single image
func (w *ImageWorker) executeWorkflow(ctx context.Context, task *queue.ScanTask) error {
	startTime := time.Now()
	
	// Build image reference
	imageRef := fmt.Sprintf("%s@%s", task.Repository, task.Digest)
	
	w.logger.Info("starting scan workflow",
		"task_id", task.ID,
		"image_ref", imageRef,
		"is_rescan", task.IsRescan)

	// Validate dependencies
	if w.registry == nil {
		return fmt.Errorf("registry client is not configured")
	}
	if w.scanner == nil {
		return fmt.Errorf("scanner is not configured")
	}
	if w.policy == nil {
		return fmt.Errorf("policy engine is not configured")
	}
	if w.attestor == nil {
		return fmt.Errorf("attestor is not configured")
	}
	if w.stateStore == nil {
		return fmt.Errorf("state store is not configured")
	}

	// Step 1: Fetch image metadata from registry
	w.logger.Debug("fetching image metadata", "image_ref", imageRef)
	manifest, err := w.registry.GetManifest(ctx, task.Repository, task.Digest)
	if err != nil {
		return fmt.Errorf("failed to fetch image metadata: %w", err)
	}
	w.logger.Debug("image metadata fetched",
		"digest", manifest.Digest,
		"architecture", manifest.Architecture,
		"os", manifest.OS)

	// Step 2: Generate SBOM using Trivy scanner
	sbomStartTime := time.Now()
	w.logger.Debug("generating SBOM", "image_ref", imageRef, "start_time", sbomStartTime)
	sbom, err := w.scanner.GenerateSBOM(ctx, imageRef)
	if err != nil {
		return fmt.Errorf("failed to generate SBOM: %w", err)
	}
	sbomDuration := time.Since(sbomStartTime)
	w.logger.Info("SBOM generated",
		"image_ref", imageRef,
		"format", sbom.Format,
		"version", sbom.Version,
		"size_bytes", len(sbom.Data),
		"duration", sbomDuration)

	// Step 3: Perform vulnerability scan using Trivy scanner
	vulnScanStartTime := time.Now()
	w.logger.Debug("scanning vulnerabilities", "image_ref", imageRef, "start_time", vulnScanStartTime)
	scanResult, err := w.scanner.ScanVulnerabilities(ctx, imageRef)
	if err != nil {
		return fmt.Errorf("failed to scan vulnerabilities: %w", err)
	}
	vulnScanDuration := time.Since(vulnScanStartTime)
	w.logger.Info("vulnerability scan completed",
		"image_ref", imageRef,
		"total_vulnerabilities", len(scanResult.Vulnerabilities),
		"duration", vulnScanDuration)

	// Step 4: Evaluate policy with CVE tolerations
	// Convert queue.CVEToleration to regsync.CVEToleration
	tolerations := convertTolerationsToRegsync(task.Tolerations)
	
	// Get policy engine for this repository (may be custom per-repo policy)
	policyEngine, err := w.getPolicyEngineForRepository(task.Repository)
	if err != nil {
		return fmt.Errorf("failed to create policy engine: %w", err)
	}
	
	w.logger.Debug("evaluating policy", "image_ref", imageRef, "tolerations", len(tolerations))
	policyDecision, err := policyEngine.Evaluate(ctx, imageRef, scanResult, tolerations)
	if err != nil {
		return fmt.Errorf("failed to evaluate policy: %w", err)
	}
	
	w.logger.Info("policy evaluation completed",
		"image_ref", imageRef,
		"passed", policyDecision.Passed,
		"critical_vulns", policyDecision.CriticalVulnCount,
		"tolerated_vulns", policyDecision.ToleratedVulnCount,
		"reason", policyDecision.Reason)

	// Log expiring tolerations
	for _, expiring := range policyDecision.ExpiringTolerations {
		w.logger.Warn("toleration expiring soon",
			"cve_id", expiring.CVEID,
			"statement", expiring.Statement,
			"expires_at", expiring.ExpiresAt,
			"days_until_expiry", expiring.DaysUntil,
			"image_ref", imageRef)
	}

	// Step 5: Create SBOM attestation (always, regardless of policy)
	sbomAttestStartTime := time.Now()
	w.logger.Debug("creating SBOM attestation", "image_ref", imageRef, "start_time", sbomAttestStartTime)
	if err := w.attestor.AttestSBOM(ctx, imageRef, sbom); err != nil {
		return fmt.Errorf("failed to create SBOM attestation: %w", err)
	}
	sbomAttestDuration := time.Since(sbomAttestStartTime)
	w.logger.Info("SBOM attestation created", "image_ref", imageRef, "duration", sbomAttestDuration)

	// Step 6: Create vulnerability attestation (always, regardless of policy)
	vulnAttestStartTime := time.Now()
	w.logger.Debug("creating vulnerability attestation", "image_ref", imageRef, "start_time", vulnAttestStartTime)
	if err := w.attestor.AttestVulnerabilities(ctx, imageRef, scanResult); err != nil {
		return fmt.Errorf("failed to create vulnerability attestation: %w", err)
	}
	vulnAttestDuration := time.Since(vulnAttestStartTime)
	w.logger.Info("vulnerability attestation created", "image_ref", imageRef, "duration", vulnAttestDuration)

	// Step 6.5: Create SCAI attestation (always, regardless of policy)
	scaiAttested := false
	var scaiAttestDuration time.Duration
	if w.scaiGenerator != nil {
		scaiAttestStartTime := time.Now()
		w.logger.Debug("generating SCAI attestation", "image_ref", imageRef, "start_time", scaiAttestStartTime)
		
		scai, err := w.scaiGenerator.GenerateSCAI(ctx, imageRef, scanResult, task.Repository)
		if err != nil {
			// Log error but don't fail the pipeline
			w.logger.Error("failed to generate SCAI attestation", "image_ref", imageRef, "error", err)
		} else {
			w.logger.Debug("SCAI attestation generated", "image_ref", imageRef)
			
			if err := w.attestor.AttestSCAI(ctx, imageRef, scai); err != nil {
				// Log error but don't fail the pipeline
				w.logger.Error("failed to attest SCAI", "image_ref", imageRef, "error", err)
			} else {
				scaiAttested = true
				scaiAttestDuration = time.Since(scaiAttestStartTime)
				w.logger.Info("SCAI attestation created", "image_ref", imageRef, "duration", scaiAttestDuration)
			}
		}
	} else {
		w.logger.Debug("SCAI generator not configured, skipping SCAI attestation", "image_ref", imageRef)
	}

	// Step 7: Sign image if policy passes
	signed := false
	if policyDecision.ShouldSign {
		w.logger.Debug("signing image", "image_ref", imageRef)
		if err := w.attestor.SignImage(ctx, imageRef); err != nil {
			return fmt.Errorf("failed to sign image: %w", err)
		}
		w.logger.Info("image signed", "image_ref", imageRef)
		signed = true
	} else {
		w.logger.Info("image not signed due to policy failure",
			"image_ref", imageRef,
			"reason", policyDecision.Reason)
	}

	// Step 8: Record scan results to state store
	scanRecord := buildScanRecord(task, scanResult, policyDecision, signed, startTime)
	
	w.logger.Debug("recording scan results", "image_ref", imageRef)
	if err := w.stateStore.RecordScan(ctx, scanRecord); err != nil {
		// Log error but don't fail the task - attestations and signatures are already created
		w.logger.Error("failed to record scan results to state store",
			"image_ref", imageRef,
			"error", err)
		// Continue - this is not a critical failure
	} else {
		w.logger.Info("scan results recorded", "image_ref", imageRef)
	}

	// Log policy failure details
	if !policyDecision.Passed {
		w.logger.Warn("image failed policy evaluation",
			"digest", task.Digest,
			"repository", task.Repository,
			"tag", task.Tag,
			"critical_vulns", policyDecision.CriticalVulnCount,
			"tolerated_vulns", policyDecision.ToleratedVulnCount,
			"reason", policyDecision.Reason)
	}

	// Log alert if this is a rescan and a previously signed image now fails
	if task.IsRescan && !policyDecision.Passed {
		// Check if image was previously signed
		lastScan, err := w.stateStore.GetLastScan(ctx, task.Digest)
		if err == nil && lastScan != nil && lastScan.Signed {
			w.logger.Error("ALERT: previously signed image now fails policy",
				"digest", task.Digest,
				"repository", task.Repository,
				"tag", task.Tag,
				"previous_scan", lastScan.ScannedAt,
				"critical_vulns", policyDecision.CriticalVulnCount,
				"reason", policyDecision.Reason)
		}
	}

	duration := time.Since(startTime)
	w.logger.Info("scan workflow completed",
		"task_id", task.ID,
		"image_ref", imageRef,
		"total_duration", duration,
		"sbom_generation_duration", sbomDuration,
		"vulnerability_scan_duration", vulnScanDuration,
		"sbom_attestation_duration", sbomAttestDuration,
		"vulnerability_attestation_duration", vulnAttestDuration,
		"scai_attestation_duration", scaiAttestDuration,
		"scai_attested", scaiAttested,
		"policy_passed", policyDecision.Passed,
		"signed", signed)

	return nil
}

// buildScanRecord constructs a ScanRecord from the workflow results
func buildScanRecord(
	task *queue.ScanTask,
	scanResult *scanner.ScanResult,
	policyDecision *policy.PolicyDecision,
	signed bool,
	scannedAt time.Time,
) *statestore.ScanRecord {
	// Count vulnerabilities by severity
	var criticalCount, highCount, mediumCount, lowCount int
	vulnerabilities := make([]statestore.VulnerabilityRecord, 0, len(scanResult.Vulnerabilities))
	
	for _, vuln := range scanResult.Vulnerabilities {
		// Count by severity
		switch vuln.Severity {
		case "CRITICAL":
			criticalCount++
		case "HIGH":
			highCount++
		case "MEDIUM":
			mediumCount++
		case "LOW":
			lowCount++
		}
		
		// Convert to VulnerabilityRecord
		vulnerabilities = append(vulnerabilities, statestore.VulnerabilityRecord{
			CVEID:            vuln.ID,
			Severity:         vuln.Severity,
			PackageName:      vuln.PackageName,
			InstalledVersion: vuln.Version,
			FixedVersion:     vuln.FixedVersion,
			Title:            vuln.Title,
			Description:      vuln.Description,
			PrimaryURL:       vuln.PrimaryURL,
		})
	}

	// Build tolerated CVEs list
	toleratedCVEs := make([]statestore.ToleratedCVE, 0, len(task.Tolerations))
	for _, toleration := range task.Tolerations {
		// Only include tolerations that were actually applied (in the tolerated CVEs list)
		isTolerated := false
		for _, toleratedID := range policyDecision.ToleratedCVEs {
			if toleratedID == toleration.ID {
				isTolerated = true
				break
			}
		}
		
		if isTolerated {
			toleratedCVEs = append(toleratedCVEs, statestore.ToleratedCVE{
				CVEID:       toleration.ID,
				Statement:   toleration.Statement,
				ToleratedAt: scannedAt,
				ExpiresAt:   toleration.ExpiresAt,
			})
		}
	}

	return &statestore.ScanRecord{
		Digest:            task.Digest,
		Repository:        task.Repository,
		Tag:               task.Tag,
		ScannedAt:         scannedAt,
		CriticalVulnCount: criticalCount,
		HighVulnCount:     highCount,
		MediumVulnCount:   mediumCount,
		LowVulnCount:      lowCount,
		PolicyPassed:      policyDecision.Passed,
		Signed:            signed,
		SBOMAttested:      true, // Always true if we reach this point
		VulnAttested:      true, // Always true if we reach this point
		Vulnerabilities:   vulnerabilities,
		ToleratedCVEs:     toleratedCVEs,
		ErrorMessage:      "",
	}
}

// isTransientError determines if an error is transient and should be retried
func isTransientError(err error) bool {
	if err == nil {
		return false
	}

	errStr := err.Error()
	
	// Network-related errors
	transientPatterns := []string{
		"timeout",
		"connection refused",
		"connection reset",
		"temporary failure",
		"too many requests",
		"rate limit",
		"service unavailable",
		"gateway timeout",
		"bad gateway",
		"dial tcp",
		"i/o timeout",
		"EOF",
		"broken pipe",
	}

	for _, pattern := range transientPatterns {
		if strings.Contains(strings.ToLower(errStr), pattern) {
			return true
		}
	}

	// Permanent errors
	permanentPatterns := []string{
		"not found",
		"unauthorized",
		"forbidden",
		"authentication",
		"invalid",
		"malformed",
		"permission denied",
		"not configured",
		"is nil",
	}

	for _, pattern := range permanentPatterns {
		if strings.Contains(strings.ToLower(errStr), pattern) {
			return false
		}
	}

	// Default to transient for unknown errors (safer to retry)
	return true
}

// convertTolerationsToRegsync converts queue.CVEToleration to regsync.CVEToleration
func convertTolerationsToRegsync(queueTolerations []queue.CVEToleration) []regsync.CVEToleration {
	tolerations := make([]regsync.CVEToleration, len(queueTolerations))
	for i, qt := range queueTolerations {
		tolerations[i] = regsync.CVEToleration{
			ID:        qt.ID,
			Statement: qt.Statement,
			ExpiresAt: qt.ExpiresAt,
		}
	}
	return tolerations
}

// getPolicyEngineForRepository returns a policy engine for the given repository
// Uses repository-specific policy from regsync config if available, otherwise uses default
func (w *ImageWorker) getPolicyEngineForRepository(repository string) (policy.PolicyEngine, error) {
	var policyConfig policy.PolicyConfig
	
	// Try to get policy from regsync config
	if w.regsyncCfg != nil {
		if regsyncPolicy := w.regsyncCfg.GetPolicyForTarget(repository); regsyncPolicy != nil {
			policyConfig = policy.PolicyConfig{
				Expression:     regsyncPolicy.Expression,
				FailureMessage: regsyncPolicy.FailureMessage,
			}
			w.logger.Debug("using repository-specific policy",
				"repository", repository,
				"expression", policyConfig.Expression)
		}
	}
	
	// If no policy configured, use default from worker
	if policyConfig.Expression == "" {
		// Use the default policy engine that was passed to the worker
		return w.policy, nil
	}
	
	// Create a new policy engine with the repository-specific config
	return policy.NewEngine(w.logger, policyConfig)
}
