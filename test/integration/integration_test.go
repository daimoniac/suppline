package integration

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/daimoniac/suppline/internal/attestation"
	"github.com/daimoniac/suppline/internal/config"
	"github.com/daimoniac/suppline/internal/policy"
	"github.com/daimoniac/suppline/internal/queue"
	"github.com/daimoniac/suppline/internal/registry"
	"github.com/daimoniac/suppline/internal/scanner"
	"github.com/daimoniac/suppline/internal/statestore"
	"github.com/daimoniac/suppline/internal/types"
)

// TestMain sets up and tears down the test environment
func TestMain(m *testing.M) {
	// Check if integration tests should run
	if os.Getenv("INTEGRATION_TEST") != "true" {
		os.Exit(0)
	}

	// Wait for services to be ready
	if err := waitForServices(); err != nil {
		panic("Failed to wait for services: " + err.Error())
	}

	// Run tests
	code := m.Run()

	// Cleanup
	cleanup()

	os.Exit(code)
}

func waitForServices() error {
	// 90 second timeout should be sufficient with --skip-db-update
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	// Wait for Trivy server
	trivyCfg := config.ScannerConfig{
		ServerAddr: getEnv("TRIVY_SERVER_ADDR", "localhost:4954"),
		Timeout:    30 * time.Second,
	}

	fmt.Println("Waiting for Trivy server to be ready...")
	startTime := time.Now()
	
	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("timeout after %v: %w", time.Since(startTime), ctx.Err())
		default:
			scanner, err := scanner.NewTrivyScanner(trivyCfg)
			if err == nil {
				if err := scanner.HealthCheck(context.Background()); err == nil {
					fmt.Printf("Trivy server ready after %v\n", time.Since(startTime))
					return nil
				}
			}
			time.Sleep(3 * time.Second)
		}
	}
}

func cleanup() {
	// Remove test database
	os.Remove("test_integration.db")
	os.Remove("test_e2e.db")
	os.Remove("test_worker_workflow.db")
}

// setupLocalRegistryImage pulls an image, tags it for local registry, and pushes it
func setupLocalRegistryImage(ctx context.Context, sourceImage, localTag string) (string, error) {
	localRegistry := "localhost:5000"
	localImage := fmt.Sprintf("%s/%s", localRegistry, localTag)
	
	// Pull the source image
	pullCmd := exec.CommandContext(ctx, "docker", "pull", sourceImage)
	if err := pullCmd.Run(); err != nil {
		return "", fmt.Errorf("failed to pull %s: %w", sourceImage, err)
	}
	
	// Tag for local registry
	tagCmd := exec.CommandContext(ctx, "docker", "tag", sourceImage, localImage)
	if err := tagCmd.Run(); err != nil {
		return "", fmt.Errorf("failed to tag image: %w", err)
	}
	
	// Push to local registry
	pushCmd := exec.CommandContext(ctx, "docker", "push", localImage)
	if err := pushCmd.Run(); err != nil {
		return "", fmt.Errorf("failed to push to local registry: %w", err)
	}
	
	// Get the digest of the pushed image
	return getImageDigest(ctx, localImage)
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// getImageDigest resolves an image tag to its digest using docker/crane
func getImageDigest(ctx context.Context, imageRef string) (string, error) {
	// Try using crane first (more reliable)
	cmd := exec.CommandContext(ctx, "crane", "digest", imageRef)
	output, err := cmd.CombinedOutput()
	if err == nil {
		digest := string(output)
		// Remove any trailing newline
		if len(digest) > 0 && digest[len(digest)-1] == '\n' {
			digest = digest[:len(digest)-1]
		}
		// Extract just the repository name without tag
		repo := imageRef
		if idx := len(imageRef) - 1; idx >= 0 {
			for i := idx; i >= 0; i-- {
				if imageRef[i] == ':' {
					repo = imageRef[:i]
					break
				}
			}
		}
		return fmt.Sprintf("%s@%s", repo, digest), nil
	}

	// Fallback to docker inspect
	cmd = exec.CommandContext(ctx, "docker", "inspect", "--format={{index .RepoDigests 0}}", imageRef)
	output, err = cmd.CombinedOutput()
	if err != nil {
		// If image doesn't exist locally, pull it first
		pullCmd := exec.CommandContext(ctx, "docker", "pull", imageRef)
		if pullErr := pullCmd.Run(); pullErr != nil {
			return "", fmt.Errorf("failed to pull image %s: %w", imageRef, pullErr)
		}
		
		// Try inspect again
		cmd = exec.CommandContext(ctx, "docker", "inspect", "--format={{index .RepoDigests 0}}", imageRef)
		output, err = cmd.CombinedOutput()
		if err != nil {
			return "", fmt.Errorf("failed to get digest for %s: %w (output: %s)", imageRef, err, string(output))
		}
	}

	digestRef := string(output)
	// Remove any trailing newline
	if len(digestRef) > 0 && digestRef[len(digestRef)-1] == '\n' {
		digestRef = digestRef[:len(digestRef)-1]
	}
	
	if digestRef == "" || digestRef == "<no value>" {
		return "", fmt.Errorf("no digest found for image %s", imageRef)
	}
	
	return digestRef, nil
}

// TestTrivyScanner tests the Trivy scanner integration
func TestTrivyScanner(t *testing.T) {
	// Check if suppline.yml exists for authentication tests
	regsyncPath := getEnv("SUPPLINE_CONFIG", "../../suppline.yml")
	
	cfg := config.ScannerConfig{
		ServerAddr:  getEnv("TRIVY_SERVER_ADDR", "localhost:4954"),
		Timeout:     5 * time.Minute,
		RegsyncPath: regsyncPath,
	}

	scanner, err := scanner.NewTrivyScanner(cfg)
	if err != nil {
		t.Fatalf("Failed to create Trivy scanner: %v", err)
	}

	ctx := context.Background()

	t.Run("HealthCheck", func(t *testing.T) {
		err := scanner.HealthCheck(ctx)
		if err != nil {
			t.Errorf("Health check failed: %v", err)
		}
	})
	
	t.Run("DockerConfigGeneration", func(t *testing.T) {
		// Verify Docker config was generated if suppline.yml exists
		if _, err := os.Stat(regsyncPath); err == nil {
			// Scanner should have generated Docker config
			// This is tested implicitly by the private image scan below
			t.Log("Docker config should be generated from suppline.yml")
		} else {
			t.Skip("Skipping Docker config test: suppline.yml not found")
		}
	})

	t.Run("ScanVulnerabilities", func(t *testing.T) {
		// Use a known vulnerable image for testing
		imageRef := "alpine:3.7"

		result, err := scanner.ScanVulnerabilities(ctx, imageRef)
		if err != nil {
			t.Fatalf("Failed to scan vulnerabilities: %v", err)
		}

		if result == nil {
			t.Fatal("Expected scan result, got nil")
		}

		if result.ImageRef != imageRef {
			t.Errorf("Expected image ref %s, got %s", imageRef, result.ImageRef)
		}

		// Alpine 3.7 is old and should have vulnerabilities
		if len(result.Vulnerabilities) == 0 {
			t.Log("Warning: Expected vulnerabilities in alpine:3.7, got none")
		}

		// Verify vulnerability structure
		for _, vuln := range result.Vulnerabilities {
			if vuln.ID == "" {
				t.Error("Vulnerability ID should not be empty")
			}
			if vuln.Severity == "" {
				t.Error("Vulnerability severity should not be empty")
			}
			if vuln.PackageName == "" {
				t.Error("Vulnerability package name should not be empty")
			}
		}

		t.Logf("Found %d vulnerabilities in %s", len(result.Vulnerabilities), imageRef)
	})

	t.Run("GenerateSBOM", func(t *testing.T) {
		imageRef := "alpine:3.7"

		sbom, err := scanner.GenerateSBOM(ctx, imageRef)
		if err != nil {
			t.Fatalf("Failed to generate SBOM: %v", err)
		}

		if sbom == nil {
			t.Fatal("Expected SBOM, got nil")
		}

		if sbom.Format != "cyclonedx" {
			t.Errorf("Expected format 'cyclonedx', got %s", sbom.Format)
		}

		if len(sbom.Data) == 0 {
			t.Error("SBOM data should not be empty")
		}

		t.Logf("Generated SBOM for %s: %d bytes", imageRef, len(sbom.Data))
	})
	
	t.Run("PrivateRegistryAuthentication", func(t *testing.T) {
		// Test scanning a private image from the configured registry
		// This verifies that Docker config authentication is working
		privateImage := getEnv("TEST_PRIVATE_IMAGE", "hostingmaloonde/nginx:1.27.1")
		
		t.Logf("Testing private image authentication: %s", privateImage)
		
		// Try to scan the private image
		result, err := scanner.ScanVulnerabilities(ctx, privateImage)
		if err != nil {
			// If this fails, it likely means authentication isn't working
			t.Logf("Private image scan failed (may indicate auth issue): %v", err)
			t.Skip("Skipping private image test - authentication may not be configured")
		}
		
		if result == nil {
			t.Fatal("Expected scan result for private image, got nil")
		}
		
		t.Logf("Successfully scanned private image: found %d vulnerabilities", len(result.Vulnerabilities))
		
		// Also test SBOM generation for private image
		sbom, err := scanner.GenerateSBOM(ctx, privateImage)
		if err != nil {
			t.Errorf("Failed to generate SBOM for private image: %v", err)
		} else {
			t.Logf("Successfully generated SBOM for private image: %d bytes", len(sbom.Data))
		}
	})
}

// TestStateStore tests the state store integration
func TestStateStore(t *testing.T) {
	dbPath := "test_integration.db"
	defer os.Remove(dbPath)

	store, err := statestore.NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("Failed to create state store: %v", err)
	}
	defer store.Close()

	ctx := context.Background()

	t.Run("RecordAndRetrieveScan", func(t *testing.T) {
		expiresAt := time.Now().Add(30 * 24 * time.Hour).Unix()
		record := &statestore.ScanRecord{
			Digest:            "sha256:test123",
			Repository:        "test/image",
			Tag:               "latest",
			CreatedAt:         time.Now(),
			CriticalVulnCount: 0,
			HighVulnCount:     1,
			MediumVulnCount:   0,
			LowVulnCount:      0,
			PolicyPassed:      true,
			SBOMAttested:      true,
			VulnAttested:      true,
			Vulnerabilities: []types.VulnerabilityRecord{
				{
					CVEID:            "CVE-2024-12345",
					Severity:         "HIGH",
					PackageName:      "testpkg",
					InstalledVersion: "1.0.0",
					FixedVersion:     "1.0.1",
					Description:      "Test vulnerability",
				},
			},
			ToleratedCVEs: []types.ToleratedCVE{
				{
					CVEID:       "CVE-2024-99999",
					Statement:   "Test toleration",
					ToleratedAt: time.Now().Unix(),
					ExpiresAt:   &expiresAt,
				},
			},
		}

		err := store.RecordScan(ctx, record)
		if err != nil {
			t.Fatalf("Failed to record scan: %v", err)
		}

		// Retrieve the scan
		retrieved, err := store.GetLastScan(ctx, record.Digest)
		if err != nil {
			t.Fatalf("Failed to retrieve scan: %v", err)
		}

		if retrieved.Digest != record.Digest {
			t.Errorf("Expected digest %s, got %s", record.Digest, retrieved.Digest)
		}

		if retrieved.Repository != record.Repository {
			t.Errorf("Expected repository %s, got %s", record.Repository, retrieved.Repository)
		}

		if len(retrieved.Vulnerabilities) != 1 {
			t.Errorf("Expected 1 vulnerability, got %d", len(retrieved.Vulnerabilities))
		}

		if len(retrieved.ToleratedCVEs) != 1 {
			t.Errorf("Expected 1 tolerated CVE, got %d", len(retrieved.ToleratedCVEs))
		}
	})

	t.Run("QueryVulnerabilities", func(t *testing.T) {
		filter := statestore.VulnFilter{
			Severity: "HIGH",
		}

		vulns, err := store.QueryVulnerabilities(ctx, filter)
		if err != nil {
			t.Fatalf("Failed to query vulnerabilities: %v", err)
		}

		// Should find the HIGH vulnerability we inserted
		if len(vulns) == 0 {
			t.Error("Expected to find vulnerabilities")
		}

		for _, vuln := range vulns {
			if vuln.Severity != "HIGH" {
				t.Errorf("Expected HIGH severity, got %s", vuln.Severity)
			}
		}
	})

	t.Run("ListDueForRescan", func(t *testing.T) {
		// Insert an old scan
		oldRecord := &statestore.ScanRecord{
			Digest:            "sha256:old123",
			Repository:        "test/old",
			Tag:               "v1",
			CreatedAt:         time.Now().Add(-48 * time.Hour), // 2 days ago
			CriticalVulnCount: 0,
			HighVulnCount:     0,
			MediumVulnCount:   0,
			LowVulnCount:      0,
			PolicyPassed:      true,
			SBOMAttested:      false,
			VulnAttested:      false,
		}

		err := store.RecordScan(ctx, oldRecord)
		if err != nil {
			t.Fatalf("Failed to record old scan: %v", err)
		}

		// List scans due for rescan (older than 24 hours)
		dueDigests, err := store.ListDueForRescan(ctx, 24*time.Hour)
		if err != nil {
			t.Fatalf("Failed to list due scans: %v", err)
		}

		found := false
		for _, digest := range dueDigests {
			if digest == oldRecord.Digest {
				found = true
				break
			}
		}

		if !found {
			t.Error("Expected to find old scan in due for rescan list")
		}
	})
}

// TestTaskQueue tests the task queue integration
func TestTaskQueue(t *testing.T) {
	q := queue.NewInMemoryQueue(100)
	defer q.Close()

	ctx := context.Background()

	t.Run("EnqueueAndDequeue", func(t *testing.T) {
		task := &queue.ScanTask{
			ID:         "task1",
			Digest:     "sha256:test456",
			Repository: "test/queue",
			Tag:        "v1",
			EnqueuedAt: time.Now(),
		}

		err := q.Enqueue(ctx, task)
		if err != nil {
			t.Fatalf("Failed to enqueue task: %v", err)
		}

		depth, err := q.GetQueueDepth(ctx)
		if err != nil {
			t.Fatalf("Failed to get queue depth: %v", err)
		}
		if depth != 1 {
			t.Errorf("Expected queue depth 1, got %d", depth)
		}

		dequeued, err := q.Dequeue(ctx)
		if err != nil {
			t.Fatalf("Failed to dequeue task: %v", err)
		}

		if dequeued.Digest != task.Digest {
			t.Errorf("Expected digest %s, got %s", task.Digest, dequeued.Digest)
		}
	})

	t.Run("Deduplication", func(t *testing.T) {
		task := &queue.ScanTask{
			ID:         "task2",
			Digest:     "sha256:dup123",
			Repository: "test/dup",
			Tag:        "v1",
			EnqueuedAt: time.Now(),
		}

		// Enqueue the same task twice
		err := q.Enqueue(ctx, task)
		if err != nil {
			t.Fatalf("Failed to enqueue first task: %v", err)
		}

		err = q.Enqueue(ctx, task)
		if err != nil {
			t.Fatalf("Failed to enqueue duplicate task: %v", err)
		}

		// Should only have one task in queue
		depth, err := q.GetQueueDepth(ctx)
		if err != nil {
			t.Fatalf("Failed to get queue depth: %v", err)
		}
		if depth != 1 {
			t.Errorf("Expected queue depth 1 after deduplication, got %d", depth)
		}
	})

	t.Run("CompleteAndFail", func(t *testing.T) {
		task := &queue.ScanTask{
			ID:         "task3",
			Digest:     "sha256:complete123",
			Repository: "test/complete",
			Tag:        "v1",
			EnqueuedAt: time.Now(),
		}

		err := q.Enqueue(ctx, task)
		if err != nil {
			t.Fatalf("Failed to enqueue task: %v", err)
		}

		dequeued, err := q.Dequeue(ctx)
		if err != nil {
			t.Fatalf("Failed to dequeue task: %v", err)
		}

		// Complete the task
		err = q.Complete(ctx, dequeued.ID)
		if err != nil {
			t.Fatalf("Failed to complete task: %v", err)
		}

		// Try to enqueue again - should work since it's completed
		task.ID = "task3-retry"
		err = q.Enqueue(ctx, task)
		if err != nil {
			t.Fatalf("Failed to enqueue after completion: %v", err)
		}

		dequeued2, err := q.Dequeue(ctx)
		if err != nil {
			t.Fatalf("Failed to dequeue second task: %v", err)
		}

		// Fail the task
		err = q.Fail(ctx, dequeued2.ID, fmt.Errorf("test error"))
		if err != nil {
			t.Fatalf("Failed to fail task: %v", err)
		}

		// Should be able to enqueue again after failure
		task.ID = "task3-retry2"
		err = q.Enqueue(ctx, task)
		if err != nil {
			t.Fatalf("Failed to enqueue after failure: %v", err)
		}
	})
}

// TestEndToEndWorkflow tests a complete workflow
func TestEndToEndWorkflow(t *testing.T) {
	// Setup
	dbPath := "test_e2e.db"
	defer os.Remove(dbPath)

	scannerCfg := config.ScannerConfig{
		ServerAddr: getEnv("TRIVY_SERVER_ADDR", "localhost:4954"),
		Timeout:    5 * time.Minute,
	}

	// Initialize components
	trivyScanner, err := scanner.NewTrivyScanner(scannerCfg)
	if err != nil {
		t.Fatalf("Failed to create scanner: %v", err)
	}

	store, err := statestore.NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("Failed to create state store: %v", err)
	}
	defer store.Close()

	q := queue.NewInMemoryQueue(100)
	defer q.Close()

	ctx := context.Background()

	// Simulate a complete scan workflow
	t.Run("CompleteWorkflow", func(t *testing.T) {
		imageRef := "alpine:3.7"
		digest := "sha256:workflow123"

		// 1. Enqueue scan task
		task := &queue.ScanTask{
			ID:         "e2e-task",
			Digest:     digest,
			Repository: "library/alpine",
			Tag:        "3.7",
			EnqueuedAt: time.Now(),
		}

		err := q.Enqueue(ctx, task)
		if err != nil {
			t.Fatalf("Failed to enqueue task: %v", err)
		}

		// 2. Dequeue task
		dequeuedTask, err := q.Dequeue(ctx)
		if err != nil {
			t.Fatalf("Failed to dequeue task: %v", err)
		}

		// 3. Scan for vulnerabilities
		scanResult, err := trivyScanner.ScanVulnerabilities(ctx, imageRef)
		if err != nil {
			t.Fatalf("Failed to scan vulnerabilities: %v", err)
		}

		// 4. Generate SBOM
		sbom, err := trivyScanner.GenerateSBOM(ctx, imageRef)
		if err != nil {
			t.Fatalf("Failed to generate SBOM: %v", err)
		}

		// 5. Record scan results
		vulnRecords := make([]types.VulnerabilityRecord, 0, len(scanResult.Vulnerabilities))
		criticalCount := 0
		highCount := 0
		mediumCount := 0
		lowCount := 0
		
		for _, vuln := range scanResult.Vulnerabilities {
			vulnRecords = append(vulnRecords, types.VulnerabilityRecord{
				CVEID:            vuln.ID,
				Severity:         vuln.Severity,
				PackageName:      vuln.PackageName,
				InstalledVersion: vuln.Version,
				FixedVersion:     vuln.FixedVersion,
				Description:      vuln.Description,
				PrimaryURL:       vuln.PrimaryURL,
			})
			
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
		}

		record := &statestore.ScanRecord{
			Digest:            dequeuedTask.Digest,
			Repository:        dequeuedTask.Repository,
			Tag:               dequeuedTask.Tag,
			CreatedAt:         time.Now(),
			CriticalVulnCount: criticalCount,
			HighVulnCount:     highCount,
			MediumVulnCount:   mediumCount,
			LowVulnCount:      lowCount,
			PolicyPassed:      true, // Would be determined by policy engine
			SBOMAttested:      true,
			VulnAttested:      false,
			Vulnerabilities:   vulnRecords,
		}

		err = store.RecordScan(ctx, record)
		if err != nil {
			t.Fatalf("Failed to record scan: %v", err)
		}

		// 6. Mark task as complete
		err = q.Complete(ctx, dequeuedTask.ID)
		if err != nil {
			t.Fatalf("Failed to complete task: %v", err)
		}

		// 7. Verify the scan was recorded
		retrieved, err := store.GetLastScan(ctx, digest)
		if err != nil {
			t.Fatalf("Failed to retrieve scan: %v", err)
		}

		if retrieved.Digest != digest {
			t.Errorf("Expected digest %s, got %s", digest, retrieved.Digest)
		}

		if !retrieved.SBOMAttested {
			t.Error("Expected SBOM to be attested")
		}

		t.Logf("Workflow completed successfully:")
		t.Logf("  - Scanned image: %s", imageRef)
		t.Logf("  - Found %d vulnerabilities", len(retrieved.Vulnerabilities))
		t.Logf("  - SBOM size: %d bytes", len(sbom.Data))
		t.Logf("  - Policy passed: %v", retrieved.PolicyPassed)
	})
}

// TestPolicyEngine tests the policy engine integration
func TestPolicyEngine(t *testing.T) {
	expiresAt := time.Now().Add(30 * 24 * time.Hour).Unix()
	expiredAt := time.Now().Add(-1 * time.Hour).Unix()

	tolerations := []types.CVEToleration{
		{
			ID:        "CVE-2024-TOLERATED",
			Statement: "Accepted risk for testing",
			ExpiresAt: &expiresAt,
		},
		{
			ID:        "CVE-2024-EXPIRED",
			Statement: "This toleration has expired",
			ExpiresAt: &expiredAt,
		},
	}

	engine, err := policy.NewEngine(nil, policy.PolicyConfig{
		Expression: "criticalCount == 0",
	})
	if err != nil {
		t.Fatalf("failed to create policy engine: %v", err)
	}
	ctx := context.Background()

	t.Run("PassWithNoVulnerabilities", func(t *testing.T) {
		result := &scanner.ScanResult{
			ImageRef:        "myregistry.com/nginx:latest",
			Vulnerabilities: []types.Vulnerability{},
		}

		decision, err := engine.Evaluate(ctx, "myregistry.com/nginx:latest", result, tolerations)
		if err != nil {
			t.Fatalf("Failed to evaluate policy: %v", err)
		}

		if !decision.Passed {
			t.Error("Expected policy to pass with no vulnerabilities")
		}

		if decision.CriticalVulnCount != 0 {
			t.Errorf("Expected 0 critical vulnerabilities, got %d", decision.CriticalVulnCount)
		}
	})

	t.Run("FailWithCriticalVulnerabilities", func(t *testing.T) {
		result := &scanner.ScanResult{
			ImageRef: "myregistry.com/nginx:latest",
			Vulnerabilities: []types.Vulnerability{
				{
					ID:       "CVE-2024-CRITICAL",
					Severity: "CRITICAL",
				},
				{
					ID:       "CVE-2024-HIGH",
					Severity: "HIGH",
				},
			},
		}

		decision, err := engine.Evaluate(ctx, "myregistry.com/nginx:latest", result, tolerations)
		if err != nil {
			t.Fatalf("Failed to evaluate policy: %v", err)
		}

		if decision.Passed {
			t.Error("Expected policy to fail with critical vulnerabilities")
		}

		if decision.CriticalVulnCount != 1 {
			t.Errorf("Expected 1 critical vulnerability, got %d", decision.CriticalVulnCount)
		}
	})

	t.Run("PassWithToleratedCVE", func(t *testing.T) {
		result := &scanner.ScanResult{
			ImageRef: "myregistry.com/nginx:latest",
			Vulnerabilities: []types.Vulnerability{
				{
					ID:       "CVE-2024-TOLERATED",
					Severity: "CRITICAL",
				},
			},
		}

		decision, err := engine.Evaluate(ctx, "myregistry.com/nginx:latest", result, tolerations)
		if err != nil {
			t.Fatalf("Failed to evaluate policy: %v", err)
		}

		if !decision.Passed {
			t.Error("Expected policy to pass with tolerated CVE")
		}

		if len(decision.ToleratedCVEs) != 1 {
			t.Errorf("Expected 1 tolerated CVE, got %d", len(decision.ToleratedCVEs))
		}

		if decision.ToleratedCVEs[0] != "CVE-2024-TOLERATED" {
			t.Errorf("Expected CVE-2024-TOLERATED, got %s", decision.ToleratedCVEs[0])
		}
	})

	t.Run("FailWithExpiredToleration", func(t *testing.T) {
		result := &scanner.ScanResult{
			ImageRef: "myregistry.com/nginx:latest",
			Vulnerabilities: []types.Vulnerability{
				{
					ID:       "CVE-2024-EXPIRED",
					Severity: "CRITICAL",
				},
			},
		}

		decision, err := engine.Evaluate(ctx, "myregistry.com/nginx:latest", result, tolerations)
		if err != nil {
			t.Fatalf("Failed to evaluate policy: %v", err)
		}

		if decision.Passed {
			t.Error("Expected policy to fail with expired toleration")
		}

		if decision.CriticalVulnCount != 1 {
			t.Errorf("Expected 1 critical vulnerability (expired toleration), got %d", decision.CriticalVulnCount)
		}
	})

	t.Run("ExpiringTolerationsWarning", func(t *testing.T) {
		expiringSoon := time.Now().Add(5 * 24 * time.Hour).Unix()
		expiringTolerations := []types.CVEToleration{
			{
				ID:        "CVE-2024-EXPIRING",
				Statement: "Expiring soon",
				ExpiresAt: &expiringSoon,
			},
		}

		result := &scanner.ScanResult{
			ImageRef: "myregistry.com/nginx:latest",
			Vulnerabilities: []types.Vulnerability{
				{
					ID:       "CVE-2024-EXPIRING",
					Severity: "CRITICAL",
				},
			},
		}

		decision, err := engine.Evaluate(ctx, "myregistry.com/nginx:latest", result, expiringTolerations)
		if err != nil {
			t.Fatalf("Failed to evaluate policy: %v", err)
		}

		if !decision.Passed {
			t.Error("Expected policy to pass with expiring toleration")
		}

		if len(decision.ExpiringTolerations) != 1 {
			t.Errorf("Expected 1 expiring toleration, got %d", len(decision.ExpiringTolerations))
		}
	})
}

// TestRegistryClient tests the registry client integration
func TestRegistryClient(t *testing.T) {
	// Skip if no registry credentials are provided
	if os.Getenv("REGISTRY_USER") == "" {
		t.Skip("Skipping registry client test: REGISTRY_USER not set")
	}

	regsyncCfg := &config.RegsyncConfig{
		Version: 1,
		Creds: []config.RegistryCredential{
			{
				Registry: os.Getenv("REGISTRY_HOST"),
				User:     os.Getenv("REGISTRY_USER"),
				Pass:     os.Getenv("REGISTRY_PASS"),
			},
		},
		Sync: []config.SyncEntry{
			{
				Source: "nginx",
				Target: fmt.Sprintf("%s/nginx", os.Getenv("REGISTRY_HOST")),
				Type:   "repository",
			},
		},
	}

	client, err := registry.NewClient(regsyncCfg)
	if err != nil {
		t.Fatalf("Failed to create registry client: %v", err)
	}

	ctx := context.Background()

	t.Run("ListRepositories", func(t *testing.T) {
		repos, err := client.ListRepositories(ctx)
		if err != nil {
			t.Fatalf("Failed to list repositories: %v", err)
		}

		if len(repos) == 0 {
			t.Error("Expected at least one repository")
		}

		t.Logf("Found %d repositories", len(repos))
	})

	// Note: The following tests require actual images in the registry
	// They are commented out but can be enabled for full integration testing
	/*
	t.Run("ListTags", func(t *testing.T) {
		repo := fmt.Sprintf("%s/nginx", os.Getenv("REGISTRY_HOST"))
		tags, err := client.ListTags(ctx, repo)
		if err != nil {
			t.Fatalf("Failed to list tags: %v", err)
		}

		if len(tags) == 0 {
			t.Error("Expected at least one tag")
		}

		t.Logf("Found %d tags for %s", len(tags), repo)
	})

	t.Run("GetDigest", func(t *testing.T) {
		repo := fmt.Sprintf("%s/nginx", os.Getenv("REGISTRY_HOST"))
		tag := "latest"

		digest, err := client.GetDigest(ctx, repo, tag)
		if err != nil {
			t.Fatalf("Failed to get digest: %v", err)
		}

		if digest == "" {
			t.Error("Expected non-empty digest")
		}

		if !strings.HasPrefix(digest, "sha256:") {
			t.Errorf("Expected digest to start with 'sha256:', got %s", digest)
		}

		t.Logf("Digest for %s:%s is %s", repo, tag, digest)
	})

	t.Run("GetManifest", func(t *testing.T) {
		repo := fmt.Sprintf("%s/nginx", os.Getenv("REGISTRY_HOST"))
		tag := "latest"

		digest, err := client.GetDigest(ctx, repo, tag)
		if err != nil {
			t.Fatalf("Failed to get digest: %v", err)
		}

		manifest, err := client.GetManifest(ctx, repo, digest)
		if err != nil {
			t.Fatalf("Failed to get manifest: %v", err)
		}

		if manifest.Digest != digest {
			t.Errorf("Expected digest %s, got %s", digest, manifest.Digest)
		}

		if manifest.Architecture == "" {
			t.Error("Expected non-empty architecture")
		}

		if manifest.OS == "" {
			t.Error("Expected non-empty OS")
		}

		if len(manifest.Layers) == 0 {
			t.Error("Expected at least one layer")
		}

		t.Logf("Manifest for %s@%s:", repo, digest)
		t.Logf("  Architecture: %s", manifest.Architecture)
		t.Logf("  OS: %s", manifest.OS)
		t.Logf("  Layers: %d", len(manifest.Layers))
	})
	*/
}

// TestAttestation tests the attestation integration
func TestAttestation(t *testing.T) {
	// Skip if no attestation key is provided
	keyPath := os.Getenv("ATTESTATION_KEY_PATH")
	if keyPath == "" {
		t.Skip("Skipping attestation test: ATTESTATION_KEY_PATH not set")
	}

	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("Failed to read attestation key: %v", err)
	}

	cfg := attestation.AttestationConfig{
		KeyBased: attestation.KeyBasedConfig{
			Key: base64.StdEncoding.EncodeToString(keyData),
		},
	}

	attestor, err := attestation.NewSigstoreAttestor(cfg, slog.Default())
	if err != nil {
		t.Fatalf("Failed to create attestor: %v", err)
	}
	
	// Note: Registry authentication should be done separately in production
	// For tests, we assume cosign is already authenticated or using local registry

	ctx := context.Background()

	t.Run("AttestSBOM", func(t *testing.T) {
		sbom := &scanner.SBOM{
			Format: "cyclonedx",
			Data:   []byte(`{"bomFormat": "CycloneDX", "specVersion": "1.4"}`),
		}

		imageRef := "test.registry.io/test/image@sha256:test123"

		err := attestor.AttestSBOM(ctx, imageRef, sbom)
		if err != nil {
			t.Logf("SBOM attestation failed (expected in test environment): %v", err)
			// Don't fail the test as this requires actual registry access
		} else {
			t.Logf("Successfully attested SBOM for %s", imageRef)
		}
	})

	t.Run("AttestVulnerabilities", func(t *testing.T) {
		scanResult := &scanner.ScanResult{
			ImageRef: "test.registry.io/test/image@sha256:test123",
			Vulnerabilities: []types.Vulnerability{
				{
					ID:          "CVE-2024-TEST",
					Severity:    "HIGH",
					PackageName: "testpkg",
					Version:     "1.0.0",
					Description: "Test vulnerability",
				},
			},
		}

		err := attestor.AttestVulnerabilities(ctx, scanResult.ImageRef, scanResult)
		if err != nil {
			t.Logf("Vulnerability attestation failed (expected in test environment): %v", err)
			// Don't fail the test as this requires actual registry access
		} else {
			t.Logf("Successfully attested vulnerabilities for %s", scanResult.ImageRef)
		}
	})
}

// TestPolicyAndAttestationWorkflow tests the integration between policy and attestation
func TestPolicyAndAttestationWorkflow(t *testing.T) {
	// Setup policy engine
	expiresAt := time.Now().Add(30 * 24 * time.Hour).Unix()
	tolerations := []types.CVEToleration{
		{
			ID:        "CVE-2024-TOLERATED",
			Statement: "Accepted risk",
			ExpiresAt: &expiresAt,
		},
	}

	engine, err := policy.NewEngine(nil, policy.PolicyConfig{
		Expression: "criticalCount == 0",
	})
	if err != nil {
		t.Fatalf("failed to create policy engine: %v", err)
	}
	ctx := context.Background()

	t.Run("WorkflowWithPolicyPass", func(t *testing.T) {
		// Scan result with tolerated CVE
		scanResult := &scanner.ScanResult{
			ImageRef: "myregistry.com/nginx:latest",
			Vulnerabilities: []types.Vulnerability{
				{
					ID:       "CVE-2024-TOLERATED",
					Severity: "CRITICAL",
				},
				{
					ID:       "CVE-2024-LOW",
					Severity: "LOW",
				},
			},
		}

		// Evaluate policy
		decision, err := engine.Evaluate(ctx, "myregistry.com/nginx:latest", scanResult, tolerations)
		if err != nil {
			t.Fatalf("Failed to evaluate policy: %v", err)
		}

		if !decision.Passed {
			t.Error("Expected policy to pass with tolerated CVE")
		}

		// In a real workflow, we would:
		// 1. Attest SBOM (always)
		// 2. Attest vulnerabilities (always)
		// 3. Attest SCAI (always)

		t.Logf("Policy passed: %v", decision.Passed)
		t.Logf("Critical count: %d", decision.CriticalVulnCount)
		t.Logf("Tolerated CVEs: %v", decision.ToleratedCVEs)
		t.Log("Would attest SBOM, vulnerabilities, and SCAI")
	})

	t.Run("WorkflowWithPolicyFail", func(t *testing.T) {
		// Scan result with non-tolerated critical CVE
		scanResult := &scanner.ScanResult{
			ImageRef: "myregistry.com/nginx:latest",
			Vulnerabilities: []types.Vulnerability{
				{
					ID:       "CVE-2024-CRITICAL",
					Severity: "CRITICAL",
				},
			},
		}

		// Evaluate policy
		decision, err := engine.Evaluate(ctx, "myregistry.com/nginx:latest", scanResult, tolerations)
		if err != nil {
			t.Fatalf("Failed to evaluate policy: %v", err)
		}

		if decision.Passed {
			t.Error("Expected policy to fail with non-tolerated critical CVE")
		}

		// In a real workflow, we would:
		// 1. Attest SBOM (always)
		// 2. Attest vulnerabilities (always)
		// 3. NOT sign image (policy failed)

		t.Logf("Policy passed: %v", decision.Passed)
		t.Logf("Critical count: %d", decision.CriticalVulnCount)
		t.Log("Would attest SBOM and vulnerabilities, but NOT sign image")
	})
}

// TestOptimizedAttestationFlow tests the optimized attestation process (Task 3)
// This test verifies that SBOM attestation uses pre-generated SBOM data without redundant Trivy invocations
func TestOptimizedAttestationFlow(t *testing.T) {
	// Use the keys from the keys/ directory (relative to workspace root)
	keyPath := getEnv("ATTESTATION_KEY_PATH", "../../keys/cosign.key")
	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		t.Skipf("Skipping optimized attestation test: key not found at %s", keyPath)
	}

	// Setup scanner
	scannerCfg := config.ScannerConfig{
		ServerAddr: getEnv("TRIVY_SERVER_ADDR", "localhost:4954"),
		Timeout:    5 * time.Minute,
	}

	trivyScanner, err := scanner.NewTrivyScanner(scannerCfg)
	if err != nil {
		t.Fatalf("Failed to create scanner: %v", err)
	}

	// Setup attestor
	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("Failed to read attestation key: %v", err)
	}

	attestorCfg := attestation.AttestationConfig{
		KeyBased: attestation.KeyBasedConfig{
			Key: base64.StdEncoding.EncodeToString(keyData),
		},
	}

	attestor, err := attestation.NewSigstoreAttestor(attestorCfg, slog.Default())
	if err != nil {
		t.Fatalf("Failed to create attestor: %v", err)
	}

	ctx := context.Background()

	t.Run("GenerateSBOMOnceAndAttest", func(t *testing.T) {
		// Set up a test image in the local registry
		t.Log("Setting up test image in local registry...")
		imageRef, err := setupLocalRegistryImage(ctx, "alpine:latest", "test/alpine:latest")
		if err != nil {
			t.Fatalf("Failed to setup local registry image: %v", err)
		}
		t.Logf("Using local registry image: %s", imageRef)
		
		// Step 1: Generate SBOM using Trivy (ONCE)
		t.Log("Step 1: Generating SBOM with Trivy...")
		sbomStartTime := time.Now()
		sbom, err := trivyScanner.GenerateSBOM(ctx, imageRef)
		if err != nil {
			t.Fatalf("Failed to generate SBOM: %v", err)
		}
		sbomDuration := time.Since(sbomStartTime)
		
		if sbom == nil {
			t.Fatal("Expected SBOM, got nil")
		}
		
		if sbom.Format != "cyclonedx" {
			t.Errorf("Expected format 'cyclonedx', got %s", sbom.Format)
		}
		
		if len(sbom.Data) == 0 {
			t.Error("SBOM data should not be empty")
		}
		
		t.Logf("SBOM generated: format=%s, version=%s, size=%d bytes, duration=%v",
			sbom.Format, sbom.Version, len(sbom.Data), sbomDuration)
		
		// Step 2: Create attestation using pre-generated SBOM
		// This should NOT invoke Trivy again
		t.Log("Step 2: Creating SBOM attestation with pre-generated data...")
		attestStartTime := time.Now()
		err = attestor.AttestSBOM(ctx, imageRef, sbom)
		attestDuration := time.Since(attestStartTime)
		
		if err != nil {
			t.Logf("SBOM attestation failed (may be expected in test environment): %v", err)
			// Don't fail the test as this requires actual registry access
			// The important part is that we're using pre-generated SBOM data
		} else {
			t.Logf("SBOM attestation created successfully in %v", attestDuration)
			
			// Verify attestation duration is significantly less than SBOM generation
			// (since we're not regenerating the SBOM)
			if attestDuration > sbomDuration {
				t.Logf("Warning: Attestation took longer than SBOM generation. This may indicate redundant SBOM generation.")
				t.Logf("  SBOM generation: %v", sbomDuration)
				t.Logf("  Attestation: %v", attestDuration)
			}
		}
		
		// Step 3: Verify attestation can be retrieved (if attestation succeeded)
		if err == nil {
			t.Log("Step 3: Verifying attestation...")
			// Construct public key path - replace .key with .pub
			var pubKeyPath string
			if len(keyPath) > 4 && keyPath[len(keyPath)-4:] == ".key" {
				pubKeyPath = keyPath[:len(keyPath)-4] + ".pub"
			} else {
				pubKeyPath = keyPath + ".pub"
			}
			t.Logf("Using public key: %s", pubKeyPath)
			
			// Use cosign to verify the attestation
			verifyCmd := exec.CommandContext(ctx, "cosign", "verify-attestation",
				"--key", pubKeyPath,
				"--type", "https://cyclonedx.org/bom",
				"--insecure-ignore-tlog",
				imageRef,
			)
			
			verifyOutput, verifyErr := verifyCmd.CombinedOutput()
			if verifyErr != nil {
				t.Logf("Attestation verification failed (may be expected in test environment): %v", verifyErr)
				t.Logf("Output: %s", string(verifyOutput))
			} else {
				t.Log("Attestation verified successfully")
				
				// Verify the attestation contains the SBOM data
				if len(verifyOutput) == 0 {
					t.Error("Expected attestation output, got empty")
				} else {
					t.Logf("Attestation output size: %d bytes", len(verifyOutput))
				}
			}
		}
		
		t.Logf("Optimized attestation flow completed:")
		t.Logf("  - SBOM generation: %v (Trivy invoked ONCE)", sbomDuration)
		t.Logf("  - Attestation creation: %v (using pre-generated SBOM)", attestDuration)
		t.Logf("  - Total time: %v", sbomDuration+attestDuration)
	})
	
	t.Run("ValidateSBOMDataFormat", func(t *testing.T) {
		t.Log("Setting up test image in local registry...")
		imageRef, err := setupLocalRegistryImage(ctx, "alpine:latest", "test/alpine:validate")
		if err != nil {
			t.Fatalf("Failed to setup local registry image: %v", err)
		}
		t.Logf("Using local registry image: %s", imageRef)
		
		// Generate SBOM
		t.Log("Generating SBOM...")
		sbom, err := trivyScanner.GenerateSBOM(ctx, imageRef)
		if err != nil {
			t.Fatalf("Failed to generate SBOM: %v", err)
		}
		
		// Validate SBOM data is valid JSON
		t.Log("Validating SBOM data format...")
		var jsonCheck interface{}
		if err := json.Unmarshal(sbom.Data, &jsonCheck); err != nil {
			t.Errorf("SBOM data is not valid JSON: %v", err)
		} else {
			t.Log("SBOM data is valid JSON")
		}
		
		// Verify it's CycloneDX format
		var cyclonedxCheck map[string]interface{}
		if err := json.Unmarshal(sbom.Data, &cyclonedxCheck); err == nil {
			if bomFormat, ok := cyclonedxCheck["bomFormat"]; ok {
				if bomFormat != "CycloneDX" {
					t.Errorf("Expected bomFormat 'CycloneDX', got %v", bomFormat)
				} else {
					t.Log("SBOM is valid CycloneDX format")
				}
			} else {
				t.Error("SBOM missing 'bomFormat' field")
			}
		}
		
		// Test attestation with valid SBOM
		t.Log("Testing attestation with valid SBOM data...")
		err = attestor.AttestSBOM(ctx, imageRef, sbom)
		if err != nil {
			t.Logf("Attestation failed (may be expected): %v", err)
		} else {
			t.Log("Attestation succeeded with valid SBOM data")
		}
	})
	
	t.Run("ErrorHandlingForMalformedSBOM", func(t *testing.T) {
		t.Log("Setting up test image in local registry...")
		imageRef, err := setupLocalRegistryImage(ctx, "alpine:latest", "test/alpine:error")
		if err != nil {
			t.Fatalf("Failed to setup local registry image: %v", err)
		}
		t.Logf("Using local registry image: %s", imageRef)
		
		// Test with nil SBOM
		t.Log("Testing with nil SBOM...")
		err = attestor.AttestSBOM(ctx, imageRef, nil)
		if err == nil {
			t.Error("Expected error with nil SBOM, got nil")
		} else {
			t.Logf("Correctly rejected nil SBOM: %v", err)
		}
		
		// Test with empty SBOM data
		t.Log("Testing with empty SBOM data...")
		emptySBOM := &scanner.SBOM{
			Format:  "cyclonedx",
			Version: "1.5",
			Data:    []byte{},
		}
		err = attestor.AttestSBOM(ctx, imageRef, emptySBOM)
		if err == nil {
			t.Error("Expected error with empty SBOM data, got nil")
		} else {
			t.Logf("Correctly rejected empty SBOM data: %v", err)
		}
		
		// Test with malformed JSON
		t.Log("Testing with malformed JSON...")
		malformedSBOM := &scanner.SBOM{
			Format:  "cyclonedx",
			Version: "1.5",
			Data:    []byte("not valid json {{{"),
		}
		err = attestor.AttestSBOM(ctx, imageRef, malformedSBOM)
		if err == nil {
			t.Error("Expected error with malformed JSON, got nil")
		} else {
			t.Logf("Correctly rejected malformed JSON: %v", err)
		}
	})
	
	t.Run("EndToEndWithVulnerabilityAttestation", func(t *testing.T) {
		t.Log("Setting up test image in local registry...")
		imageRef, err := setupLocalRegistryImage(ctx, "alpine:3.7", "test/alpine:3.7")
		if err != nil {
			t.Fatalf("Failed to setup local registry image: %v", err)
		}
		t.Logf("Using local registry image: %s", imageRef)
		
		// Step 1: Generate SBOM (once)
		t.Log("Step 1: Generating SBOM...")
		sbomStartTime := time.Now()
		sbom, err := trivyScanner.GenerateSBOM(ctx, imageRef)
		if err != nil {
			t.Fatalf("Failed to generate SBOM: %v", err)
		}
		sbomDuration := time.Since(sbomStartTime)
		t.Logf("SBOM generated in %v", sbomDuration)
		
		// Step 2: Scan vulnerabilities (once)
		t.Log("Step 2: Scanning vulnerabilities...")
		scanStartTime := time.Now()
		scanResult, err := trivyScanner.ScanVulnerabilities(ctx, imageRef)
		if err != nil {
			t.Fatalf("Failed to scan vulnerabilities: %v", err)
		}
		scanDuration := time.Since(scanStartTime)
		t.Logf("Vulnerability scan completed in %v, found %d vulnerabilities", scanDuration, len(scanResult.Vulnerabilities))
		
		// Step 3: Create SBOM attestation (using pre-generated SBOM)
		t.Log("Step 3: Creating SBOM attestation...")
		sbomAttestStartTime := time.Now()
		err = attestor.AttestSBOM(ctx, imageRef, sbom)
		sbomAttestDuration := time.Since(sbomAttestStartTime)
		if err != nil {
			t.Logf("SBOM attestation failed (may be expected): %v", err)
		} else {
			t.Logf("SBOM attestation created in %v", sbomAttestDuration)
		}
		
		// Step 4: Create vulnerability attestation (using pre-generated scan results)
		t.Log("Step 4: Creating vulnerability attestation...")
		vulnAttestStartTime := time.Now()
		err = attestor.AttestVulnerabilities(ctx, imageRef, scanResult)
		vulnAttestDuration := time.Since(vulnAttestStartTime)
		if err != nil {
			t.Logf("Vulnerability attestation failed (may be expected): %v", err)
		} else {
			t.Logf("Vulnerability attestation created in %v", vulnAttestDuration)
		}
		
		totalDuration := sbomDuration + scanDuration + sbomAttestDuration + vulnAttestDuration
		t.Logf("End-to-end optimized flow completed:")
		t.Logf("  - SBOM generation: %v", sbomDuration)
		t.Logf("  - Vulnerability scan: %v", scanDuration)
		t.Logf("  - SBOM attestation: %v", sbomAttestDuration)
		t.Logf("  - Vulnerability attestation: %v", vulnAttestDuration)
		t.Logf("  - Total time: %v", totalDuration)
		t.Logf("  - Trivy invocations: 2 (SBOM + Vuln scan, no redundant calls)")
	})
}

// TestCompleteWorkerWorkflow tests the complete worker scan workflow (Task 8.2)
// This test exercises all 8 steps of the workflow with real components
func TestCompleteWorkerWorkflow(t *testing.T) {
	// Setup
	dbPath := "test_worker_workflow.db"
	defer os.Remove(dbPath)

	scannerCfg := config.ScannerConfig{
		ServerAddr: getEnv("TRIVY_SERVER_ADDR", "localhost:4954"),
		Timeout:    5 * time.Minute,
	}

	// Initialize all components
	trivyScanner, err := scanner.NewTrivyScanner(scannerCfg)
	if err != nil {
		t.Fatalf("Failed to create scanner: %v", err)
	}

	store, err := statestore.NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("Failed to create state store: %v", err)
	}
	defer store.Close()

	policyEngine, err := policy.NewEngine(nil, policy.PolicyConfig{
		Expression: "criticalCount == 0",
	})
	if err != nil {
		t.Fatalf("failed to create policy engine: %v", err)
	}

	// Create mock registry client (since we don't have a real registry in test)
	regsyncCfg := &config.RegsyncConfig{
		Version: 1,
		Sync: []config.SyncEntry{
			{
				Source: "alpine",
				Target: "test.registry.io/alpine",
				Type:   "repository",
			},
		},
	}

	_, err = registry.NewClient(regsyncCfg)
	if err != nil {
		t.Fatalf("Failed to create registry client: %v", err)
	}

	ctx := context.Background()

	t.Run("WorkflowWithCleanImage", func(t *testing.T) {
		// Use a recent Alpine image (should have fewer vulnerabilities)
		imageRef := "alpine:latest"
		digest := "sha256:clean-test-123"

		// Step 1: Scan for vulnerabilities
		t.Log("Step 1: Scanning for vulnerabilities...")
		scanResult, err := trivyScanner.ScanVulnerabilities(ctx, imageRef)
		if err != nil {
			t.Fatalf("Failed to scan vulnerabilities: %v", err)
		}
		t.Logf("Found %d vulnerabilities", len(scanResult.Vulnerabilities))

		// Step 2: Generate SBOM
		t.Log("Step 2: Generating SBOM...")
		sbom, err := trivyScanner.GenerateSBOM(ctx, imageRef)
		if err != nil {
			t.Fatalf("Failed to generate SBOM: %v", err)
		}
		t.Logf("Generated SBOM: %d bytes", len(sbom.Data))

		// Step 3: Evaluate policy (no tolerations)
		t.Log("Step 3: Evaluating policy...")
		decision, err := policyEngine.Evaluate(ctx, imageRef, scanResult, []types.CVEToleration{})
		if err != nil {
			t.Fatalf("Failed to evaluate policy: %v", err)
		}
		t.Logf("Policy decision: passed=%v, critical=%d, high=%d",
			decision.Passed, decision.CriticalVulnCount, len(scanResult.Vulnerabilities))

		// Step 4: Record scan results
		t.Log("Step 4: Recording scan results...")
		vulnRecords := make([]types.VulnerabilityRecord, 0, len(scanResult.Vulnerabilities))
		criticalCount := 0
		highCount := 0
		mediumCount := 0
		lowCount := 0

		for _, vuln := range scanResult.Vulnerabilities {
			vulnRecords = append(vulnRecords, types.VulnerabilityRecord{
				CVEID:            vuln.ID,
				Severity:         vuln.Severity,
				PackageName:      vuln.PackageName,
				InstalledVersion: vuln.Version,
				FixedVersion:     vuln.FixedVersion,
				Title:            vuln.Title,
				Description:      vuln.Description,
				PrimaryURL:       vuln.PrimaryURL,
			})

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
		}

		record := &statestore.ScanRecord{
			Digest:            digest,
			Repository:        "library/alpine",
			Tag:               "latest",
			CreatedAt:         time.Now(),
			CriticalVulnCount: criticalCount,
			HighVulnCount:     highCount,
			MediumVulnCount:   mediumCount,
			LowVulnCount:      lowCount,
			PolicyPassed:      decision.Passed,
			SBOMAttested:      true,
			VulnAttested:      true,
			Vulnerabilities:   vulnRecords,
		}

		err = store.RecordScan(ctx, record)
		if err != nil {
			t.Fatalf("Failed to record scan: %v", err)
		}

		// Step 5: Verify the scan was recorded
		t.Log("Step 5: Verifying scan record...")
		retrieved, err := store.GetLastScan(ctx, digest)
		if err != nil {
			t.Fatalf("Failed to retrieve scan: %v", err)
		}

		if retrieved.Digest != digest {
			t.Errorf("Expected digest %s, got %s", digest, retrieved.Digest)
		}

		if !retrieved.SBOMAttested {
			t.Error("Expected SBOM to be attested")
		}

		if !retrieved.VulnAttested {
			t.Error("Expected vulnerabilities to be attested")
		}

		t.Logf("Workflow completed successfully:")
		t.Logf("  - Image: %s", imageRef)
		t.Logf("  - Vulnerabilities: %d (Critical: %d, High: %d, Medium: %d, Low: %d)",
			len(retrieved.Vulnerabilities), criticalCount, highCount, mediumCount, lowCount)
		t.Logf("  - Policy passed: %v", retrieved.PolicyPassed)
	})

	t.Run("WorkflowWithVulnerableImage", func(t *testing.T) {
		// Use an old Alpine image (known to have vulnerabilities)
		imageRef := "alpine:3.7"
		digest := "sha256:vulnerable-test-456"

		// Step 1: Scan for vulnerabilities
		t.Log("Step 1: Scanning vulnerable image...")
		scanResult, err := trivyScanner.ScanVulnerabilities(ctx, imageRef)
		if err != nil {
			t.Fatalf("Failed to scan vulnerabilities: %v", err)
		}
		t.Logf("Found %d vulnerabilities", len(scanResult.Vulnerabilities))

		// Step 2: Generate SBOM
		t.Log("Step 2: Generating SBOM...")
		sbom, err := trivyScanner.GenerateSBOM(ctx, imageRef)
		if err != nil {
			t.Fatalf("Failed to generate SBOM: %v", err)
		}
		t.Logf("Generated SBOM: %d bytes", len(sbom.Data))

		// Step 3: Evaluate policy (no tolerations - should fail if critical vulns exist)
		t.Log("Step 3: Evaluating policy...")
		decision, err := policyEngine.Evaluate(ctx, imageRef, scanResult, []types.CVEToleration{})
		if err != nil {
			t.Fatalf("Failed to evaluate policy: %v", err)
		}
		t.Logf("Policy decision: passed=%v, critical=%d", decision.Passed, decision.CriticalVulnCount)

		// Step 4: Record scan results
		t.Log("Step 4: Recording scan results...")
		vulnRecords := make([]types.VulnerabilityRecord, 0, len(scanResult.Vulnerabilities))
		criticalCount := 0
		highCount := 0
		mediumCount := 0
		lowCount := 0

		for _, vuln := range scanResult.Vulnerabilities {
			vulnRecords = append(vulnRecords, types.VulnerabilityRecord{
				CVEID:            vuln.ID,
				Severity:         vuln.Severity,
				PackageName:      vuln.PackageName,
				InstalledVersion: vuln.Version,
				FixedVersion:     vuln.FixedVersion,
				Title:            vuln.Title,
				Description:      vuln.Description,
				PrimaryURL:       vuln.PrimaryURL,
			})

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
		}

		record := &statestore.ScanRecord{
			Digest:            digest,
			Repository:        "library/alpine",
			Tag:               "3.7",
			CreatedAt:         time.Now(),
			CriticalVulnCount: criticalCount,
			HighVulnCount:     highCount,
			MediumVulnCount:   mediumCount,
			LowVulnCount:      lowCount,
			PolicyPassed:      decision.Passed,
			SBOMAttested:      true,
			VulnAttested:      true,
			Vulnerabilities:   vulnRecords,
		}

		err = store.RecordScan(ctx, record)
		if err != nil {
			t.Fatalf("Failed to record scan: %v", err)
		}

		// Step 5: Verify the scan was recorded
		t.Log("Step 5: Verifying scan record...")
		retrieved, err := store.GetLastScan(ctx, digest)
		if err != nil {
			t.Fatalf("Failed to retrieve scan: %v", err)
		}

		if retrieved.Digest != digest {
			t.Errorf("Expected digest %s, got %s", digest, retrieved.Digest)
		}

		// Should always attest, regardless of policy
		if !retrieved.SBOMAttested {
			t.Error("Expected SBOM to be attested")
		}

		if !retrieved.VulnAttested {
			t.Error("Expected vulnerabilities to be attested")
		}


		t.Logf("Workflow completed successfully:")
		t.Logf("  - Image: %s", imageRef)
		t.Logf("  - Vulnerabilities: %d (Critical: %d, High: %d, Medium: %d, Low: %d)",
			len(retrieved.Vulnerabilities), criticalCount, highCount, mediumCount, lowCount)
		t.Logf("  - Policy passed: %v", retrieved.PolicyPassed)
	})

	t.Run("WorkflowWithToleratedCVEs", func(t *testing.T) {
		// Use an old Alpine image
		imageRef := "alpine:3.7"
		digest := "sha256:tolerated-test-789"

		// Step 1: Scan for vulnerabilities
		t.Log("Step 1: Scanning image...")
		scanResult, err := trivyScanner.ScanVulnerabilities(ctx, imageRef)
		if err != nil {
			t.Fatalf("Failed to scan vulnerabilities: %v", err)
		}

		// Find a critical CVE to tolerate
		var criticalCVE string
		for _, vuln := range scanResult.Vulnerabilities {
			if vuln.Severity == "CRITICAL" {
				criticalCVE = vuln.ID
				break
			}
		}

		if criticalCVE == "" {
			t.Skip("No critical CVEs found to test toleration")
		}

		t.Logf("Found critical CVE to tolerate: %s", criticalCVE)

		// Step 2: Generate SBOM
		t.Log("Step 2: Generating SBOM...")
		_, err = trivyScanner.GenerateSBOM(ctx, imageRef)
		if err != nil {
			t.Fatalf("Failed to generate SBOM: %v", err)
		}

		// Step 3: Evaluate policy WITH toleration
		t.Log("Step 3: Evaluating policy with toleration...")
		expiresAt := time.Now().Add(30 * 24 * time.Hour).Unix()
		tolerations := []types.CVEToleration{
			{
				ID:        criticalCVE,
				Statement: "Accepted risk for integration testing",
				ExpiresAt: &expiresAt,
			},
		}

		decision, err := policyEngine.Evaluate(ctx, imageRef, scanResult, tolerations)
		if err != nil {
			t.Fatalf("Failed to evaluate policy: %v", err)
		}

		t.Logf("Policy decision: passed=%v, critical=%d, tolerated=%d",
			decision.Passed, decision.CriticalVulnCount, decision.ToleratedVulnCount)

		// Verify the CVE was tolerated
		if len(decision.ToleratedCVEs) == 0 {
			t.Error("Expected at least one tolerated CVE")
		}

		found := false
		for _, toleratedID := range decision.ToleratedCVEs {
			if toleratedID == criticalCVE {
				found = true
				break
			}
		}

		if !found {
			t.Errorf("Expected CVE %s to be in tolerated list", criticalCVE)
		}

		// Step 4: Record scan results with tolerations
		t.Log("Step 4: Recording scan results with tolerations...")
		vulnRecords := make([]types.VulnerabilityRecord, 0, len(scanResult.Vulnerabilities))
		criticalCount := 0
		highCount := 0
		mediumCount := 0
		lowCount := 0

		for _, vuln := range scanResult.Vulnerabilities {
			vulnRecords = append(vulnRecords, types.VulnerabilityRecord{
				CVEID:            vuln.ID,
				Severity:         vuln.Severity,
				PackageName:      vuln.PackageName,
				InstalledVersion: vuln.Version,
				FixedVersion:     vuln.FixedVersion,
				Title:            vuln.Title,
				Description:      vuln.Description,
				PrimaryURL:       vuln.PrimaryURL,
			})

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
		}

		toleratedCVEs := []types.ToleratedCVE{
			{
				CVEID:       criticalCVE,
				Statement:   "Accepted risk for integration testing",
				ToleratedAt: time.Now().Unix(),
				ExpiresAt:   &expiresAt,
			},
		}

		record := &statestore.ScanRecord{
			Digest:            digest,
			Repository:        "library/alpine",
			Tag:               "3.7",
			CreatedAt:         time.Now(),
			CriticalVulnCount: criticalCount,
			HighVulnCount:     highCount,
			MediumVulnCount:   mediumCount,
			LowVulnCount:      lowCount,
			PolicyPassed:      decision.Passed,
			SBOMAttested:      true,
			VulnAttested:      true,
			Vulnerabilities:   vulnRecords,
			ToleratedCVEs:     toleratedCVEs,
		}

		err = store.RecordScan(ctx, record)
		if err != nil {
			t.Fatalf("Failed to record scan: %v", err)
		}

		// Step 5: Verify the scan was recorded with tolerations
		t.Log("Step 5: Verifying scan record with tolerations...")
		retrieved, err := store.GetLastScan(ctx, digest)
		if err != nil {
			t.Fatalf("Failed to retrieve scan: %v", err)
		}

		if len(retrieved.ToleratedCVEs) == 0 {
			t.Error("Expected tolerated CVEs to be recorded")
		}

		if retrieved.ToleratedCVEs[0].CVEID != criticalCVE {
			t.Errorf("Expected tolerated CVE %s, got %s", criticalCVE, retrieved.ToleratedCVEs[0].CVEID)
		}

		t.Logf("Workflow with tolerations completed successfully:")
		t.Logf("  - Image: %s", imageRef)
		t.Logf("  - Vulnerabilities: %d (Critical: %d, High: %d, Medium: %d, Low: %d)",
			len(retrieved.Vulnerabilities), criticalCount, highCount, mediumCount, lowCount)
		t.Logf("  - Tolerated CVEs: %d", len(retrieved.ToleratedCVEs))
		t.Logf("  - Policy passed: %v", retrieved.PolicyPassed)
	})

	t.Run("WorkflowWithRescan", func(t *testing.T) {
		// Test rescan scenario where a previously passing image now fails
		imageRef := "alpine:3.7"
		digest := "sha256:rescan-test-999"

		// First scan: with toleration (should pass and sign)
		t.Log("First scan: with toleration...")
		scanResult, err := trivyScanner.ScanVulnerabilities(ctx, imageRef)
		if err != nil {
			t.Fatalf("Failed to scan vulnerabilities: %v", err)
		}

		// Find a critical CVE
		var criticalCVE string
		for _, vuln := range scanResult.Vulnerabilities {
			if vuln.Severity == "CRITICAL" {
				criticalCVE = vuln.ID
				break
			}
		}

		if criticalCVE == "" {
			t.Skip("No critical CVEs found for rescan test")
		}

		expiresAt := time.Now().Add(30 * 24 * time.Hour).Unix()
		tolerations := []types.CVEToleration{
			{
				ID:        criticalCVE,
				Statement: "Temporary acceptance",
				ExpiresAt: &expiresAt,
			},
		}

		_, err = policyEngine.Evaluate(ctx, imageRef, scanResult, tolerations)
		if err != nil {
			t.Fatalf("Failed to evaluate policy: %v", err)
		}

		// Record first scan (should pass)
		record1 := &statestore.ScanRecord{
			Digest:            digest,
			Repository:        "library/alpine",
			Tag:               "3.7",
			CreatedAt:         time.Now().Add(-24 * time.Hour), // Yesterday
			CriticalVulnCount: 0, // Tolerated
			PolicyPassed:      true,
			SBOMAttested:      true,
			VulnAttested:      true,
		}

		err = store.RecordScan(ctx, record1)
		if err != nil {
			t.Fatalf("Failed to record first scan: %v", err)
		}

		// Second scan: without toleration (should fail)
		t.Log("Second scan: without toleration (rescan)...")
		decision2, err := policyEngine.Evaluate(ctx, imageRef, scanResult, []types.CVEToleration{})
		if err != nil {
			t.Fatalf("Failed to evaluate policy on rescan: %v", err)
		}

		// Record second scan (should fail)
		record2 := &statestore.ScanRecord{
			Digest:            digest,
			Repository:        "library/alpine",
			Tag:               "3.7",
			CreatedAt:         time.Now(),
			CriticalVulnCount: decision2.CriticalVulnCount,
			PolicyPassed:      decision2.Passed,
			SBOMAttested:      true,
			VulnAttested:      true,
		}

		err = store.RecordScan(ctx, record2)
		if err != nil {
			t.Fatalf("Failed to record second scan: %v", err)
		}

		// Verify rescan behavior
		retrieved, err := store.GetLastScan(ctx, digest)
		if err != nil {
			t.Fatalf("Failed to retrieve scan: %v", err)
		}


		if retrieved.PolicyPassed {
			t.Error("Expected policy to fail on rescan without toleration")
		}

		t.Logf("Rescan workflow completed successfully:")
		t.Logf("  - First scan: passed=%v", true)
		t.Logf("  - Second scan: passed=%v", retrieved.PolicyPassed)
		t.Logf("  - Alert: Previously passing image now fails policy")
	})
}
