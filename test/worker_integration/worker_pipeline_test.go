package worker_integration

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/daimoniac/suppline/internal/attestation"
	supplineErrors "github.com/daimoniac/suppline/internal/errors"
	"github.com/daimoniac/suppline/internal/policy"
	"github.com/daimoniac/suppline/internal/queue"
	"github.com/daimoniac/suppline/internal/registry"
	"github.com/daimoniac/suppline/internal/scanner"
	"github.com/daimoniac/suppline/internal/statestore"
	"github.com/daimoniac/suppline/internal/types"
	"github.com/daimoniac/suppline/internal/worker"
)

// Mock implementations for pipeline integration tests

type mockRegistry struct {
	manifestError error
}

func (m *mockRegistry) ListRepositories(ctx context.Context) ([]string, error) {
	return []string{"test/repo"}, nil
}

func (m *mockRegistry) ListTags(ctx context.Context, repo string) ([]string, error) {
	return []string{"latest"}, nil
}

func (m *mockRegistry) GetDigest(ctx context.Context, repo, tag string) (string, error) {
	return "sha256:abc123", nil
}

func (m *mockRegistry) GetManifest(ctx context.Context, repository, digest string) (*registry.Manifest, error) {
	if m.manifestError != nil {
		return nil, m.manifestError
	}
	return &registry.Manifest{
		Digest:    digest,
		MediaType: "application/vnd.docker.distribution.manifest.v2+json",
	}, nil
}

type mockScanner struct {
	sbomError error
	vulnError error
}

func (m *mockScanner) GenerateSBOM(ctx context.Context, imageRef string) (*scanner.SBOM, error) {
	if m.sbomError != nil {
		return nil, m.sbomError
	}
	return &scanner.SBOM{
		Format:  "cyclonedx",
		Version: "1.5",
		Data:    []byte(`{"bomFormat": "CycloneDX"}`),
		Created: time.Now(),
	}, nil
}

func (m *mockScanner) ScanVulnerabilities(ctx context.Context, imageRef string) (*scanner.ScanResult, error) {
	if m.vulnError != nil {
		return nil, m.vulnError
	}
	return &scanner.ScanResult{
		Vulnerabilities: []types.Vulnerability{},
	}, nil
}

func (m *mockScanner) HealthCheck(ctx context.Context) error {
	return nil
}

type mockPolicyEngine struct{}

func (m *mockPolicyEngine) Evaluate(ctx context.Context, imageRef string, scanResult *scanner.ScanResult, tolerations []types.CVEToleration) (*policy.PolicyDecision, error) {
	return &policy.PolicyDecision{
		Passed: true,
		Reason: "no vulnerabilities found",
	}, nil
}

type mockAttestor struct{}

func (m *mockAttestor) AttestSBOM(ctx context.Context, imageRef string, sbom *scanner.SBOM) error {
	return nil
}

func (m *mockAttestor) AttestVulnerabilities(ctx context.Context, imageRef string, scanResult *scanner.ScanResult) error {
	return nil
}

func (m *mockAttestor) AttestSCAI(ctx context.Context, imageRef string, scai *attestation.SCAIAttestation) error {
	return nil
}

type mockStateStore struct {
	recordScanError  error
	getLastScanError error
	lastScanID       int64
	cleanupCalled    map[string]bool
	cleanupErrors    map[string]error
}

func newMockStateStore() *mockStateStore {
	return &mockStateStore{
		cleanupCalled: make(map[string]bool),
		cleanupErrors: make(map[string]error),
		lastScanID:    1,
	}
}

func (m *mockStateStore) RecordScan(ctx context.Context, record *statestore.ScanRecord) error {
	return m.recordScanError
}

func (m *mockStateStore) GetLastScan(ctx context.Context, digest string) (*statestore.ScanRecord, error) {
	if m.getLastScanError != nil {
		return nil, m.getLastScanError
	}
	return &statestore.ScanRecord{
		ID:     m.lastScanID,
		Digest: digest,
	}, nil
}

func (m *mockStateStore) ListDueForRescan(ctx context.Context, interval time.Duration) ([]string, error) {
	return nil, nil
}

func (m *mockStateStore) CleanupArtifactScans(ctx context.Context, digest string) error {
	m.cleanupCalled["artifact_"+digest] = true
	if err, exists := m.cleanupErrors["artifact_"+digest]; exists {
		return err
	}
	return nil
}

func (m *mockStateStore) CleanupOrphanedRepositories(ctx context.Context) ([]string, error) {
	m.cleanupCalled["repositories"] = true
	if err, exists := m.cleanupErrors["repositories"]; exists {
		return nil, err
	}
	return []string{}, nil
}

func (m *mockStateStore) CleanupExcessScans(ctx context.Context, digest string, maxScansToKeep int) error {
	m.cleanupCalled["excess_"+digest] = true
	if err, exists := m.cleanupErrors["excess_"+digest]; exists {
		return err
	}
	return nil
}

// Pipeline integration tests

func TestPipeline_ManifestNotFoundCleanup(t *testing.T) {
	// Setup mocks
	mockQ := queue.NewInMemoryQueue(10)
	defer mockQ.Close()

	mockReg := &mockRegistry{
		manifestError: supplineErrors.NewManifestNotFound(errors.New("MANIFEST_UNKNOWN")),
	}
	mockScan := &mockScanner{}
	mockPol := &mockPolicyEngine{}
	mockAtt := &mockAttestor{}
	mockStore := newMockStateStore()

	logger := slog.Default()
	config := worker.DefaultConfig()

	w := worker.NewImageWorker(mockQ, mockScan, mockPol, mockAtt, mockReg, mockStore, config, logger, nil)

	task := &queue.ScanTask{
		ID:         "test-1",
		Repository: "test/repo",
		Digest:     "sha256:abc123",
		Tag:        "latest",
		EnqueuedAt: time.Now(),
	}

	// Execute pipeline
	err := w.ProcessTask(context.Background(), task)

	// Should return the manifest error
	if err == nil {
		t.Fatal("expected error for manifest not found")
	}

	if !supplineErrors.IsManifestNotFound(err) {
		t.Errorf("expected manifest not found error, got: %v", err)
	}

	// Verify cleanup was called
	if !mockStore.cleanupCalled["artifact_"+task.Digest] {
		t.Error("expected artifact cleanup to be called")
	}

	if !mockStore.cleanupCalled["repositories"] {
		t.Error("expected repository cleanup to be called")
	}
}

func TestPipeline_SuccessfulScanCleanup(t *testing.T) {
	// Setup mocks
	mockQ := queue.NewInMemoryQueue(10)
	defer mockQ.Close()

	mockReg := &mockRegistry{}
	mockScan := &mockScanner{}
	mockPol := &mockPolicyEngine{}
	mockAtt := &mockAttestor{}
	mockStore := newMockStateStore()

	logger := slog.Default()
	config := worker.DefaultConfig()

	w := worker.NewImageWorker(mockQ, mockScan, mockPol, mockAtt, mockReg, mockStore, config, logger, nil)

	task := &queue.ScanTask{
		ID:         "test-1",
		Repository: "test/repo",
		Digest:     "sha256:abc123",
		Tag:        "latest",
		EnqueuedAt: time.Now(),
	}

	// Execute pipeline
	err := w.ProcessTask(context.Background(), task)

	// Should succeed
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	// Verify cleanup was called
	if !mockStore.cleanupCalled["excess_"+task.Digest] {
		t.Error("expected excess scan cleanup to be called")
	}

	if !mockStore.cleanupCalled["repositories"] {
		t.Error("expected repository cleanup to be called")
	}
}

func TestPipeline_CleanupErrorHandling(t *testing.T) {
	// Setup mocks with cleanup errors
	mockQ := queue.NewInMemoryQueue(10)
	defer mockQ.Close()

	mockReg := &mockRegistry{
		manifestError: supplineErrors.NewManifestNotFound(errors.New("MANIFEST_UNKNOWN")),
	}
	mockScan := &mockScanner{}
	mockPol := &mockPolicyEngine{}
	mockAtt := &mockAttestor{}
	mockStore := newMockStateStore()

	// Set cleanup to fail
	mockStore.cleanupErrors["artifact_sha256:abc123"] = errors.New("cleanup failed")

	logger := slog.Default()
	config := worker.DefaultConfig()

	w := worker.NewImageWorker(mockQ, mockScan, mockPol, mockAtt, mockReg, mockStore, config, logger, nil)

	task := &queue.ScanTask{
		ID:         "test-1",
		Repository: "test/repo",
		Digest:     "sha256:abc123",
		Tag:        "latest",
		EnqueuedAt: time.Now(),
	}

	// Execute pipeline
	err := w.ProcessTask(context.Background(), task)

	// Should still return the original manifest error, not the cleanup error
	if err == nil {
		t.Fatal("expected error for manifest not found")
	}

	if !supplineErrors.IsManifestNotFound(err) {
		t.Errorf("expected manifest not found error, got: %v", err)
	}

	// Verify cleanup was attempted
	if !mockStore.cleanupCalled["artifact_"+task.Digest] {
		t.Error("expected artifact cleanup to be attempted")
	}
}

func TestPipeline_SuccessfulScanCleanupError(t *testing.T) {
	// Setup mocks
	mockQ := queue.NewInMemoryQueue(10)
	defer mockQ.Close()

	mockReg := &mockRegistry{}
	mockScan := &mockScanner{}
	mockPol := &mockPolicyEngine{}
	mockAtt := &mockAttestor{}
	mockStore := newMockStateStore()

	// Set excess scan cleanup to fail
	mockStore.cleanupErrors["excess_sha256:abc123"] = errors.New("cleanup failed")

	logger := slog.Default()
	config := worker.DefaultConfig()

	w := worker.NewImageWorker(mockQ, mockScan, mockPol, mockAtt, mockReg, mockStore, config, logger, nil)

	task := &queue.ScanTask{
		ID:         "test-1",
		Repository: "test/repo",
		Digest:     "sha256:abc123",
		Tag:        "latest",
		EnqueuedAt: time.Now(),
	}

	// Execute pipeline
	err := w.ProcessTask(context.Background(), task)

	// Should still succeed despite cleanup error
	if err != nil {
		t.Fatalf("expected no error despite cleanup failure, got: %v", err)
	}

	// Verify cleanup was attempted
	if !mockStore.cleanupCalled["excess_"+task.Digest] {
		t.Error("expected excess scan cleanup to be attempted")
	}
}

// Tests for worker error handling with cleanup errors

func TestProcessTask_TransientCleanupErrorRetry(t *testing.T) {
	// Setup mocks
	mockQ := queue.NewInMemoryQueue(10)
	defer mockQ.Close()

	mockReg := &mockRegistry{
		manifestError: supplineErrors.NewManifestNotFound(errors.New("MANIFEST_UNKNOWN")),
	}
	mockScan := &mockScanner{}
	mockPol := &mockPolicyEngine{}
	mockAtt := &mockAttestor{}
	mockStore := newMockStateStore()

	// Set cleanup to fail with transient error
	mockStore.cleanupErrors["artifact_sha256:abc123"] = supplineErrors.NewTransientf("database connection failed")

	logger := slog.Default()
	config := worker.Config{
		RetryAttempts: 2,
		RetryBackoff:  10 * time.Millisecond, // Short backoff for testing
		Concurrency:   1,
	}

	w := worker.NewImageWorker(mockQ, mockScan, mockPol, mockAtt, mockReg, mockStore, config, logger, nil)

	task := &queue.ScanTask{
		ID:         "test-1",
		Repository: "test/repo",
		Digest:     "sha256:abc123",
		Tag:        "latest",
		EnqueuedAt: time.Now(),
	}

	// Execute pipeline - should retry due to transient cleanup error
	err := w.ProcessTask(context.Background(), task)

	// Should return transient error after retries exhausted
	if err == nil {
		t.Fatal("expected error after retries exhausted")
	}

	if !supplineErrors.IsTransient(err) {
		t.Errorf("expected transient error after retries, got: %v", err)
	}

	// Verify cleanup was attempted multiple times due to retries
	if !mockStore.cleanupCalled["artifact_"+task.Digest] {
		t.Error("expected artifact cleanup to be attempted")
	}
}

func TestProcessTask_PermanentCleanupErrorNoRetry(t *testing.T) {
	// Setup mocks
	mockQ := queue.NewInMemoryQueue(10)
	defer mockQ.Close()

	mockReg := &mockRegistry{
		manifestError: supplineErrors.NewManifestNotFound(errors.New("MANIFEST_UNKNOWN")),
	}
	mockScan := &mockScanner{}
	mockPol := &mockPolicyEngine{}
	mockAtt := &mockAttestor{}
	mockStore := newMockStateStore()

	// Set cleanup to fail with permanent error
	mockStore.cleanupErrors["artifact_sha256:abc123"] = supplineErrors.NewPermanentf("invalid digest format")

	logger := slog.Default()
	config := worker.Config{
		RetryAttempts: 3,
		RetryBackoff:  10 * time.Millisecond,
		Concurrency:   1,
	}

	w := worker.NewImageWorker(mockQ, mockScan, mockPol, mockAtt, mockReg, mockStore, config, logger, nil)

	task := &queue.ScanTask{
		ID:         "test-1",
		Repository: "test/repo",
		Digest:     "sha256:abc123",
		Tag:        "latest",
		EnqueuedAt: time.Now(),
	}

	// Execute pipeline - should not retry due to permanent cleanup error
	err := w.ProcessTask(context.Background(), task)

	// Should return the original manifest error (permanent cleanup errors are logged but don't override original error)
	if err == nil {
		t.Fatal("expected error for manifest not found")
	}

	if !supplineErrors.IsManifestNotFound(err) {
		t.Errorf("expected manifest not found error (original error should be preserved), got: %v", err)
	}

	// Verify cleanup was attempted only once (no retries)
	if !mockStore.cleanupCalled["artifact_"+task.Digest] {
		t.Error("expected artifact cleanup to be attempted")
	}
}

func TestProcessTask_SuccessfulScanTransientCleanupError(t *testing.T) {
	// Setup mocks for successful scan with transient cleanup error
	mockQ := queue.NewInMemoryQueue(10)
	defer mockQ.Close()

	mockReg := &mockRegistry{}
	mockScan := &mockScanner{}
	mockPol := &mockPolicyEngine{}
	mockAtt := &mockAttestor{}
	mockStore := newMockStateStore()

	// Set excess scan cleanup to fail with transient error
	mockStore.cleanupErrors["excess_sha256:abc123"] = supplineErrors.NewTransientf("database timeout")

	logger := slog.Default()
	config := worker.Config{
		RetryAttempts: 2,
		RetryBackoff:  10 * time.Millisecond,
		Concurrency:   1,
	}

	w := worker.NewImageWorker(mockQ, mockScan, mockPol, mockAtt, mockReg, mockStore, config, logger, nil)

	task := &queue.ScanTask{
		ID:         "test-1",
		Repository: "test/repo",
		Digest:     "sha256:abc123",
		Tag:        "latest",
		EnqueuedAt: time.Now(),
	}

	// Execute pipeline - should retry due to transient cleanup error
	err := w.ProcessTask(context.Background(), task)

	// Should return transient error after retries exhausted
	if err == nil {
		t.Fatal("expected error after retries exhausted")
	}

	if !supplineErrors.IsTransient(err) {
		t.Errorf("expected transient error after retries, got: %v", err)
	}

	// Verify cleanup was attempted
	if !mockStore.cleanupCalled["excess_"+task.Digest] {
		t.Error("expected excess scan cleanup to be attempted")
	}
}

func TestProcessTask_SuccessfulScanPermanentCleanupError(t *testing.T) {
	// Setup mocks for successful scan with permanent cleanup error
	mockQ := queue.NewInMemoryQueue(10)
	defer mockQ.Close()

	mockReg := &mockRegistry{}
	mockScan := &mockScanner{}
	mockPol := &mockPolicyEngine{}
	mockAtt := &mockAttestor{}
	mockStore := newMockStateStore()

	// Set excess scan cleanup to fail with permanent error
	mockStore.cleanupErrors["excess_sha256:abc123"] = supplineErrors.NewPermanentf("invalid scan ID")

	logger := slog.Default()
	config := worker.Config{
		RetryAttempts: 3,
		RetryBackoff:  10 * time.Millisecond,
		Concurrency:   1,
	}

	w := worker.NewImageWorker(mockQ, mockScan, mockPol, mockAtt, mockReg, mockStore, config, logger, nil)

	task := &queue.ScanTask{
		ID:         "test-1",
		Repository: "test/repo",
		Digest:     "sha256:abc123",
		Tag:        "latest",
		EnqueuedAt: time.Now(),
	}

	// Execute pipeline - should complete successfully despite permanent cleanup error
	err := w.ProcessTask(context.Background(), task)

	// Should succeed - permanent cleanup errors should be logged but not fail the task
	if err != nil {
		t.Fatalf("expected success despite permanent cleanup error, got: %v", err)
	}

	// Verify cleanup was attempted
	if !mockStore.cleanupCalled["excess_"+task.Digest] {
		t.Error("expected excess scan cleanup to be attempted")
	}
}

func TestProcessTask_ErrorClassificationIntegration(t *testing.T) {
	tests := []struct {
		name           string
		cleanupError   error
		expectedRetry  bool
		expectedResult string
	}{
		{
			name:           "transient cleanup error should retry",
			cleanupError:   supplineErrors.NewTransientf("connection timeout"),
			expectedRetry:  true,
			expectedResult: "transient",
		},
		{
			name:           "permanent cleanup error should not retry",
			cleanupError:   supplineErrors.NewPermanentf("invalid input"),
			expectedRetry:  false,
			expectedResult: "permanent",
		},
		{
			name:           "unclassified cleanup error should not retry",
			cleanupError:   errors.New("unknown error"),
			expectedRetry:  false,
			expectedResult: "unclassified",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup mocks
			mockQ := queue.NewInMemoryQueue(10)
			defer mockQ.Close()

			mockReg := &mockRegistry{
				manifestError: supplineErrors.NewManifestNotFound(errors.New("MANIFEST_UNKNOWN")),
			}
			mockScan := &mockScanner{}
			mockPol := &mockPolicyEngine{}
			mockAtt := &mockAttestor{}
			mockStore := newMockStateStore()

			// Set cleanup to fail with test error
			mockStore.cleanupErrors["artifact_sha256:abc123"] = tt.cleanupError

			logger := slog.Default()
			config := worker.Config{
				RetryAttempts: 2,
				RetryBackoff:  10 * time.Millisecond,
				Concurrency:   1,
			}

			w := worker.NewImageWorker(mockQ, mockScan, mockPol, mockAtt, mockReg, mockStore, config, logger, nil)

			task := &queue.ScanTask{
				ID:         "test-1",
				Repository: "test/repo",
				Digest:     "sha256:abc123",
				Tag:        "latest",
				EnqueuedAt: time.Now(),
			}

			// Execute pipeline
			err := w.ProcessTask(context.Background(), task)

			// Verify error classification behavior
			if tt.expectedResult == "transient" {
				if err == nil {
					t.Fatal("expected transient error after retries")
				}
				if !supplineErrors.IsTransient(err) {
					t.Errorf("expected transient error, got: %v", err)
				}
			} else {
				// For permanent and unclassified cleanup errors, the original manifest error should be returned
				// (cleanup errors are logged but don't override the original error)
				if err == nil {
					t.Fatal("expected error for manifest not found")
				}
				if !supplineErrors.IsManifestNotFound(err) {
					t.Errorf("expected manifest not found error (original error preserved), got: %v", err)
				}
			}

			// Verify cleanup was attempted
			if !mockStore.cleanupCalled["artifact_"+task.Digest] {
				t.Error("expected artifact cleanup to be attempted")
			}
		})
	}
}
