package watcher

import (
	"context"
	"fmt"
	"github.com/suppline/suppline/internal/types"
	"testing"
	"time"

	"github.com/suppline/suppline/internal/config"
	"github.com/suppline/suppline/internal/observability"
	"github.com/suppline/suppline/internal/queue"
	"github.com/suppline/suppline/internal/registry"
	"github.com/suppline/suppline/internal/statestore"
)

// Mock implementations for testing

type mockRegistryClient struct {
	repositories []string
	tags         map[string][]string
	digests      map[string]string // repo:tag -> digest
	err          error
}

func (m *mockRegistryClient) ListRepositories(ctx context.Context) ([]string, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.repositories, nil
}

func (m *mockRegistryClient) ListTags(ctx context.Context, repo string) ([]string, error) {
	if m.err != nil {
		return nil, m.err
	}
	if tags, ok := m.tags[repo]; ok {
		return tags, nil
	}
	return []string{}, nil
}

func (m *mockRegistryClient) GetDigest(ctx context.Context, repo, tag string) (string, error) {
	if m.err != nil {
		return "", m.err
	}
	key := fmt.Sprintf("%s:%s", repo, tag)
	if digest, ok := m.digests[key]; ok {
		return digest, nil
	}
	return fmt.Sprintf("sha256:mock%s%s", repo, tag), nil
}

func (m *mockRegistryClient) GetManifest(ctx context.Context, repo, digest string) (*registry.Manifest, error) {
	return nil, fmt.Errorf("not implemented")
}

type mockStateStore struct {
	scans        map[string]*statestore.ScanRecord
	dueForRescan []string
	err          error
}

func (m *mockStateStore) RecordScan(ctx context.Context, record *statestore.ScanRecord) error {
	if m.err != nil {
		return m.err
	}
	if m.scans == nil {
		m.scans = make(map[string]*statestore.ScanRecord)
	}
	m.scans[record.Digest] = record
	return nil
}

func (m *mockStateStore) GetLastScan(ctx context.Context, digest string) (*statestore.ScanRecord, error) {
	if m.err != nil {
		return nil, m.err
	}
	if scan, ok := m.scans[digest]; ok {
		return scan, nil
	}
	return nil, statestore.ErrScanNotFound
}

// mockStateStore only implements the core StateStore interface
// since the watcher doesn't need query methods

func TestWatcher_Discover_NewImages(t *testing.T) {
	ctx := context.Background()

	// Setup mock registry with new images
	mockRegistry := &mockRegistryClient{
		repositories: []string{"myorg/app1", "myorg/app2"},
		tags: map[string][]string{
			"myorg/app1": {"v1.0", "v1.1"},
			"myorg/app2": {"latest"},
		},
		digests: map[string]string{
			"myorg/app1:v1.0":   "sha256:digest1",
			"myorg/app1:v1.1":   "sha256:digest2",
			"myorg/app2:latest": "sha256:digest3",
		},
	}

	// Setup mock state store with no previous scans
	mockStore := &mockStateStore{
		scans: make(map[string]*statestore.ScanRecord),
	}

	// Setup mock queue
	mockQueue := queue.NewInMemoryQueue(100)

	// Setup regsync config with tolerations
	expiresAt := time.Now().Add(30 * 24 * time.Hour)
	regsyncCfg := &config.RegsyncConfig{
		Sync: []config.SyncEntry{
			{
				Target: "myorg/app1",
				Tolerate: []types.CVEToleration{
					{ID: "CVE-2024-1234", Statement: "test toleration", ExpiresAt: &expiresAt},
				},
			},
			{
				Target: "myorg/app2",
			},
		},
	}

	// Create watcher
	logger := observability.NewLogger("error") // Use error level to reduce test output
	w := NewWatcher(mockRegistry, regsyncCfg, mockStore, mockQueue, Config{
		PollInterval:   5 * time.Second,
		RescanInterval: 24 * time.Hour,
	}, logger)

	// Run discovery
	err := w.Discover(ctx)
	if err != nil {
		t.Fatalf("Discover failed: %v", err)
	}

	// Verify tasks were enqueued
	queueDepth, _ := mockQueue.GetQueueDepth(ctx)
	if queueDepth != 3 {
		t.Errorf("Expected 3 tasks in queue, got %d", queueDepth)
	}

	// Dequeue and verify tasks
	task1, _ := mockQueue.Dequeue(ctx)
	if task1.Repository != "myorg/app1" {
		t.Errorf("Expected repository myorg/app1, got %s", task1.Repository)
	}
	if task1.IsRescan {
		t.Error("Expected IsRescan to be false for new image")
	}
	if len(task1.Tolerations) != 1 {
		t.Errorf("Expected 1 toleration, got %d", len(task1.Tolerations))
	}

	task2, _ := mockQueue.Dequeue(ctx)
	if task2.Repository != "myorg/app1" {
		t.Errorf("Expected repository myorg/app1, got %s", task2.Repository)
	}

	task3, _ := mockQueue.Dequeue(ctx)
	if task3.Repository != "myorg/app2" {
		t.Errorf("Expected repository myorg/app2, got %s", task3.Repository)
	}
	if len(task3.Tolerations) != 0 {
		t.Errorf("Expected 0 tolerations for app2, got %d", len(task3.Tolerations))
	}
}

func TestWatcher_Discover_RescanDue(t *testing.T) {
	ctx := context.Background()

	// Setup mock registry
	mockRegistry := &mockRegistryClient{
		repositories: []string{"myorg/app1"},
		tags: map[string][]string{
			"myorg/app1": {"v1.0"},
		},
		digests: map[string]string{
			"myorg/app1:v1.0": "sha256:digest1",
		},
	}

	// Setup mock state store with old scan
	oldScanTime := time.Now().Add(-25 * time.Hour) // 25 hours ago
	mockStore := &mockStateStore{
		scans: map[string]*statestore.ScanRecord{
			"sha256:digest1": {
				Digest:     "sha256:digest1",
				Repository: "myorg/app1",
				Tag:        "v1.0",
				ScannedAt:  oldScanTime,
			},
		},
	}

	// Setup mock queue
	mockQueue := queue.NewInMemoryQueue(100)

	// Setup regsync config with 24 hour rescan interval
	regsyncCfg := &config.RegsyncConfig{
		Defaults: config.Defaults{
			RescanInterval: "24h",
		},
		Sync: []config.SyncEntry{
			{Target: "myorg/app1"},
		},
	}

	// Create watcher
	logger := observability.NewLogger("error") // Use error level to reduce test output
	w := NewWatcher(mockRegistry, regsyncCfg, mockStore, mockQueue, Config{
		PollInterval:   5 * time.Second,
		RescanInterval: 24 * time.Hour,
	}, logger)

	// Run discovery
	err := w.Discover(ctx)
	if err != nil {
		t.Fatalf("Discover failed: %v", err)
	}

	// Verify rescan task was enqueued
	queueDepth, _ := mockQueue.GetQueueDepth(ctx)
	if queueDepth != 1 {
		t.Errorf("Expected 1 task in queue, got %d", queueDepth)
	}

	task, _ := mockQueue.Dequeue(ctx)
	if !task.IsRescan {
		t.Error("Expected IsRescan to be true for old image")
	}
	if task.Digest != "sha256:digest1" {
		t.Errorf("Expected digest sha256:digest1, got %s", task.Digest)
	}
}

func TestWatcher_Discover_SkipRecentScan(t *testing.T) {
	ctx := context.Background()

	// Setup mock registry
	mockRegistry := &mockRegistryClient{
		repositories: []string{"myorg/app1"},
		tags: map[string][]string{
			"myorg/app1": {"v1.0"},
		},
		digests: map[string]string{
			"myorg/app1:v1.0": "sha256:digest1",
		},
	}

	// Setup mock state store with recent scan
	recentScanTime := time.Now().Add(-1 * time.Hour) // 1 hour ago
	mockStore := &mockStateStore{
		scans: map[string]*statestore.ScanRecord{
			"sha256:digest1": {
				Digest:     "sha256:digest1",
				Repository: "myorg/app1",
				Tag:        "v1.0",
				ScannedAt:  recentScanTime,
			},
		},
	}

	// Setup mock queue
	mockQueue := queue.NewInMemoryQueue(100)

	// Setup regsync config
	regsyncCfg := &config.RegsyncConfig{
		Sync: []config.SyncEntry{
			{Target: "myorg/app1"},
		},
	}

	// Create watcher with 24 hour rescan interval
	logger := observability.NewLogger("error") // Use error level to reduce test output
	w := NewWatcher(mockRegistry, regsyncCfg, mockStore, mockQueue, Config{
		PollInterval:   5 * time.Second,
		RescanInterval: 24 * time.Hour,
	}, logger)

	// Run discovery
	err := w.Discover(ctx)
	if err != nil {
		t.Fatalf("Discover failed: %v", err)
	}

	// Verify no tasks were enqueued
	queueDepth, _ := mockQueue.GetQueueDepth(ctx)
	if queueDepth != 0 {
		t.Errorf("Expected 0 tasks in queue, got %d", queueDepth)
	}
}

func TestWatcher_Discover_Deduplication(t *testing.T) {
	ctx := context.Background()

	// Setup mock registry with same digest for multiple tags
	mockRegistry := &mockRegistryClient{
		repositories: []string{"myorg/app1"},
		tags: map[string][]string{
			"myorg/app1": {"v1.0", "latest"},
		},
		digests: map[string]string{
			"myorg/app1:v1.0":   "sha256:samedigest",
			"myorg/app1:latest": "sha256:samedigest",
		},
	}

	// Setup mock state store
	mockStore := &mockStateStore{
		scans: make(map[string]*statestore.ScanRecord),
	}

	// Setup mock queue
	mockQueue := queue.NewInMemoryQueue(100)

	// Setup regsync config
	regsyncCfg := &config.RegsyncConfig{
		Sync: []config.SyncEntry{
			{Target: "myorg/app1"},
		},
	}

	// Create watcher
	logger := observability.NewLogger("error") // Use error level to reduce test output
	w := NewWatcher(mockRegistry, regsyncCfg, mockStore, mockQueue, Config{
		PollInterval:   5 * time.Second,
		RescanInterval: 24 * time.Hour,
	}, logger)

	// Run discovery
	err := w.Discover(ctx)
	if err != nil {
		t.Fatalf("Discover failed: %v", err)
	}

	// Verify only one task was enqueued (deduplication by digest)
	queueDepth, _ := mockQueue.GetQueueDepth(ctx)
	if queueDepth != 1 {
		t.Errorf("Expected 1 task in queue due to deduplication, got %d", queueDepth)
	}

	// Verify the metrics show one was dropped
	metrics := mockQueue.GetMetrics()
	if metrics.Dropped != 1 {
		t.Errorf("Expected 1 dropped task, got %d", metrics.Dropped)
	}
}

func TestWatcher_Discover_ErrorHandling(t *testing.T) {
	ctx := context.Background()

	// Setup mock registry that returns error
	mockRegistry := &mockRegistryClient{
		err: fmt.Errorf("registry connection failed"),
	}

	// Setup mock state store
	mockStore := &mockStateStore{
		scans: make(map[string]*statestore.ScanRecord),
	}

	// Setup mock queue
	mockQueue := queue.NewInMemoryQueue(100)

	// Setup regsync config
	regsyncCfg := &config.RegsyncConfig{
		Sync: []config.SyncEntry{
			{Target: "myorg/app1"},
		},
	}

	// Create watcher
	logger := observability.NewLogger("error") // Use error level to reduce test output
	w := NewWatcher(mockRegistry, regsyncCfg, mockStore, mockQueue, Config{
		PollInterval:   5 * time.Second,
		RescanInterval: 24 * time.Hour,
	}, logger)

	// Run discovery - should return error
	err := w.Discover(ctx)
	if err == nil {
		t.Error("Expected error from Discover, got nil")
	}

	// Verify no tasks were enqueued
	queueDepth, _ := mockQueue.GetQueueDepth(ctx)
	if queueDepth != 0 {
		t.Errorf("Expected 0 tasks in queue, got %d", queueDepth)
	}
}

// Test shouldScanImage with never scanned case
func TestShouldScanImage_NeverScanned(t *testing.T) {
	ctx := context.Background()

	// Setup mock state store with no scans
	mockStore := &mockStateStore{
		scans: make(map[string]*statestore.ScanRecord),
	}

	// Setup mock registry and queue (not used in this test)
	mockRegistry := &mockRegistryClient{}
	mockQueue := queue.NewInMemoryQueue(100)
	regsyncCfg := &config.RegsyncConfig{}

	// Create watcher
	logger := observability.NewLogger("error")
	w := &watcherImpl{
		registryClient: mockRegistry,
		regsyncConfig:  regsyncCfg,
		stateStore:     mockStore,
		taskQueue:      mockQueue,
		logger:         logger,
	}

	// Test shouldScanImage
	shouldScan, reason, isRescan, err := w.shouldScanImage(
		ctx,
		"myorg/app1",
		"v1.0",
		"sha256:newdigest",
		24*time.Hour,
	)

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if !shouldScan {
		t.Error("Expected shouldScan to be true for never scanned image")
	}
	if reason != "never scanned before" {
		t.Errorf("Expected reason 'never scanned before', got %q", reason)
	}
	if isRescan {
		t.Error("Expected isRescan to be false for never scanned image")
	}
}

// Test shouldScanImage with digest changed case
func TestShouldScanImage_DigestChanged(t *testing.T) {
	ctx := context.Background()

	// Setup mock state store with scan for new digest that has wrong digest in record
	// This simulates the case where we query by current digest but the stored record
	// has a different digest (which shouldn't happen in practice, but tests the logic)
	oldScanTime := time.Now().Add(-1 * time.Hour)
	mockStore := &mockStateStore{
		scans: map[string]*statestore.ScanRecord{
			"sha256:newdigest": {
				Digest:     "sha256:olddigest", // Different digest in record
				Repository: "myorg/app1",
				Tag:        "v1.0",
				ScannedAt:  oldScanTime,
			},
		},
	}

	// Setup mock registry and queue (not used in this test)
	mockRegistry := &mockRegistryClient{}
	mockQueue := queue.NewInMemoryQueue(100)
	regsyncCfg := &config.RegsyncConfig{}

	// Create watcher
	logger := observability.NewLogger("error")
	w := &watcherImpl{
		registryClient: mockRegistry,
		regsyncConfig:  regsyncCfg,
		stateStore:     mockStore,
		taskQueue:      mockQueue,
		logger:         logger,
	}

	// Test shouldScanImage with different digest
	shouldScan, reason, isRescan, err := w.shouldScanImage(
		ctx,
		"myorg/app1",
		"v1.0",
		"sha256:newdigest",
		24*time.Hour,
	)

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if !shouldScan {
		t.Error("Expected shouldScan to be true for changed digest")
	}
	if reason != "digest changed since last scan" {
		t.Errorf("Expected reason 'digest changed since last scan', got %q", reason)
	}
	if isRescan {
		t.Error("Expected isRescan to be false for digest change")
	}
}

// Test shouldScanImage with interval elapsed case
func TestShouldScanImage_IntervalElapsed(t *testing.T) {
	ctx := context.Background()

	// Setup mock state store with old scan (25 hours ago)
	oldScanTime := time.Now().Add(-25 * time.Hour)
	mockStore := &mockStateStore{
		scans: map[string]*statestore.ScanRecord{
			"sha256:samedigest": {
				Digest:     "sha256:samedigest",
				Repository: "myorg/app1",
				Tag:        "v1.0",
				ScannedAt:  oldScanTime,
			},
		},
	}

	// Setup mock registry and queue (not used in this test)
	mockRegistry := &mockRegistryClient{}
	mockQueue := queue.NewInMemoryQueue(100)
	regsyncCfg := &config.RegsyncConfig{}

	// Create watcher
	logger := observability.NewLogger("error")
	w := &watcherImpl{
		registryClient: mockRegistry,
		regsyncConfig:  regsyncCfg,
		stateStore:     mockStore,
		taskQueue:      mockQueue,
		logger:         logger,
	}

	// Test shouldScanImage with elapsed interval (24 hours)
	shouldScan, reason, isRescan, err := w.shouldScanImage(
		ctx,
		"myorg/app1",
		"v1.0",
		"sha256:samedigest",
		24*time.Hour,
	)

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if !shouldScan {
		t.Error("Expected shouldScan to be true for elapsed interval")
	}
	if reason == "" {
		t.Error("Expected reason to be set for elapsed interval")
	}
	if !isRescan {
		t.Error("Expected isRescan to be true for elapsed interval")
	}
}

// Test shouldScanImage with skip case (digest matches, interval not elapsed)
func TestShouldScanImage_Skip(t *testing.T) {
	ctx := context.Background()

	// Setup mock state store with recent scan (1 hour ago)
	recentScanTime := time.Now().Add(-1 * time.Hour)
	mockStore := &mockStateStore{
		scans: map[string]*statestore.ScanRecord{
			"sha256:samedigest": {
				Digest:     "sha256:samedigest",
				Repository: "myorg/app1",
				Tag:        "v1.0",
				ScannedAt:  recentScanTime,
			},
		},
	}

	// Setup mock registry and queue (not used in this test)
	mockRegistry := &mockRegistryClient{}
	mockQueue := queue.NewInMemoryQueue(100)
	regsyncCfg := &config.RegsyncConfig{}

	// Create watcher
	logger := observability.NewLogger("error")
	w := &watcherImpl{
		registryClient: mockRegistry,
		regsyncConfig:  regsyncCfg,
		stateStore:     mockStore,
		taskQueue:      mockQueue,
		logger:         logger,
	}

	// Test shouldScanImage with matching digest and interval not elapsed
	shouldScan, reason, isRescan, err := w.shouldScanImage(
		ctx,
		"myorg/app1",
		"v1.0",
		"sha256:samedigest",
		24*time.Hour,
	)

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if shouldScan {
		t.Error("Expected shouldScan to be false for recent scan with matching digest")
	}
	if reason == "" {
		t.Error("Expected reason to be set for skip decision")
	}
	if isRescan {
		t.Error("Expected isRescan to be false for skip decision")
	}
}

// Test shouldScanImage error handling
func TestShouldScanImage_ErrorHandling(t *testing.T) {
	ctx := context.Background()

	// Setup mock state store that returns error
	mockStore := &mockStateStore{
		err: fmt.Errorf("database connection failed"),
	}

	// Setup mock registry and queue (not used in this test)
	mockRegistry := &mockRegistryClient{}
	mockQueue := queue.NewInMemoryQueue(100)
	regsyncCfg := &config.RegsyncConfig{}

	// Create watcher
	logger := observability.NewLogger("error")
	w := &watcherImpl{
		registryClient: mockRegistry,
		regsyncConfig:  regsyncCfg,
		stateStore:     mockStore,
		taskQueue:      mockQueue,
		logger:         logger,
	}

	// Test shouldScanImage with state store error
	shouldScan, reason, isRescan, err := w.shouldScanImage(
		ctx,
		"myorg/app1",
		"v1.0",
		"sha256:digest",
		24*time.Hour,
	)

	if err == nil {
		t.Error("Expected error from shouldScanImage")
	}
	if shouldScan {
		t.Error("Expected shouldScan to be false when error occurs")
	}
	if reason != "" {
		t.Error("Expected reason to be empty when error occurs")
	}
	if isRescan {
		t.Error("Expected isRescan to be false when error occurs")
	}
}

// Test processTag fail-safe behavior on shouldScanImage error
func TestProcessTag_FailSafeBehavior(t *testing.T) {
	ctx := context.Background()

	// Setup mock registry
	mockRegistry := &mockRegistryClient{
		digests: map[string]string{
			"myorg/app1:v1.0": "sha256:digest1",
		},
	}

	// Setup mock state store that returns error
	mockStore := &mockStateStore{
		err: fmt.Errorf("database connection failed"),
	}

	// Setup mock queue
	mockQueue := queue.NewInMemoryQueue(100)

	// Setup regsync config
	regsyncCfg := &config.RegsyncConfig{
		Sync: []config.SyncEntry{
			{Target: "myorg/app1"},
		},
	}

	// Create watcher
	logger := observability.NewLogger("error")
	w := &watcherImpl{
		registryClient: mockRegistry,
		regsyncConfig:  regsyncCfg,
		stateStore:     mockStore,
		taskQueue:      mockQueue,
		logger:         logger,
	}

	// Process tag - should enqueue despite error (fail-safe)
	err := w.processTag(ctx, "myorg/app1", "v1.0", nil)
	if err != nil {
		t.Fatalf("processTag failed: %v", err)
	}

	// Verify task was enqueued (fail-safe behavior)
	queueDepth, _ := mockQueue.GetQueueDepth(ctx)
	if queueDepth != 1 {
		t.Errorf("Expected 1 task in queue (fail-safe), got %d", queueDepth)
	}

	// Verify task details
	task, _ := mockQueue.Dequeue(ctx)
	if task.IsRescan {
		t.Error("Expected IsRescan to be false for fail-safe enqueue")
	}
}
