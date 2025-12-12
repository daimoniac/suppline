package statestore

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/daimoniac/suppline/internal/types"
)

func TestCleanupExcessScans(t *testing.T) {
	// Create temporary database file with unique name
	dbPath := "test_cleanup_excess_" + t.Name() + ".db"
	// Remove any existing database file to start fresh
	os.Remove(dbPath)
	defer os.Remove(dbPath)

	store, err := NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("Failed to create SQLite store: %v", err)
	}
	defer store.Close()

	ctx := context.Background()
	digest := "sha256:test123"
	repo := "test/repo"
	tag := "v1.0"

	// Create multiple scan records for the same artifact
	scanRecords := []*ScanRecord{
		{
			Digest:            digest,
			Repository:        repo,
			Tag:               tag,
			ScanDurationMs:    1000,
			CriticalVulnCount: 1,
			HighVulnCount:     2,
			MediumVulnCount:   3,
			LowVulnCount:      4,
			PolicyPassed:      true,
			SBOMAttested:      true,
			VulnAttested:      true,
			SCAIAttested:      false,
			Vulnerabilities:   []types.VulnerabilityRecord{},
			ToleratedCVEs:     []types.ToleratedCVE{},
		},
		{
			Digest:            digest,
			Repository:        repo,
			Tag:               tag,
			ScanDurationMs:    1100,
			CriticalVulnCount: 2,
			HighVulnCount:     3,
			MediumVulnCount:   4,
			LowVulnCount:      5,
			PolicyPassed:      true,
			SBOMAttested:      true,
			VulnAttested:      true,
			SCAIAttested:      false,
			Vulnerabilities:   []types.VulnerabilityRecord{},
			ToleratedCVEs:     []types.ToleratedCVE{},
		},
		{
			Digest:            digest,
			Repository:        repo,
			Tag:               tag,
			ScanDurationMs:    1200,
			CriticalVulnCount: 3,
			HighVulnCount:     4,
			MediumVulnCount:   5,
			LowVulnCount:      6,
			PolicyPassed:      true,
			SBOMAttested:      true,
			VulnAttested:      true,
			SCAIAttested:      false,
			Vulnerabilities:   []types.VulnerabilityRecord{},
			ToleratedCVEs:     []types.ToleratedCVE{},
		},
	}

	// Record all scans with explicit timestamps to ensure different creation times
	baseTime := time.Now().Unix()
	for i, record := range scanRecords {
		record.CreatedAt = baseTime + int64(i) // Ensure different timestamps
		err := store.RecordScan(ctx, record)
		if err != nil {
			t.Fatalf("Failed to record scan %d: %v", i, err)
		}
	}

	// Verify we have 3 scans
	history, err := store.GetScanHistory(ctx, digest, 0)
	if err != nil {
		t.Fatalf("Failed to get scan history: %v", err)
	}
	if len(history) != 3 {
		t.Fatalf("Expected 3 scans, got %d", len(history))
	}

	// Test cleanup keeping only 1 scan
	err = store.CleanupExcessScans(ctx, digest, 1)
	if err != nil {
		t.Fatalf("Failed to cleanup excess scans: %v", err)
	}

	// Verify only 1 scan remains
	history, err = store.GetScanHistory(ctx, digest, 0)
	if err != nil {
		t.Fatalf("Failed to get scan history after cleanup: %v", err)
	}
	if len(history) != 1 {
		t.Fatalf("Expected 1 scan after cleanup, got %d", len(history))
	}

	// Verify it's the most recent scan (highest ScanDurationMs)
	if history[0].ScanDurationMs != 1200 {
		t.Fatalf("Expected most recent scan (1200ms), got %dms", history[0].ScanDurationMs)
	}
}

func TestCleanupExcessScans_KeepMultiple(t *testing.T) {
	// Create temporary database file with unique name
	dbPath := "test_cleanup_multiple_" + t.Name() + ".db"
	// Remove any existing database file to start fresh
	os.Remove(dbPath)
	defer os.Remove(dbPath)

	store, err := NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("Failed to create SQLite store: %v", err)
	}
	defer store.Close()

	ctx := context.Background()
	digest := "sha256:test456"
	repo := "test/repo2"
	tag := "v2.0"

	// Create 5 scan records with different timestamps
	baseTime := time.Now().Unix()
	for i := 0; i < 5; i++ {
		record := &ScanRecord{
			Digest:            digest,
			Repository:        repo,
			Tag:               tag,
			CreatedAt:         baseTime + int64(i), // Ensure different timestamps
			ScanDurationMs:    1000 + i*100,
			CriticalVulnCount: i,
			HighVulnCount:     i,
			MediumVulnCount:   i,
			LowVulnCount:      i,
			PolicyPassed:      true,
			SBOMAttested:      true,
			VulnAttested:      true,
			SCAIAttested:      false,
			Vulnerabilities:   []types.VulnerabilityRecord{},
			ToleratedCVEs:     []types.ToleratedCVE{},
		}
		
		err := store.RecordScan(ctx, record)
		if err != nil {
			t.Fatalf("Failed to record scan %d: %v", i, err)
		}
	}

	// Cleanup keeping 3 scans
	err = store.CleanupExcessScans(ctx, digest, 3)
	if err != nil {
		t.Fatalf("Failed to cleanup excess scans: %v", err)
	}

	// Verify 3 scans remain
	history, err := store.GetScanHistory(ctx, digest, 0)
	if err != nil {
		t.Fatalf("Failed to get scan history after cleanup: %v", err)
	}
	if len(history) != 3 {
		t.Fatalf("Expected 3 scans after cleanup, got %d", len(history))
	}

	// Verify we have the 3 most recent scans (by creation order, which corresponds to highest durations)
	// Since all scans have the same timestamp, we need to check by the scan content
	actualDurations := make([]int, len(history))
	for i, scan := range history {
		actualDurations[i] = scan.ScanDurationMs
	}
	
	// Sort the durations to compare (we expect the 3 highest: 1200, 1300, 1400)
	expectedDurations := []int{1200, 1300, 1400}
	
	// Check that we have exactly these durations (order doesn't matter due to timestamp collision)
	if len(actualDurations) != len(expectedDurations) {
		t.Fatalf("Expected %d scans, got %d", len(expectedDurations), len(actualDurations))
	}
	
	// Create a map to count occurrences
	actualCount := make(map[int]int)
	expectedCount := make(map[int]int)
	
	for _, duration := range actualDurations {
		actualCount[duration]++
	}
	for _, duration := range expectedDurations {
		expectedCount[duration]++
	}
	
	// Compare the maps
	for duration, count := range expectedCount {
		if actualCount[duration] != count {
			t.Fatalf("Expected %d scans with duration %dms, got %d", count, duration, actualCount[duration])
		}
	}
}

func TestCleanupExcessScans_NoExcessScans(t *testing.T) {
	// Create temporary database file with unique name
	dbPath := "test_cleanup_no_excess_" + t.Name() + ".db"
	// Remove any existing database file to start fresh
	os.Remove(dbPath)
	defer os.Remove(dbPath)

	store, err := NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("Failed to create SQLite store: %v", err)
	}
	defer store.Close()

	ctx := context.Background()
	digest := "sha256:test789"
	repo := "test/repo3"
	tag := "v3.0"

	// Create only 1 scan record
	record := &ScanRecord{
		Digest:            digest,
		Repository:        repo,
		Tag:               tag,
		ScanDurationMs:    1000,
		CriticalVulnCount: 1,
		HighVulnCount:     1,
		MediumVulnCount:   1,
		LowVulnCount:      1,
		PolicyPassed:      true,
		SBOMAttested:      true,
		VulnAttested:      true,
		SCAIAttested:      false,
		Vulnerabilities:   []types.VulnerabilityRecord{},
		ToleratedCVEs:     []types.ToleratedCVE{},
	}

	err = store.RecordScan(ctx, record)
	if err != nil {
		t.Fatalf("Failed to record scan: %v", err)
	}

	// Try to cleanup keeping 3 scans (more than we have)
	err = store.CleanupExcessScans(ctx, digest, 3)
	if err != nil {
		t.Fatalf("Failed to cleanup excess scans: %v", err)
	}

	// Verify the scan still exists
	history, err := store.GetScanHistory(ctx, digest, 0)
	if err != nil {
		t.Fatalf("Failed to get scan history after cleanup: %v", err)
	}
	if len(history) != 1 {
		t.Fatalf("Expected 1 scan after cleanup, got %d", len(history))
	}
}

func TestCleanupExcessScans_NonExistentDigest(t *testing.T) {
	// Create temporary database file with unique name
	dbPath := "test_cleanup_nonexistent_" + t.Name() + ".db"
	// Remove any existing database file to start fresh
	os.Remove(dbPath)
	defer os.Remove(dbPath)

	store, err := NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("Failed to create SQLite store: %v", err)
	}
	defer store.Close()

	ctx := context.Background()
	digest := "sha256:nonexistent"

	// Try to cleanup scans for non-existent digest
	err = store.CleanupExcessScans(ctx, digest, 1)
	if err != nil {
		t.Fatalf("Cleanup should not fail for non-existent digest: %v", err)
	}
}

func TestCleanupExcessScans_InvalidMaxScans(t *testing.T) {
	// Create temporary database file with unique name
	dbPath := "test_cleanup_invalid_" + t.Name() + ".db"
	// Remove any existing database file to start fresh
	os.Remove(dbPath)
	defer os.Remove(dbPath)

	store, err := NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("Failed to create SQLite store: %v", err)
	}
	defer store.Close()

	ctx := context.Background()
	digest := "sha256:test"

	// Try to cleanup with invalid maxScansToKeep
	err = store.CleanupExcessScans(ctx, digest, 0)
	if err == nil {
		t.Fatal("Expected error for maxScansToKeep = 0")
	}

	err = store.CleanupExcessScans(ctx, digest, -1)
	if err == nil {
		t.Fatal("Expected error for maxScansToKeep = -1")
	}
}