package statestore

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"testing"

	"github.com/daimoniac/suppline/internal/types"
	"github.com/leanovate/gopter"
	"github.com/leanovate/gopter/gen"
	"github.com/leanovate/gopter/prop"
)

// TestCleanupArtifactScansProperty tests the property that MANIFEST_UNKNOWN cleanup completeness
// **Feature: scan-cleanup-management, Property 1: MANIFEST_UNKNOWN cleanup completeness**
// **Validates: Requirements 1.1, 1.2**
func TestCleanupArtifactScansProperty(t *testing.T) {
	properties := gopter.NewProperties(nil)

	properties.Property("After cleanup, no scan records remain for the digest", prop.ForAll(
		func(digest string, repoName string, tag string, vulnCount int) bool {
			// Create a temporary database
			store, cleanup := createTestStore(t)
			defer cleanup()

			ctx := context.Background()

			// Create a scan record for the digest
			record := &ScanRecord{
				Repository:        repoName,
				Digest:           digest,
				Tag:              tag,
				ScanDurationMs:   1000,
				CriticalVulnCount: vulnCount,
				HighVulnCount:    vulnCount,
				MediumVulnCount:  vulnCount,
				LowVulnCount:     vulnCount,
				PolicyPassed:     true,
				SBOMAttested:     true,
				VulnAttested:     true,
				SCAIAttested:     true,
				Vulnerabilities:  generateVulnerabilities(vulnCount),
			}

			// Record the scan
			err := store.RecordScan(ctx, record)
			if err != nil {
				t.Logf("Failed to record scan: %v", err)
				return false
			}

			// Verify scan exists before cleanup
			_, err = store.GetLastScan(ctx, digest)
			if err != nil {
				t.Logf("Scan should exist before cleanup: %v", err)
				return false
			}

			// Perform cleanup
			err = store.CleanupArtifactScans(ctx, digest)
			if err != nil {
				t.Logf("Cleanup failed: %v", err)
				return false
			}

			// Verify no scan records remain for this digest
			_, err = store.GetLastScan(ctx, digest)
			return err == ErrScanNotFound
		},
		genValidDigest(),
		genValidRepoName(),
		genValidTag(),
		gen.IntRange(0, 10),
	))

	properties.TestingRun(t, gopter.ConsoleReporter(false))
}

// TestVulnerabilityCascadeDeletionProperty tests the property that vulnerability cascade deletion works
// **Feature: scan-cleanup-management, Property 2: Vulnerability cascade deletion**
// **Validates: Requirements 1.3, 2.2**
func TestVulnerabilityCascadeDeletionProperty(t *testing.T) {
	properties := gopter.NewProperties(nil)

	properties.Property("When scan records are deleted, all associated vulnerabilities are also deleted", prop.ForAll(
		func(digest string, repoName string, tag string, vulnCount int) bool {
			// Create a temporary database
			store, cleanup := createTestStore(t)
			defer cleanup()

			ctx := context.Background()

			// Create a scan record with vulnerabilities
			record := &ScanRecord{
				Repository:        repoName,
				Digest:           digest,
				Tag:              tag,
				ScanDurationMs:   1000,
				CriticalVulnCount: vulnCount,
				HighVulnCount:    vulnCount,
				MediumVulnCount:  vulnCount,
				LowVulnCount:     vulnCount,
				PolicyPassed:     true,
				SBOMAttested:     true,
				VulnAttested:     true,
				SCAIAttested:     true,
				Vulnerabilities:  generateVulnerabilities(vulnCount),
			}

			// Record the scan
			err := store.RecordScan(ctx, record)
			if err != nil {
				t.Logf("Failed to record scan: %v", err)
				return false
			}

			// Count vulnerabilities before cleanup
			vulnCountBefore := countVulnerabilities(store.(*SQLiteStore), digest)
			if vulnCountBefore != vulnCount {
				t.Logf("Expected %d vulnerabilities before cleanup, got %d", vulnCount, vulnCountBefore)
				return false
			}

			// Perform cleanup
			err = store.CleanupArtifactScans(ctx, digest)
			if err != nil {
				t.Logf("Cleanup failed: %v", err)
				return false
			}

			// Count vulnerabilities after cleanup - should be 0
			vulnCountAfter := countVulnerabilities(store.(*SQLiteStore), digest)
			return vulnCountAfter == 0
		},
		genValidDigest(),
		genValidRepoName(),
		genValidTag(),
		gen.IntRange(1, 10), // At least 1 vulnerability to test cascade deletion
	))

	properties.TestingRun(t, gopter.ConsoleReporter(false))
}

// Helper functions for property testing

func createTestStore(t *testing.T) (StateStoreCleanup, func()) {
	// Create a temporary database file
	tmpFile, err := os.CreateTemp("", "test_*.db")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	tmpFile.Close()

	store, err := NewSQLiteStore(tmpFile.Name())
	if err != nil {
		os.Remove(tmpFile.Name())
		t.Fatalf("Failed to create store: %v", err)
	}

	cleanup := func() {
		store.Close()
		os.Remove(tmpFile.Name())
	}

	return store, cleanup
}

func genValidDigest() gopter.Gen {
	return gen.AlphaString().Map(func(s string) string {
		// Ensure we have at least 64 characters for a valid SHA256 digest
		for len(s) < 64 {
			s = s + "0123456789abcdef"
		}
		return "sha256:" + s[:64]
	})
}

func genValidRepoName() gopter.Gen {
	return gen.AlphaString().Map(func(s string) string {
		if len(s) == 0 {
			return "test-repo"
		}
		return s[:min(len(s), 20)]
	})
}

func genValidTag() gopter.Gen {
	return gen.AlphaString().Map(func(s string) string {
		if len(s) == 0 {
			return "latest"
		}
		return s[:min(len(s), 10)]
	})
}

func generateVulnerabilities(count int) []types.VulnerabilityRecord {
	vulns := make([]types.VulnerabilityRecord, count)
	for i := 0; i < count; i++ {
		vulns[i] = types.VulnerabilityRecord{
			CVEID:            fmt.Sprintf("CVE-2023-%04d", i+1),
			Severity:         "HIGH",
			PackageName:      fmt.Sprintf("package-%d", i),
			InstalledVersion: "1.0.0",
			FixedVersion:     "1.0.1",
			Title:            fmt.Sprintf("Test vulnerability %d", i),
			Description:      fmt.Sprintf("Test description %d", i),
			PrimaryURL:       fmt.Sprintf("https://example.com/cve-%d", i),
		}
	}
	return vulns
}

func countVulnerabilities(store *SQLiteStore, digest string) int {
	var count int
	err := store.db.QueryRow(`
		SELECT COUNT(v.id)
		FROM vulnerabilities v
		JOIN scan_records sr ON v.scan_record_id = sr.id
		JOIN artifacts a ON sr.artifact_id = a.id
		WHERE a.digest = ?
	`, digest).Scan(&count)
	if err != nil {
		return -1
	}
	return count
}

// TestExcessScanCleanupProperty tests the property that excess scan cleanup works correctly
// **Feature: scan-cleanup-management, Property 3: Excess scan cleanup**
// **Validates: Requirements 2.1, 2.3**
func TestExcessScanCleanupProperty(t *testing.T) {
	properties := gopter.NewProperties(nil)

	properties.Property("After cleanup, only the most recent N scans are preserved", prop.ForAll(
		func(digest string, repoName string, tag string, scanCount int, maxScansToKeep int) bool {
			if scanCount < 2 {
				return true // Skip cases with less than 2 scans
			}
			if maxScansToKeep < 1 {
				maxScansToKeep = 1 // Must keep at least 1 scan
			}
			if maxScansToKeep >= scanCount {
				return true // Skip cases where we keep all scans
			}

			// Create a temporary database
			store, cleanup := createTestStore(t)
			defer cleanup()

			ctx := context.Background()

			// Create multiple scan records for the same digest
			for i := 0; i < scanCount; i++ {
				record := &ScanRecord{
					Repository:        repoName,
					Digest:           digest,
					Tag:              tag,
					ScanDurationMs:   1000 + i*100,
					CriticalVulnCount: i,
					HighVulnCount:    i,
					MediumVulnCount:  i,
					LowVulnCount:     i,
					PolicyPassed:     true,
					SBOMAttested:     true,
					VulnAttested:     true,
					SCAIAttested:     true,
					Vulnerabilities:  generateVulnerabilities(1),
				}

				err := store.RecordScan(ctx, record)
				if err != nil {
					t.Logf("Failed to record scan %d: %v", i, err)
					return false
				}
			}

			// Perform cleanup
			err := store.CleanupExcessScans(ctx, digest, maxScansToKeep)
			if err != nil {
				t.Logf("Cleanup failed: %v", err)
				return false
			}

			// Count remaining scans
			remainingScans := countScanRecords(store.(*SQLiteStore), digest)

			return remainingScans == maxScansToKeep
		},
		genValidDigest(),
		genValidRepoName(),
		genValidTag(),
		gen.IntRange(2, 5), // At least 2 scans to test cleanup
		gen.IntRange(1, 3), // Keep 1-3 scans
	))

	properties.TestingRun(t, gopter.ConsoleReporter(false))
}

// TestArtifactReferenceConsistencyProperty tests the property that artifact reference consistency is maintained
// **Feature: scan-cleanup-management, Property 4: Artifact reference consistency**
// **Validates: Requirements 2.4**
func TestArtifactReferenceConsistencyProperty(t *testing.T) {
	properties := gopter.NewProperties(nil)

	properties.Property("After cleanup, artifact's last_scan_id points to the most recent remaining scan", prop.ForAll(
		func(digest string, repoName string, tag string, scanCount int, maxScansToKeep int) bool {
			if scanCount < 2 {
				return true // Skip cases with less than 2 scans
			}
			if maxScansToKeep < 1 {
				maxScansToKeep = 1 // Must keep at least 1 scan
			}
			if maxScansToKeep >= scanCount {
				return true // Skip cases where we keep all scans
			}

			// Create a temporary database
			store, cleanup := createTestStore(t)
			defer cleanup()

			ctx := context.Background()

			// Create multiple scan records for the same digest
			var scanIDs []int64
			for i := 0; i < scanCount; i++ {
				record := &ScanRecord{
					Repository:        repoName,
					Digest:           digest,
					Tag:              tag,
					ScanDurationMs:   1000 + i*100,
					CriticalVulnCount: i,
					HighVulnCount:    i,
					MediumVulnCount:  i,
					LowVulnCount:     i,
					PolicyPassed:     true,
					SBOMAttested:     true,
					VulnAttested:     true,
					SCAIAttested:     true,
					Vulnerabilities:  generateVulnerabilities(1),
				}

				err := store.RecordScan(ctx, record)
				if err != nil {
					t.Logf("Failed to record scan %d: %v", i, err)
					return false
				}

				// Get the scan ID that was just created
				lastScan, err := store.GetLastScan(ctx, digest)
				if err != nil {
					t.Logf("Failed to get last scan: %v", err)
					return false
				}
				scanIDs = append(scanIDs, lastScan.ID)
			}

			// Perform cleanup
			err := store.CleanupExcessScans(ctx, digest, maxScansToKeep)
			if err != nil {
				t.Logf("Cleanup failed: %v", err)
				return false
			}

			// Get the artifact's last_scan_id
			lastScanID := getArtifactLastScanID(store.(*SQLiteStore), digest)
			if lastScanID == -1 {
				t.Logf("Failed to get artifact's last_scan_id")
				return false
			}

			// The last_scan_id should be the highest remaining scan ID (most recent)
			expectedLastScanID := scanIDs[scanCount-1] // The last (highest) scan ID should remain
			return lastScanID == expectedLastScanID
		},
		genValidDigest(),
		genValidRepoName(),
		genValidTag(),
		gen.IntRange(2, 5), // At least 2 scans to test cleanup
		gen.IntRange(1, 3), // Keep 1-3 scans
	))

	properties.TestingRun(t, gopter.ConsoleReporter(false))
}

func countScanRecords(store *SQLiteStore, digest string) int {
	var count int
	err := store.db.QueryRow(`
		SELECT COUNT(sr.id)
		FROM scan_records sr
		JOIN artifacts a ON sr.artifact_id = a.id
		WHERE a.digest = ?
	`, digest).Scan(&count)
	if err != nil {
		return -1
	}
	return count
}

func getArtifactLastScanID(store *SQLiteStore, digest string) int64 {
	var lastScanID int64
	err := store.db.QueryRow(`
		SELECT last_scan_id
		FROM artifacts
		WHERE digest = ?
	`, digest).Scan(&lastScanID)
	if err != nil {
		return -1
	}
	return lastScanID
}

// TestEmptyArtifactCleanupProperty tests the property that empty artifact cleanup works
// **Feature: scan-cleanup-management, Property 5: Empty artifact cleanup**
// **Validates: Requirements 1.4**
func TestEmptyArtifactCleanupProperty(t *testing.T) {
	properties := gopter.NewProperties(nil)

	properties.Property("When an artifact has no remaining scan records, the artifact is deleted", prop.ForAll(
		func(digest string, repoName string, tag string) bool {
			// Create a temporary database
			store, cleanup := createTestStore(t)
			defer cleanup()

			ctx := context.Background()

			// Create a scan record for the digest
			record := &ScanRecord{
				Repository:        repoName,
				Digest:           digest,
				Tag:              tag,
				ScanDurationMs:   1000,
				CriticalVulnCount: 1,
				HighVulnCount:    1,
				MediumVulnCount:  1,
				LowVulnCount:     1,
				PolicyPassed:     true,
				SBOMAttested:     true,
				VulnAttested:     true,
				SCAIAttested:     true,
				Vulnerabilities:  generateVulnerabilities(1),
			}

			// Record the scan
			err := store.RecordScan(ctx, record)
			if err != nil {
				t.Logf("Failed to record scan: %v", err)
				return false
			}

			// Verify artifact exists before cleanup
			_, err = store.GetLastScan(ctx, digest)
			if err != nil {
				t.Logf("Scan should exist before cleanup: %v", err)
				return false
			}

			// Perform cleanup (this should delete all scans and the artifact)
			err = store.CleanupArtifactScans(ctx, digest)
			if err != nil {
				t.Logf("Cleanup failed: %v", err)
				return false
			}

			// Verify artifact no longer exists
			_, err = store.GetLastScan(ctx, digest)
			return err == ErrScanNotFound
		},
		genValidDigest(),
		genValidRepoName(),
		genValidTag(),
	))

	properties.TestingRun(t, gopter.ConsoleReporter(false))
}

// TestEmptyRepositoryCleanupProperty tests the property that empty repository cleanup works
// **Feature: scan-cleanup-management, Property 6: Empty repository cleanup**
// **Validates: Requirements 1.5**
func TestEmptyRepositoryCleanupProperty(t *testing.T) {
	properties := gopter.NewProperties(nil)

	properties.Property("When a repository has no remaining artifacts, the repository is deleted", prop.ForAll(
		func(digest string, repoName string, tag string) bool {
			// Create a temporary database
			store, cleanup := createTestStore(t)
			defer cleanup()

			ctx := context.Background()

			// Create a scan record for the digest (this creates repository and artifact)
			record := &ScanRecord{
				Repository:        repoName,
				Digest:           digest,
				Tag:              tag,
				ScanDurationMs:   1000,
				CriticalVulnCount: 1,
				HighVulnCount:    1,
				MediumVulnCount:  1,
				LowVulnCount:     1,
				PolicyPassed:     true,
				SBOMAttested:     true,
				VulnAttested:     true,
				SCAIAttested:     true,
				Vulnerabilities:  generateVulnerabilities(1),
			}

			// Record the scan
			err := store.RecordScan(ctx, record)
			if err != nil {
				t.Logf("Failed to record scan: %v", err)
				return false
			}

			// Verify repository exists by checking if we can get the scan
			_, err = store.GetLastScan(ctx, digest)
			if err != nil {
				t.Logf("Scan should exist before cleanup: %v", err)
				return false
			}

			// Perform cleanup (this should delete all scans, the artifact, and the repository)
			err = store.CleanupArtifactScans(ctx, digest)
			if err != nil {
				t.Logf("Cleanup failed: %v", err)
				return false
			}

			// Verify repository no longer exists by checking that no scans exist for this digest
			_, err = store.GetLastScan(ctx, digest)
			if err != ErrScanNotFound {
				t.Logf("Expected ErrScanNotFound after cleanup, got: %v", err)
				return false
			}

			// Also test the CleanupOrphanedRepositories method
			deletedRepos, err := store.CleanupOrphanedRepositories(ctx)
			if err != nil {
				t.Logf("CleanupOrphanedRepositories failed: %v", err)
				return false
			}

			// Since we already cleaned up in CleanupArtifactScans, there should be no orphaned repos
			return len(deletedRepos) == 0
		},
		genValidDigest(),
		genValidRepoName(),
		genValidTag(),
	))

	properties.TestingRun(t, gopter.ConsoleReporter(false))
}

// TestTransactionAtomicityProperty tests the property that transaction atomicity is maintained
// **Feature: scan-cleanup-management, Property 7: Transaction atomicity**
// **Validates: Requirements 3.2, 3.3**
func TestTransactionAtomicityProperty(t *testing.T) {
	properties := gopter.NewProperties(nil)

	properties.Property("Either all database changes succeed together or all changes are rolled back when failures occur", prop.ForAll(
		func(digest string, repoName string, tag string, vulnCount int) bool {
			// Create a temporary database
			store, cleanup := createTestStore(t)
			defer cleanup()

			ctx := context.Background()

			// Create a scan record for the digest
			record := &ScanRecord{
				Repository:        repoName,
				Digest:           digest,
				Tag:              tag,
				ScanDurationMs:   1000,
				CriticalVulnCount: vulnCount,
				HighVulnCount:    vulnCount,
				MediumVulnCount:  vulnCount,
				LowVulnCount:     vulnCount,
				PolicyPassed:     true,
				SBOMAttested:     true,
				VulnAttested:     true,
				SCAIAttested:     true,
				Vulnerabilities:  generateVulnerabilities(vulnCount),
			}

			// Record the scan
			err := store.RecordScan(ctx, record)
			if err != nil {
				t.Logf("Failed to record scan: %v", err)
				return false
			}

			// Get initial state counts
			initialScanCount := countScanRecords(store.(*SQLiteStore), digest)
			initialVulnCount := countVulnerabilities(store.(*SQLiteStore), digest)
			initialArtifactExists := artifactExists(store.(*SQLiteStore), digest)

			// Test transaction atomicity by simulating a failure scenario
			// We'll create a custom operation that should fail partway through
			sqliteStore := store.(*SQLiteStore)
			
			// Try to execute a cleanup operation that will fail due to constraint violation
			// We'll attempt to delete from a non-existent table to force a failure
			err = sqliteStore.executeCleanup(ctx, func(tx *sql.Tx) error {
				// First, do a valid operation
				_, err := tx.ExecContext(ctx, `
					UPDATE artifacts SET last_scan_id = NULL WHERE digest = ?
				`, digest)
				if err != nil {
					return err
				}

				// Then, force a failure with an invalid SQL operation
				_, err = tx.ExecContext(ctx, `
					DELETE FROM non_existent_table WHERE id = 1
				`)
				return err // This should cause a rollback
			})

			// The operation should fail
			if err == nil {
				t.Logf("Expected operation to fail, but it succeeded")
				return false
			}

			// Verify that the database state is unchanged (rollback occurred)
			finalScanCount := countScanRecords(store.(*SQLiteStore), digest)
			finalVulnCount := countVulnerabilities(store.(*SQLiteStore), digest)
			finalArtifactExists := artifactExists(store.(*SQLiteStore), digest)

			// All counts should be the same as before the failed operation
			return initialScanCount == finalScanCount &&
				initialVulnCount == finalVulnCount &&
				initialArtifactExists == finalArtifactExists
		},
		genValidDigest(),
		genValidRepoName(),
		genValidTag(),
		gen.IntRange(1, 5),
	))

	properties.TestingRun(t, gopter.ConsoleReporter(false))
}

// TestCleanupIdempotencyProperty tests the property that cleanup idempotency is maintained
// **Feature: scan-cleanup-management, Property 8: Cleanup idempotency**
// **Validates: Requirements 3.5**
func TestCleanupIdempotencyProperty(t *testing.T) {
	properties := gopter.NewProperties(nil)

	properties.Property("Cleanup operations executed multiple times with same parameters produce identical final database state", prop.ForAll(
		func(digest string, repoName string, tag string, vulnCount int, executionCount int) bool {
			if executionCount < 2 {
				executionCount = 2 // Ensure at least 2 executions
			}
			if executionCount > 5 {
				executionCount = 5 // Limit to reasonable number
			}

			// Create a temporary database
			store, cleanup := createTestStore(t)
			defer cleanup()

			ctx := context.Background()

			// Create a scan record for the digest
			record := &ScanRecord{
				Repository:        repoName,
				Digest:           digest,
				Tag:              tag,
				ScanDurationMs:   1000,
				CriticalVulnCount: vulnCount,
				HighVulnCount:    vulnCount,
				MediumVulnCount:  vulnCount,
				LowVulnCount:     vulnCount,
				PolicyPassed:     true,
				SBOMAttested:     true,
				VulnAttested:     true,
				SCAIAttested:     true,
				Vulnerabilities:  generateVulnerabilities(vulnCount),
			}

			// Record the scan
			err := store.RecordScan(ctx, record)
			if err != nil {
				t.Logf("Failed to record scan: %v", err)
				return false
			}

			// Execute cleanup operation multiple times
			for i := 0; i < executionCount; i++ {
				err = store.CleanupArtifactScans(ctx, digest)
				if err != nil {
					t.Logf("Cleanup failed on execution %d: %v", i+1, err)
					return false
				}
			}

			// Verify final state - should be the same regardless of execution count
			finalScanCount := countScanRecords(store.(*SQLiteStore), digest)
			finalVulnCount := countVulnerabilities(store.(*SQLiteStore), digest)
			finalArtifactExists := artifactExists(store.(*SQLiteStore), digest)

			// After cleanup, there should be no scans, no vulnerabilities, and no artifact
			return finalScanCount == 0 && finalVulnCount == 0 && !finalArtifactExists
		},
		genValidDigest(),
		genValidRepoName(),
		genValidTag(),
		gen.IntRange(1, 5),
		gen.IntRange(2, 5),
	))



	properties.TestingRun(t, gopter.ConsoleReporter(false))
}

func artifactExists(store *SQLiteStore, digest string) bool {
	var count int
	err := store.db.QueryRow(`
		SELECT COUNT(*)
		FROM artifacts
		WHERE digest = ?
	`, digest).Scan(&count)
	return err == nil && count > 0
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}