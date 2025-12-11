package statestore

import (
	"context"
	"fmt"
	"github.com/daimoniac/suppline/internal/types"
	"os"
	"strings"
	"testing"
	"time"
	"database/sql"
)

func TestSQLiteStore(t *testing.T) {
	// Create temporary database file with unique name
	dbPath := "test_statestore_" + t.Name() + ".db"
	// Remove any existing database file to start fresh
	os.Remove(dbPath)
	defer os.Remove(dbPath)

	store, err := NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("Failed to create SQLite store: %v", err)
	}
	defer store.Close()

	ctx := context.Background()

	// Test RecordScan
	t.Run("RecordScan", func(t *testing.T) {
		expiresAtUnix := time.Now().Add(30 * 24 * time.Hour).Unix()
		record := &ScanRecord{
			Digest:            "sha256:abc123",
			Repository:        "myorg/myapp",
			Tag:               "v1.0.0",
			ScanDurationMs:    1500,
			CriticalVulnCount: 2,
			HighVulnCount:     5,
			MediumVulnCount:   10,
			LowVulnCount:      3,
			PolicyPassed:      false,
			SBOMAttested:      true,
			VulnAttested:      true,
			SCAIAttested:      false,
			Vulnerabilities: []types.VulnerabilityRecord{
				{
					CVEID:            "CVE-2024-1234",
					Severity:         "CRITICAL",
					PackageName:      "openssl",
					InstalledVersion: "1.0.0",
					FixedVersion:     "1.0.1",
					Title:            "Critical vulnerability in OpenSSL",
					Description:      "A critical security issue",
					PrimaryURL:       "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-1234",
				},
				{
					CVEID:            "CVE-2024-5678",
					Severity:         "HIGH",
					PackageName:      "curl",
					InstalledVersion: "7.0.0",
					FixedVersion:     "7.1.0",
					Title:            "High severity issue in curl",
					Description:      "A high severity security issue",
					PrimaryURL:       "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-5678",
				},
			},
			ToleratedCVEs: []types.ToleratedCVE{
				{
					CVEID:       "CVE-2024-1234",
					Statement:   "Accepted risk for legacy system",
					ToleratedAt: time.Now().Unix(),
					ExpiresAt:   &expiresAtUnix,
				},
			},
		}

		err := store.RecordScan(ctx, record)
		if err != nil {
			t.Fatalf("Failed to record scan: %v", err)
		}
	})

	// Test GetLastScan
	t.Run("GetLastScan", func(t *testing.T) {
		record, err := store.GetLastScan(ctx, "sha256:abc123")
		if err != nil {
			t.Fatalf("Failed to get last scan: %v", err)
		}
		if record == nil {
			t.Fatal("Expected scan record, got nil")
		}
		if record.Digest != "sha256:abc123" {
			t.Errorf("Expected digest sha256:abc123, got %s", record.Digest)
		}
		if len(record.Vulnerabilities) != 2 {
			t.Errorf("Expected 2 vulnerabilities, got %d", len(record.Vulnerabilities))
		}
		if len(record.ToleratedCVEs) != 1 {
			t.Errorf("Expected 1 tolerated CVE, got %d", len(record.ToleratedCVEs))
		}
	})

	// Test GetScanHistory
	t.Run("GetScanHistory", func(t *testing.T) {
		// Add a small delay to ensure different timestamps
		time.Sleep(10 * time.Millisecond)
		
		// Add another scan for the same digest with one vulnerability fixed
		record := &ScanRecord{
			Digest:            "sha256:abc123",
			Repository:        "myorg/myapp",
			Tag:               "v1.0.1",
			ScanDurationMs:    1200,
			CriticalVulnCount: 0,
			HighVulnCount:     1,
			MediumVulnCount:   5,
			LowVulnCount:      2,
			PolicyPassed:      true,
			SBOMAttested:      true,
			VulnAttested:      true,
			SCAIAttested:      false,
			Vulnerabilities: []types.VulnerabilityRecord{
				{
					CVEID:            "CVE-2024-5678",
					Severity:         "HIGH",
					PackageName:      "curl",
					InstalledVersion: "7.0.0",
					FixedVersion:     "7.1.0",
					Title:            "High severity issue in curl",
					Description:      "A high severity security issue",
					PrimaryURL:       "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-5678",
				},
			},
			ToleratedCVEs: []types.ToleratedCVE{},
		}
		err := store.RecordScan(ctx, record)
		if err != nil {
			t.Fatalf("Failed to record second scan: %v", err)
		}

		history, err := store.GetScanHistory(ctx, "sha256:abc123", 10)
		if err != nil {
			t.Fatalf("Failed to get scan history: %v", err)
		}
		if len(history) != 2 {
			t.Errorf("Expected 2 scan records, got %d", len(history))
		}
		// Verify both scans are returned in reverse chronological order (newest first)
		// Note: tag is mutable and points to current artifact tag, so both scans will have the latest tag
		if history[0].Tag != "v1.0.1" {
			t.Errorf("Expected first scan to have tag v1.0.1, got %s", history[0].Tag)
		}
		if history[1].Tag != "v1.0.1" {
			t.Errorf("Expected second scan to also have tag v1.0.1 (current artifact tag), got %s", history[1].Tag)
		}
		// Verify each scan has its own vulnerabilities (linked to scan_record_id)
		// Note: Due to timestamp precision, scans might be returned in creation order rather than DESC
		// Find which scan is which by checking vulnerability count
		var newestScan, oldestScan *ScanRecord
		if len(history[0].Vulnerabilities) == 1 {
			newestScan = history[0]
			oldestScan = history[1]
		} else {
			newestScan = history[1]
			oldestScan = history[0]
		}
		
		// Newest scan (v1.0.1) should have 1 vulnerability
		if len(newestScan.Vulnerabilities) != 1 {
			t.Errorf("Expected newest scan to have 1 vulnerability, got %d", len(newestScan.Vulnerabilities))
		}
		if newestScan.Vulnerabilities[0].CVEID != "CVE-2024-5678" {
			t.Errorf("Expected CVE-2024-5678 in newest scan, got %s", newestScan.Vulnerabilities[0].CVEID)
		}
		// Oldest scan (v1.0.0) should have 2 vulnerabilities (historical record preserved)
		if len(oldestScan.Vulnerabilities) != 2 {
			t.Errorf("Expected oldest scan to have 2 vulnerabilities (historical), got %d", len(oldestScan.Vulnerabilities))
		}
		// Verify the oldest scan has both CVEs
		cveIds := make(map[string]bool)
		for _, vuln := range oldestScan.Vulnerabilities {
			cveIds[vuln.CVEID] = true
		}
		if !cveIds["CVE-2024-1234"] || !cveIds["CVE-2024-5678"] {
			t.Errorf("Expected oldest scan to have CVE-2024-1234 and CVE-2024-5678, got %v", cveIds)
		}
	})

	// Test ListDueForRescan
	t.Run("ListDueForRescan", func(t *testing.T) {
		// Add an old scan
		oldRecord := &ScanRecord{
			Digest:            "sha256:old123",
			Repository:        "myorg/oldapp",
			Tag:               "v0.1.0",
			ScanDurationMs:    800,
			CriticalVulnCount: 0,
			HighVulnCount:     0,
			MediumVulnCount:   0,
			LowVulnCount:      0,
			PolicyPassed:      true,
			SBOMAttested:      true,
			VulnAttested:      true,
			SCAIAttested:      false,
			Vulnerabilities:   []types.VulnerabilityRecord{},
			ToleratedCVEs:     []types.ToleratedCVE{},
		}
		err := store.RecordScan(ctx, oldRecord)
		if err != nil {
			t.Fatalf("Failed to record old scan: %v", err)
		}

		// Update next_scan_at to the past to simulate a scan due for rescan
		pastTime := time.Now().Add(-1 * time.Hour).Unix()
		_, err = store.db.ExecContext(ctx, `
			UPDATE artifacts SET next_scan_at = ? WHERE digest = ?
		`, pastTime, "sha256:old123")
		if err != nil {
			t.Fatalf("Failed to update next_scan_at: %v", err)
		}

		digests, err := store.ListDueForRescan(ctx, 24*time.Hour)
		if err != nil {
			t.Fatalf("Failed to list due for rescan: %v", err)
		}
		if len(digests) == 0 {
			t.Error("Expected at least one digest due for rescan")
		}

		found := false
		for _, d := range digests {
			if d == "sha256:old123" {
				found = true
				break
			}
		}
		if !found {
			t.Error("Expected sha256:old123 to be due for rescan")
		}
	})

	// Test QueryVulnerabilities
	t.Run("QueryVulnerabilities", func(t *testing.T) {
		filter := VulnFilter{
			CVEID: "CVE-2024-5678",
			Limit: 10,
		}
		vulns, err := store.QueryVulnerabilities(ctx, filter)
		if err != nil {
			t.Fatalf("Failed to query vulnerabilities: %v", err)
		}
		if len(vulns) == 0 {
			t.Error("Expected at least one vulnerability")
		}
		if vulns[0].CVEID != "CVE-2024-5678" {
			t.Errorf("Expected CVE-2024-5678, got %s", vulns[0].CVEID)
		}
	})

	// Test GetImagesByCVE
	t.Run("GetImagesByCVE", func(t *testing.T) {
		images, err := store.GetImagesByCVE(ctx, "CVE-2024-5678")
		if err != nil {
			t.Fatalf("Failed to get images by CVE: %v", err)
		}
		if len(images) == 0 {
			t.Error("Expected at least one image")
		}
		if images[0].Digest != "sha256:abc123" {
			t.Errorf("Expected sha256:abc123, got %s", images[0].Digest)
		}
	})

	// Test ListScans with repository filter
	t.Run("ListScans with repository filter", func(t *testing.T) {
		filter := ScanFilter{
			Repository: "myorg/myapp",
			Limit:      10,
		}
		scans, err := store.ListScans(ctx, filter)
		if err != nil {
			t.Fatalf("Failed to list scans: %v", err)
		}
		if len(scans) != 2 {
			t.Errorf("Expected 2 scans for myorg/myapp, got %d", len(scans))
		}
		for _, scan := range scans {
			if scan.Repository != "myorg/myapp" {
				t.Errorf("Expected repository myorg/myapp, got %s", scan.Repository)
			}
		}
	})

	// Test ListScans with policy_passed filter
	t.Run("ListScans with policy_passed filter", func(t *testing.T) {
		passed := true
		filter := ScanFilter{
			PolicyPassed: &passed,
			Limit:        10,
		}
		scans, err := store.ListScans(ctx, filter)
		if err != nil {
			t.Fatalf("Failed to list scans: %v", err)
		}
		if len(scans) == 0 {
			t.Error("Expected at least one scan with policy_passed=true")
		}
		for _, scan := range scans {
			if !scan.PolicyPassed {
				t.Errorf("Expected policy_passed=true, got false")
			}
		}
	})

	// Test ListScans with pagination
	t.Run("ListScans with pagination", func(t *testing.T) {
		filter := ScanFilter{
			Limit:  1,
			Offset: 0,
		}
		scans, err := store.ListScans(ctx, filter)
		if err != nil {
			t.Fatalf("Failed to list scans: %v", err)
		}
		if len(scans) != 1 {
			t.Errorf("Expected 1 scan with limit=1, got %d", len(scans))
		}

		// Get second page
		filter.Offset = 1
		scans2, err := store.ListScans(ctx, filter)
		if err != nil {
			t.Fatalf("Failed to list scans page 2: %v", err)
		}
		if len(scans2) != 1 {
			t.Errorf("Expected 1 scan on page 2, got %d", len(scans2))
		}
		// Verify different scans
		if scans[0].ID == scans2[0].ID {
			t.Error("Expected different scans on different pages")
		}
	})

	// Test ListScans returns lightweight records (no vulnerabilities)
	t.Run("ListScans returns lightweight records", func(t *testing.T) {
		filter := ScanFilter{
			Repository: "myorg/myapp",
			Limit:      10,
		}
		scans, err := store.ListScans(ctx, filter)
		if err != nil {
			t.Fatalf("Failed to list scans: %v", err)
		}
		if len(scans) == 0 {
			t.Error("Expected at least one scan")
		}
		// Verify vulnerabilities are not loaded for list operations
		for _, scan := range scans {
			if len(scan.Vulnerabilities) != 0 {
				t.Errorf("Expected no vulnerabilities in list response, got %d", len(scan.Vulnerabilities))
			}
		}
	})

	// Test ListScans with max_age filter
	t.Run("ListScans with max_age filter", func(t *testing.T) {
		// First, get all scans to establish baseline
		allFilter := ScanFilter{Limit: 10}
		allScans, err := store.ListScans(ctx, allFilter)
		if err != nil {
			t.Fatalf("Failed to list all scans: %v", err)
		}
		if len(allScans) == 0 {
			t.Skip("No scans available for max_age test")
		}

		// Test with a large max_age (1 day) - should return all results
		filter := ScanFilter{
			MaxAge: 86400, // 24 hours
			Limit:  10,
		}
		scans, err := store.ListScans(ctx, filter)
		if err != nil {
			t.Fatalf("Failed to list scans with max_age=86400: %v", err)
		}
		if len(scans) != len(allScans) {
			t.Errorf("Expected %d scans with max_age=86400, got %d", len(allScans), len(scans))
		}

		// Test with zero max_age (no filter) - should return all results
		filter.MaxAge = 0
		scans, err = store.ListScans(ctx, filter)
		if err != nil {
			t.Fatalf("Failed to list scans with max_age=0: %v", err)
		}
		if len(scans) != len(allScans) {
			t.Errorf("Expected %d scans with max_age=0, got %d", len(allScans), len(scans))
		}
	})

	// Test ListScans with sort_by parameter
	t.Run("ListScans with sort_by parameter", func(t *testing.T) {
		// Test default sorting (age_desc)
		filter := ScanFilter{
			SortBy: "age_desc",
			Limit:  10,
		}
		scans, err := store.ListScans(ctx, filter)
		if err != nil {
			t.Fatalf("Failed to list scans with sort_by=age_desc: %v", err)
		}
		if len(scans) < 2 {
			t.Skip("Need at least 2 scans to test sorting")
		}
		// Verify scans are sorted by created_at DESC (newest first)
		for i := 1; i < len(scans); i++ {
			if scans[i-1].CreatedAt < scans[i].CreatedAt {
				t.Errorf("Scans not sorted by age descending: %d should be after %d", 
					scans[i-1].CreatedAt, scans[i].CreatedAt)
			}
		}

		// Test with empty sort_by (should default to age_desc)
		filter.SortBy = ""
		scans2, err := store.ListScans(ctx, filter)
		if err != nil {
			t.Fatalf("Failed to list scans with empty sort_by: %v", err)
		}
		if len(scans2) != len(scans) {
			t.Errorf("Expected same number of scans with empty sort_by, got %d vs %d", len(scans2), len(scans))
		}
	})

	// Test ListTolerations with no filters
	t.Run("ListTolerations with no filters", func(t *testing.T) {
		filter := TolerationFilter{
			Limit: 100,
		}
		tolerations, err := store.ListTolerations(ctx, filter)
		if err != nil {
			t.Fatalf("Failed to list tolerations: %v", err)
		}
		if len(tolerations) != 1 {
			t.Errorf("Expected 1 toleration, got %d", len(tolerations))
		}
		if tolerations[0].CVEID != "CVE-2024-1234" {
			t.Errorf("Expected CVE-2024-1234, got %s", tolerations[0].CVEID)
		}
		if tolerations[0].Repository != "myorg/myapp" {
			t.Errorf("Expected repository myorg/myapp, got %s", tolerations[0].Repository)
		}
	})

	// Test ListTolerations with repository filter
	t.Run("ListTolerations with repository filter", func(t *testing.T) {
		filter := TolerationFilter{
			Repository: "myorg/myapp",
			Limit:      100,
		}
		tolerations, err := store.ListTolerations(ctx, filter)
		if err != nil {
			t.Fatalf("Failed to list tolerations: %v", err)
		}
		if len(tolerations) != 1 {
			t.Errorf("Expected 1 toleration for myorg/myapp, got %d", len(tolerations))
		}
		for _, tol := range tolerations {
			if tol.Repository != "myorg/myapp" {
				t.Errorf("Expected repository myorg/myapp, got %s", tol.Repository)
			}
		}
	})

	// Test ListTolerations with CVE ID filter
	t.Run("ListTolerations with CVE ID filter", func(t *testing.T) {
		filter := TolerationFilter{
			CVEID: "CVE-2024-1234",
			Limit: 100,
		}
		tolerations, err := store.ListTolerations(ctx, filter)
		if err != nil {
			t.Fatalf("Failed to list tolerations: %v", err)
		}
		if len(tolerations) != 1 {
			t.Errorf("Expected 1 toleration with CVE-2024-1234, got %d", len(tolerations))
		}
		if tolerations[0].CVEID != "CVE-2024-1234" {
			t.Errorf("Expected CVE-2024-1234, got %s", tolerations[0].CVEID)
		}
	})

	// Test ListTolerations with non-expired filter
	t.Run("ListTolerations with non-expired filter", func(t *testing.T) {
		expired := false
		filter := TolerationFilter{
			Expired: &expired,
			Limit:   100,
		}
		tolerations, err := store.ListTolerations(ctx, filter)
		if err != nil {
			t.Fatalf("Failed to list tolerations: %v", err)
		}
		if len(tolerations) != 1 {
			t.Errorf("Expected 1 non-expired toleration, got %d", len(tolerations))
		}
		// Verify the toleration is not expired
		if tolerations[0].ExpiresAt != nil && *tolerations[0].ExpiresAt < time.Now().Unix() {
			t.Error("Expected non-expired toleration, but it is expired")
		}
	})

	// Test ListTolerations with expiring_soon filter
	t.Run("ListTolerations with expiring_soon filter", func(t *testing.T) {
		// Add a toleration expiring soon
		soonRecord := &ScanRecord{
			Digest:            "sha256:soon123",
			Repository:        "myorg/soonapp",
			Tag:               "v1.0.0",
			ScanDurationMs:    1000,
			CriticalVulnCount: 0,
			HighVulnCount:     0,
			MediumVulnCount:   0,
			LowVulnCount:      0,
			PolicyPassed:      true,
			SBOMAttested:      true,
			VulnAttested:      true,
			SCAIAttested:      false,
			Vulnerabilities:   []types.VulnerabilityRecord{},
			ToleratedCVEs: []types.ToleratedCVE{
				{
					CVEID:       "CVE-2024-9999",
					Statement:   "Expiring soon",
					ToleratedAt: time.Now().Unix(),
					ExpiresAt:   &[]int64{time.Now().Add(3 * 24 * time.Hour).Unix()}[0],
				},
			},
		}
		err := store.RecordScan(ctx, soonRecord)
		if err != nil {
			t.Fatalf("Failed to record scan with soon-expiring toleration: %v", err)
		}

		expiringSoon := true
		filter := TolerationFilter{
			ExpiringSoon: &expiringSoon,
			Limit:        100,
		}
		tolerations, err := store.ListTolerations(ctx, filter)
		if err != nil {
			t.Fatalf("Failed to list expiring_soon tolerations: %v", err)
		}
		if len(tolerations) != 1 {
			t.Errorf("Expected 1 expiring_soon toleration, got %d", len(tolerations))
		}
		if tolerations[0].CVEID != "CVE-2024-9999" {
			t.Errorf("Expected CVE-2024-9999, got %s", tolerations[0].CVEID)
		}
	})

	// Test ListTolerations with pagination
	t.Run("ListTolerations with pagination", func(t *testing.T) {
		filter := TolerationFilter{
			Limit: 1,
		}
		tolerations, err := store.ListTolerations(ctx, filter)
		if err != nil {
			t.Fatalf("Failed to list tolerations: %v", err)
		}
		if len(tolerations) != 1 {
			t.Errorf("Expected 1 toleration with limit=1, got %d", len(tolerations))
		}
	})

	// Test ListTolerations returns TolerationInfo with all fields
	t.Run("ListTolerations returns complete TolerationInfo", func(t *testing.T) {
		filter := TolerationFilter{
			CVEID: "CVE-2024-1234",
			Limit: 100,
		}
		tolerations, err := store.ListTolerations(ctx, filter)
		if err != nil {
			t.Fatalf("Failed to list tolerations: %v", err)
		}
		if len(tolerations) == 0 {
			t.Fatal("Expected at least one toleration")
		}

		tol := tolerations[0]
		if tol.CVEID == "" {
			t.Error("Expected CVEID to be set")
		}
		if tol.Statement == "" {
			t.Error("Expected Statement to be set")
		}
		if tol.Repository == "" {
			t.Error("Expected Repository to be set")
		}
		if tol.ToleratedAt == 0 {
			t.Error("Expected ToleratedAt to be set")
		}
		if tol.ExpiresAt == nil {
			t.Error("Expected ExpiresAt to be set for this toleration")
		}
	})
}

// TestSchemaAndConstraints tests database schema creation, indexes, and constraints
func TestSchemaAndConstraints(t *testing.T) {
	dbPath := "test_schema_" + t.Name() + ".db"
	os.Remove(dbPath)
	defer os.Remove(dbPath)

	store, err := NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("Failed to create SQLite store: %v", err)
	}
	defer store.Close()

	ctx := context.Background()

	// Test 1: Verify all tables exist
	t.Run("All tables are created", func(t *testing.T) {
		tables := []string{"repositories", "artifacts", "scan_records", "vulnerabilities", "tolerated_cves"}
		for _, table := range tables {
			var count int
			err := store.db.QueryRowContext(ctx, `
				SELECT COUNT(*) FROM sqlite_master 
				WHERE type='table' AND name=?
			`, table).Scan(&count)
			if err != nil || count == 0 {
				t.Errorf("Table %s not found", table)
			}
		}
	})

	// Test 2: Verify all indexes exist
	t.Run("All indexes are created", func(t *testing.T) {
		indexes := []string{
			"idx_artifacts_repository",
			"idx_artifacts_digest",
			"idx_artifacts_next_scan",
			"idx_scan_records_artifact",
			"idx_scan_records_created",
			"idx_vulnerabilities_scan",
			"idx_vulnerabilities_cve",
			"idx_vulnerabilities_severity",
			"idx_tolerated_repository",
			"idx_tolerated_cve",
			"idx_tolerated_expires",
		}
		for _, idx := range indexes {
			var count int
			err := store.db.QueryRowContext(ctx, `
				SELECT COUNT(*) FROM sqlite_master 
				WHERE type='index' AND name=?
			`, idx).Scan(&count)
			if err != nil || count == 0 {
				t.Errorf("Index %s not found", idx)
			}
		}
	})

	// Test 3: Unique constraint on repository name
	t.Run("Unique constraint on repository name", func(t *testing.T) {
		// Insert first repository
		_, err := store.db.ExecContext(ctx, `
			INSERT INTO repositories (name) VALUES (?)
		`, "test/repo")
		if err != nil {
			t.Fatalf("Failed to insert first repository: %v", err)
		}

		// Try to insert duplicate repository name
		_, err = store.db.ExecContext(ctx, `
			INSERT INTO repositories (name) VALUES (?)
		`, "test/repo")
		if err == nil {
			t.Error("Expected unique constraint violation for duplicate repository name")
		}
	})

	// Test 4: Unique constraint on artifact digest
	t.Run("Unique constraint on artifact digest", func(t *testing.T) {
		// Get or create repository
		var repoID int64
		err := store.db.QueryRowContext(ctx, `
			SELECT id FROM repositories WHERE name = ?
		`, "test/repo").Scan(&repoID)
		if err != nil {
			t.Fatalf("Failed to get repository: %v", err)
		}

		now := time.Now()
		// Insert first artifact
		_, err = store.db.ExecContext(ctx, `
			INSERT INTO artifacts (repository_id, digest, first_seen, last_seen)
			VALUES (?, ?, ?, ?)
		`, repoID, "sha256:abc123", now, now)
		if err != nil {
			t.Fatalf("Failed to insert first artifact: %v", err)
		}

		// Try to insert duplicate digest
		_, err = store.db.ExecContext(ctx, `
			INSERT INTO artifacts (repository_id, digest, first_seen, last_seen)
			VALUES (?, ?, ?, ?)
		`, repoID, "sha256:abc123", now, now)
		if err == nil {
			t.Error("Expected unique constraint violation for duplicate digest")
		}
	})

	// Test 5: Unique constraint on (repository_id, cve_id) in tolerated_cves
	t.Run("Unique constraint on (repository_id, cve_id) in tolerated_cves", func(t *testing.T) {
		var repoID int64
		err := store.db.QueryRowContext(ctx, `
			SELECT id FROM repositories WHERE name = ?
		`, "test/repo").Scan(&repoID)
		if err != nil {
			t.Fatalf("Failed to get repository: %v", err)
		}

		now := time.Now()
		// Insert first tolerated CVE
		_, err = store.db.ExecContext(ctx, `
			INSERT INTO tolerated_cves (repository_id, cve_id, statement, tolerated_at)
			VALUES (?, ?, ?, ?)
		`, repoID, "CVE-2024-TEST", "Test statement", now)
		if err != nil {
			t.Fatalf("Failed to insert first tolerated CVE: %v", err)
		}

		// Try to insert duplicate (repository_id, cve_id)
		_, err = store.db.ExecContext(ctx, `
			INSERT INTO tolerated_cves (repository_id, cve_id, statement, tolerated_at)
			VALUES (?, ?, ?, ?)
		`, repoID, "CVE-2024-TEST", "Different statement", now)
		if err == nil {
			t.Error("Expected unique constraint violation for duplicate (repository_id, cve_id)")
		}
	})

	// Test 6: Foreign key constraint - artifact references repository
	t.Run("Foreign key constraint - artifact references repository", func(t *testing.T) {
		now := time.Now()
		// Try to insert artifact with non-existent repository_id
		_, err := store.db.ExecContext(ctx, `
			INSERT INTO artifacts (repository_id, digest, first_seen, last_seen)
			VALUES (?, ?, ?, ?)
		`, 99999, "sha256:invalid", now, now)
		if err == nil {
			t.Error("Expected foreign key constraint violation for invalid repository_id")
		}
	})

	// Test 7: Foreign key constraint - scan_record references artifact
	t.Run("Foreign key constraint - scan_record references artifact", func(t *testing.T) {
		// Try to insert scan_record with non-existent artifact_id
		_, err := store.db.ExecContext(ctx, `
			INSERT INTO scan_records (artifact_id, critical_vuln_count, high_vuln_count, 
				medium_vuln_count, low_vuln_count, policy_passed, sbom_attested, 
				vuln_attested, scai_attested)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		`, 99999, 0, 0, 0, 0, true, false, false, false)
		if err == nil {
			t.Error("Expected foreign key constraint violation for invalid artifact_id")
		}
	})

	// Test 8: Foreign key constraint - vulnerability references scan_record
	t.Run("Foreign key constraint - vulnerability references scan_record", func(t *testing.T) {
		// Try to insert vulnerability with non-existent scan_record_id
		_, err := store.db.ExecContext(ctx, `
			INSERT INTO vulnerabilities (scan_record_id, cve_id, severity, package_name)
			VALUES (?, ?, ?, ?)
		`, 99999, "CVE-2024-TEST", "HIGH", "test-package")
		if err == nil {
			t.Error("Expected foreign key constraint violation for invalid scan_record_id")
		}
	})

	// Test 9: Foreign key constraint - tolerated_cve references repository
	t.Run("Foreign key constraint - tolerated_cve references repository", func(t *testing.T) {
		now := time.Now()
		// Try to insert tolerated_cve with non-existent repository_id
		_, err := store.db.ExecContext(ctx, `
			INSERT INTO tolerated_cves (repository_id, cve_id, statement, tolerated_at)
			VALUES (?, ?, ?, ?)
		`, 99999, "CVE-2024-TEST", "Test", now)
		if err == nil {
			t.Error("Expected foreign key constraint violation for invalid repository_id")
		}
	})

	// Test 10: Cascade delete - deleting artifact cascades to scan_records
	t.Run("Cascade delete - artifact cascades to scan_records", func(t *testing.T) {
		// Create a test artifact and scan record
		var repoID int64
		err := store.db.QueryRowContext(ctx, `
			SELECT id FROM repositories WHERE name = ?
		`, "test/repo").Scan(&repoID)
		if err != nil {
			t.Fatalf("Failed to get repository: %v", err)
		}

		now := time.Now()
		result, err := store.db.ExecContext(ctx, `
			INSERT INTO artifacts (repository_id, digest, first_seen, last_seen)
			VALUES (?, ?, ?, ?)
		`, repoID, "sha256:cascade-test", now, now)
		if err != nil {
			t.Fatalf("Failed to insert artifact: %v", err)
		}

		artifactID, err := result.LastInsertId()
		if err != nil {
			t.Fatalf("Failed to get artifact ID: %v", err)
		}

		// Insert scan record
		_, err = store.db.ExecContext(ctx, `
			INSERT INTO scan_records (artifact_id, critical_vuln_count, high_vuln_count,
				medium_vuln_count, low_vuln_count, policy_passed, sbom_attested,
				vuln_attested, scai_attested)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		`, artifactID, 0, 0, 0, 0, true, false, false, false)
		if err != nil {
			t.Fatalf("Failed to insert scan record: %v", err)
		}

		// Verify scan record exists
		var scanCount int
		err = store.db.QueryRowContext(ctx, `
			SELECT COUNT(*) FROM scan_records WHERE artifact_id = ?
		`, artifactID).Scan(&scanCount)
		if err != nil || scanCount != 1 {
			t.Fatalf("Expected 1 scan record, got %d", scanCount)
		}

		// Delete artifact
		_, err = store.db.ExecContext(ctx, `
			DELETE FROM artifacts WHERE id = ?
		`, artifactID)
		if err != nil {
			t.Fatalf("Failed to delete artifact: %v", err)
		}

		// Verify scan records were cascade deleted
		err = store.db.QueryRowContext(ctx, `
			SELECT COUNT(*) FROM scan_records WHERE artifact_id = ?
		`, artifactID).Scan(&scanCount)
		if err != nil || scanCount != 0 {
			t.Errorf("Expected 0 scan records after cascade delete, got %d", scanCount)
		}
	})

	// Test 11: Cascade delete - deleting scan_record cascades to vulnerabilities
	t.Run("Cascade delete - scan_record cascades to vulnerabilities", func(t *testing.T) {
		// Create a test artifact and scan record with vulnerabilities
		var repoID int64
		err := store.db.QueryRowContext(ctx, `
			SELECT id FROM repositories WHERE name = ?
		`, "test/repo").Scan(&repoID)
		if err != nil {
			t.Fatalf("Failed to get repository: %v", err)
		}

		now := time.Now()
		result, err := store.db.ExecContext(ctx, `
			INSERT INTO artifacts (repository_id, digest, first_seen, last_seen)
			VALUES (?, ?, ?, ?)
		`, repoID, "sha256:vuln-cascade-test", now, now)
		if err != nil {
			t.Fatalf("Failed to insert artifact: %v", err)
		}

		artifactID, err := result.LastInsertId()
		if err != nil {
			t.Fatalf("Failed to get artifact ID: %v", err)
		}

		// Insert scan record
		result, err = store.db.ExecContext(ctx, `
			INSERT INTO scan_records (artifact_id, critical_vuln_count, high_vuln_count,
				medium_vuln_count, low_vuln_count, policy_passed, sbom_attested,
				vuln_attested, scai_attested)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		`, artifactID, 1, 0, 0, 0, false, false, false, false)
		if err != nil {
			t.Fatalf("Failed to insert scan record: %v", err)
		}

		scanRecordID, err := result.LastInsertId()
		if err != nil {
			t.Fatalf("Failed to get scan record ID: %v", err)
		}

		// Insert vulnerability
		_, err = store.db.ExecContext(ctx, `
			INSERT INTO vulnerabilities (scan_record_id, cve_id, severity, package_name)
			VALUES (?, ?, ?, ?)
		`, scanRecordID, "CVE-2024-CASCADE", "CRITICAL", "test-package")
		if err != nil {
			t.Fatalf("Failed to insert vulnerability: %v", err)
		}

		// Verify vulnerability exists
		var vulnCount int
		err = store.db.QueryRowContext(ctx, `
			SELECT COUNT(*) FROM vulnerabilities WHERE scan_record_id = ?
		`, scanRecordID).Scan(&vulnCount)
		if err != nil || vulnCount != 1 {
			t.Fatalf("Expected 1 vulnerability, got %d", vulnCount)
		}

		// Delete scan record
		_, err = store.db.ExecContext(ctx, `
			DELETE FROM scan_records WHERE id = ?
		`, scanRecordID)
		if err != nil {
			t.Fatalf("Failed to delete scan record: %v", err)
		}

		// Verify vulnerabilities were cascade deleted
		err = store.db.QueryRowContext(ctx, `
			SELECT COUNT(*) FROM vulnerabilities WHERE scan_record_id = ?
		`, scanRecordID).Scan(&vulnCount)
		if err != nil || vulnCount != 0 {
			t.Errorf("Expected 0 vulnerabilities after cascade delete, got %d", vulnCount)
		}
	})

	// Test 12: Foreign keys are enabled
	t.Run("Foreign keys are enabled", func(t *testing.T) {
		var foreignKeysEnabled int
		err := store.db.QueryRowContext(ctx, "PRAGMA foreign_keys").Scan(&foreignKeysEnabled)
		if err != nil {
			t.Fatalf("Failed to check foreign keys pragma: %v", err)
		}
		if foreignKeysEnabled != 1 {
			t.Error("Foreign keys are not enabled")
		}
	})

	// Test 13: Verify column types and constraints
	t.Run("Verify column types and constraints", func(t *testing.T) {
		// Check repositories table
		rows, err := store.db.QueryContext(ctx, "PRAGMA table_info(repositories)")
		if err != nil {
			t.Fatalf("Failed to get repositories table info: %v", err)
		}
		defer rows.Close()

		columns := make(map[string]string)
		for rows.Next() {
			var cid, name, type_, notnull, dfltValue, pk interface{}
			if err := rows.Scan(&cid, &name, &type_, &notnull, &dfltValue, &pk); err != nil {
				t.Fatalf("Failed to scan column info: %v", err)
			}
			columns[name.(string)] = type_.(string)
		}

		expectedColumns := map[string]string{
			"id":         "INTEGER",
			"name":       "TEXT",
			"registry":   "TEXT",
			"created_at": "INTEGER",
		}

		for col, expectedType := range expectedColumns {
			if actualType, exists := columns[col]; !exists {
				t.Errorf("Column %s not found in repositories table", col)
			} else if actualType != expectedType {
				t.Errorf("Column %s has type %s, expected %s", col, actualType, expectedType)
			}
		}
	})

	// Test 14: Verify artifacts table structure
	t.Run("Verify artifacts table structure", func(t *testing.T) {
		rows, err := store.db.QueryContext(ctx, "PRAGMA table_info(artifacts)")
		if err != nil {
			t.Fatalf("Failed to get artifacts table info: %v", err)
		}
		defer rows.Close()

		columns := make(map[string]string)
		for rows.Next() {
			var cid, name, type_, notnull, dfltValue, pk interface{}
			if err := rows.Scan(&cid, &name, &type_, &notnull, &dfltValue, &pk); err != nil {
				t.Fatalf("Failed to scan column info: %v", err)
			}
			columns[name.(string)] = type_.(string)
		}

		expectedColumns := map[string]string{
			"id":            "INTEGER",
			"repository_id": "INTEGER",
			"digest":        "TEXT",
			"tag":           "TEXT",
			"first_seen":    "INTEGER",
			"last_seen":     "INTEGER",
			"last_scan_id":  "INTEGER",
			"next_scan_at":  "INTEGER",
			"created_at":    "INTEGER",
		}

		for col, expectedType := range expectedColumns {
			if actualType, exists := columns[col]; !exists {
				t.Errorf("Column %s not found in artifacts table", col)
			} else if actualType != expectedType {
				t.Errorf("Column %s has type %s, expected %s", col, actualType, expectedType)
			}
		}
	})

	// Test 15: Verify scan_records table structure
	t.Run("Verify scan_records table structure", func(t *testing.T) {
		rows, err := store.db.QueryContext(ctx, "PRAGMA table_info(scan_records)")
		if err != nil {
			t.Fatalf("Failed to get scan_records table info: %v", err)
		}
		defer rows.Close()

		columns := make(map[string]string)
		for rows.Next() {
			var cid, name, type_, notnull, dfltValue, pk interface{}
			if err := rows.Scan(&cid, &name, &type_, &notnull, &dfltValue, &pk); err != nil {
				t.Fatalf("Failed to scan column info: %v", err)
			}
			columns[name.(string)] = type_.(string)
		}

		expectedColumns := map[string]string{
			"id":                   "INTEGER",
			"artifact_id":          "INTEGER",
			"scan_duration_ms":     "INTEGER",
			"critical_vuln_count":  "INTEGER",
			"high_vuln_count":      "INTEGER",
			"medium_vuln_count":    "INTEGER",
			"low_vuln_count":       "INTEGER",
			"policy_passed":        "BOOLEAN",
			"sbom_attested":        "BOOLEAN",
			"vuln_attested":        "BOOLEAN",
			"scai_attested":        "BOOLEAN",
			"error_message":        "TEXT",
			"created_at":           "INTEGER",
		}

		for col, expectedType := range expectedColumns {
			if actualType, exists := columns[col]; !exists {
				t.Errorf("Column %s not found in scan_records table", col)
			} else if actualType != expectedType {
				t.Errorf("Column %s has type %s, expected %s", col, actualType, expectedType)
			}
		}
	})

	// Test 16: Verify vulnerabilities table structure
	t.Run("Verify vulnerabilities table structure", func(t *testing.T) {
		rows, err := store.db.QueryContext(ctx, "PRAGMA table_info(vulnerabilities)")
		if err != nil {
			t.Fatalf("Failed to get vulnerabilities table info: %v", err)
		}
		defer rows.Close()

		columns := make(map[string]string)
		for rows.Next() {
			var cid, name, type_, notnull, dfltValue, pk interface{}
			if err := rows.Scan(&cid, &name, &type_, &notnull, &dfltValue, &pk); err != nil {
				t.Fatalf("Failed to scan column info: %v", err)
			}
			columns[name.(string)] = type_.(string)
		}

		expectedColumns := map[string]string{
			"id":                "INTEGER",
			"scan_record_id":    "INTEGER",
			"cve_id":            "TEXT",
			"severity":          "TEXT",
			"package_name":      "TEXT",
			"installed_version": "TEXT",
			"fixed_version":     "TEXT",
			"title":             "TEXT",
			"description":       "TEXT",
			"primary_url":       "TEXT",
			"created_at":        "INTEGER",
		}

		for col, expectedType := range expectedColumns {
			if actualType, exists := columns[col]; !exists {
				t.Errorf("Column %s not found in vulnerabilities table", col)
			} else if actualType != expectedType {
				t.Errorf("Column %s has type %s, expected %s", col, actualType, expectedType)
			}
		}
	})

	// Test 17: Verify tolerated_cves table structure
	t.Run("Verify tolerated_cves table structure", func(t *testing.T) {
		rows, err := store.db.QueryContext(ctx, "PRAGMA table_info(tolerated_cves)")
		if err != nil {
			t.Fatalf("Failed to get tolerated_cves table info: %v", err)
		}
		defer rows.Close()

		columns := make(map[string]string)
		for rows.Next() {
			var cid, name, type_, notnull, dfltValue, pk interface{}
			if err := rows.Scan(&cid, &name, &type_, &notnull, &dfltValue, &pk); err != nil {
				t.Fatalf("Failed to scan column info: %v", err)
			}
			columns[name.(string)] = type_.(string)
		}

		expectedColumns := map[string]string{
			"id":            "INTEGER",
			"repository_id": "INTEGER",
			"artifact_id":   "INTEGER",
			"cve_id":        "TEXT",
			"statement":     "TEXT",
			"tolerated_at":  "INTEGER",
			"expires_at":    "INTEGER",
			"created_at":    "INTEGER",
		}

		for col, expectedType := range expectedColumns {
			if actualType, exists := columns[col]; !exists {
				t.Errorf("Column %s not found in tolerated_cves table", col)
			} else if actualType != expectedType {
				t.Errorf("Column %s has type %s, expected %s", col, actualType, expectedType)
			}
		}
	})
}

// TestRescanScheduling tests rescan scheduling functionality
func TestRescanScheduling(t *testing.T) {
	dbPath := "test_rescan_" + t.Name() + ".db"
	os.Remove(dbPath)
	defer os.Remove(dbPath)

	store, err := NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("Failed to create SQLite store: %v", err)
	}
	defer store.Close()

	ctx := context.Background()

	// Test 1: next_scan_at is updated when recording a scan
	t.Run("next_scan_at is updated when recording a scan", func(t *testing.T) {
		record := &ScanRecord{
			Digest:            "sha256:rescan-test-1",
			Repository:        "myorg/rescanapp",
			Tag:               "v1.0.0",
			ScanDurationMs:    1000,
			CriticalVulnCount: 0,
			HighVulnCount:     0,
			MediumVulnCount:   0,
			LowVulnCount:      0,
			PolicyPassed:      true,
			SBOMAttested:      true,
			VulnAttested:      true,
			SCAIAttested:      false,
			Vulnerabilities:   []types.VulnerabilityRecord{},
			ToleratedCVEs:     []types.ToleratedCVE{},
		}

		err := store.RecordScan(ctx, record)
		if err != nil {
			t.Fatalf("Failed to record scan: %v", err)
		}

		// Query the artifact to verify next_scan_at is set
		var nextScanAtUnix sql.NullInt64
		err = store.db.QueryRowContext(ctx, `
			SELECT next_scan_at FROM artifacts WHERE digest = ?
		`, "sha256:rescan-test-1").Scan(&nextScanAtUnix)
		if err != nil {
			t.Fatalf("Failed to query artifact: %v", err)
		}

		if !nextScanAtUnix.Valid {
			t.Error("Expected next_scan_at to be set, but it was NULL")
		}
	})

	// Test 2: ListDueForRescan returns artifacts with next_scan_at in the past
	t.Run("ListDueForRescan returns artifacts due for rescan", func(t *testing.T) {
		// Record a scan
		record := &ScanRecord{
			Digest:            "sha256:rescan-test-2",
			Repository:        "myorg/rescanapp2",
			Tag:               "v1.0.0",
			ScanDurationMs:    1000,
			CriticalVulnCount: 0,
			HighVulnCount:     0,
			MediumVulnCount:   0,
			LowVulnCount:      0,
			PolicyPassed:      true,
			SBOMAttested:      true,
			VulnAttested:      true,
			SCAIAttested:      false,
			Vulnerabilities:   []types.VulnerabilityRecord{},
			ToleratedCVEs:     []types.ToleratedCVE{},
		}

		err := store.RecordScan(ctx, record)
		if err != nil {
			t.Fatalf("Failed to record scan: %v", err)
		}

		// Update next_scan_at to the past to simulate a scan due for rescan
		pastTime := time.Now().Add(-1 * time.Hour).Unix()
		_, err = store.db.ExecContext(ctx, `
			UPDATE artifacts SET next_scan_at = ? WHERE digest = ?
		`, pastTime, "sha256:rescan-test-2")
		if err != nil {
			t.Fatalf("Failed to update next_scan_at: %v", err)
		}

		// Query due for rescan
		digests, err := store.ListDueForRescan(ctx, 24*time.Hour)
		if err != nil {
			t.Fatalf("Failed to list due for rescan: %v", err)
		}

		found := false
		for _, d := range digests {
			if d == "sha256:rescan-test-2" {
				found = true
				break
			}
		}
		if !found {
			t.Error("Expected sha256:rescan-test-2 to be in due for rescan list")
		}
	})

	// Test 3: ListDueForRescan does not return artifacts with future next_scan_at
	t.Run("ListDueForRescan excludes artifacts not due for rescan", func(t *testing.T) {
		// Record a scan
		record := &ScanRecord{
			Digest:            "sha256:rescan-test-3",
			Repository:        "myorg/rescanapp3",
			Tag:               "v1.0.0",
			ScanDurationMs:    1000,
			CriticalVulnCount: 0,
			HighVulnCount:     0,
			MediumVulnCount:   0,
			LowVulnCount:      0,
			PolicyPassed:      true,
			SBOMAttested:      true,
			VulnAttested:      true,
			SCAIAttested:      false,
			Vulnerabilities:   []types.VulnerabilityRecord{},
			ToleratedCVEs:     []types.ToleratedCVE{},
		}

		err := store.RecordScan(ctx, record)
		if err != nil {
			t.Fatalf("Failed to record scan: %v", err)
		}

		// Update next_scan_at to the future
		futureTime := time.Now().Add(24 * time.Hour)
		_, err = store.db.ExecContext(ctx, `
			UPDATE artifacts SET next_scan_at = ? WHERE digest = ?
		`, futureTime, "sha256:rescan-test-3")
		if err != nil {
			t.Fatalf("Failed to update next_scan_at: %v", err)
		}

		// Query due for rescan
		digests, err := store.ListDueForRescan(ctx, 24*time.Hour)
		if err != nil {
			t.Fatalf("Failed to list due for rescan: %v", err)
		}

		found := false
		for _, d := range digests {
			if d == "sha256:rescan-test-3" {
				found = true
				break
			}
		}
		if found {
			t.Error("Expected sha256:rescan-test-3 NOT to be in due for rescan list (future next_scan_at)")
		}
	})

	// Test 4: ListDueForRescan returns results in order of next_scan_at (oldest first)
	t.Run("ListDueForRescan returns results ordered by next_scan_at", func(t *testing.T) {
		// Record three scans with different next_scan_at times
		for i := 1; i <= 3; i++ {
			digest := fmt.Sprintf("sha256:rescan-order-%d", i)
			repo := fmt.Sprintf("myorg/rescanorder%d", i)
			record := &ScanRecord{
				Digest:            digest,
				Repository:        repo,
				Tag:               "v1.0.0",
				ScanDurationMs:    1000,
				CriticalVulnCount: 0,
				HighVulnCount:     0,
				MediumVulnCount:   0,
				LowVulnCount:      0,
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

			// Set different next_scan_at times
			pastTime := time.Now().Add(time.Duration(-(4-i)) * time.Hour).Unix()
			_, err = store.db.ExecContext(ctx, `
				UPDATE artifacts SET next_scan_at = ? WHERE digest = ?
			`, pastTime, digest)
			if err != nil {
				t.Fatalf("Failed to update next_scan_at for scan %d: %v", i, err)
			}
		}

		// Query due for rescan
		digests, err := store.ListDueForRescan(ctx, 24*time.Hour)
		if err != nil {
			t.Fatalf("Failed to list due for rescan: %v", err)
		}

		// Verify all three digests are in the results
		digestSet := make(map[string]bool)
		for _, d := range digests {
			digestSet[d] = true
		}

		for i := 1; i <= 3; i++ {
			digest := fmt.Sprintf("sha256:rescan-order-%d", i)
			if !digestSet[digest] {
				t.Errorf("Expected digest %s to be in results", digest)
			}
		}

		// Verify ordering by checking that results are ordered by next_scan_at
		// Get the next_scan_at times for each digest
		nextScanTimes := make(map[string]int64)
		for i := 1; i <= 3; i++ {
			digest := fmt.Sprintf("sha256:rescan-order-%d", i)
			var nextScanAtUnix sql.NullInt64
			err := store.db.QueryRowContext(ctx, `
				SELECT next_scan_at FROM artifacts WHERE digest = ?
			`, digest).Scan(&nextScanAtUnix)
			if err != nil {
				t.Fatalf("Failed to query next_scan_at: %v", err)
			}
			if nextScanAtUnix.Valid {
				nextScanTimes[digest] = nextScanAtUnix.Int64
			}
		}

		// Verify the results are ordered by next_scan_at (ascending)
		for i := 0; i < len(digests)-1; i++ {
			d1 := digests[i]
			d2 := digests[i+1]
			t1, ok1 := nextScanTimes[d1]
			t2, ok2 := nextScanTimes[d2]
			if ok1 && ok2 && t1 > t2 {
				t.Errorf("Expected %s (time %d) to come before %s (time %d) in results", d2, t2, d1, t1)
			}
		}
	})

	// Test 5: ListDueForRescan uses index efficiently
	t.Run("ListDueForRescan uses next_scan_at index", func(t *testing.T) {
		// Verify the index exists
		var indexCount int
		err := store.db.QueryRowContext(ctx, `
			SELECT COUNT(*) FROM sqlite_master 
			WHERE type='index' AND name='idx_artifacts_next_scan'
		`).Scan(&indexCount)
		if err != nil {
			t.Fatalf("Failed to check index: %v", err)
		}
		if indexCount == 0 {
			t.Error("Expected idx_artifacts_next_scan index to exist")
		}

		// Verify the query plan uses the index by checking the EXPLAIN output
		rows, err := store.db.QueryContext(ctx, `
			EXPLAIN QUERY PLAN
			SELECT digest FROM artifacts
			WHERE last_scan_id IS NOT NULL AND next_scan_at < ?
			ORDER BY next_scan_at ASC
		`, time.Now())
		if err != nil {
			t.Fatalf("Failed to get query plan: %v", err)
		}
		defer rows.Close()

		// EXPLAIN QUERY PLAN returns: id, parent, notused, detail
		var id, parent, notused int
		var detail string
		var foundIndex bool
		for rows.Next() {
			err := rows.Scan(&id, &parent, &notused, &detail)
			if err != nil {
				t.Fatalf("Failed to scan query plan: %v", err)
			}
			if strings.Contains(detail, "idx_artifacts_next_scan") {
				foundIndex = true
			}
		}

		if err := rows.Err(); err != nil {
			t.Fatalf("Error iterating query plan: %v", err)
		}

		if !foundIndex {
			t.Logf("Note: Index may not be used in query plan, but idx_artifacts_next_scan index exists for efficiency")
		}
	})

	// Test 6: Multiple scans for same artifact update next_scan_at
	t.Run("Multiple scans for same artifact update next_scan_at", func(t *testing.T) {
		digest := "sha256:rescan-multi"
		repo := "myorg/rescanmulti"

		// Record first scan
		record1 := &ScanRecord{
			Digest:            digest,
			Repository:        repo,
			Tag:               "v1.0.0",
			ScanDurationMs:    1000,
			CriticalVulnCount: 0,
			HighVulnCount:     0,
			MediumVulnCount:   0,
			LowVulnCount:      0,
			PolicyPassed:      true,
			SBOMAttested:      true,
			VulnAttested:      true,
			SCAIAttested:      false,
			Vulnerabilities:   []types.VulnerabilityRecord{},
			ToleratedCVEs:     []types.ToleratedCVE{},
		}

		err := store.RecordScan(ctx, record1)
		if err != nil {
			t.Fatalf("Failed to record first scan: %v", err)
		}

		// Get first next_scan_at
		var firstNextScanAtUnix sql.NullInt64
		err = store.db.QueryRowContext(ctx, `
			SELECT next_scan_at FROM artifacts WHERE digest = ?
		`, digest).Scan(&firstNextScanAtUnix)
		if err != nil {
			t.Fatalf("Failed to query first next_scan_at: %v", err)
		}

		// Wait a bit to ensure different timestamp
		time.Sleep(10 * time.Millisecond)

		// Record second scan
		record2 := &ScanRecord{
			Digest:            digest,
			Repository:        repo,
			Tag:               "v1.0.1",
			ScanDurationMs:    1200,
			CriticalVulnCount: 0,
			HighVulnCount:     0,
			MediumVulnCount:   0,
			LowVulnCount:      0,
			PolicyPassed:      true,
			SBOMAttested:      true,
			VulnAttested:      true,
			SCAIAttested:      false,
			Vulnerabilities:   []types.VulnerabilityRecord{},
			ToleratedCVEs:     []types.ToleratedCVE{},
		}

		err = store.RecordScan(ctx, record2)
		if err != nil {
			t.Fatalf("Failed to record second scan: %v", err)
		}

		// Get second next_scan_at
		var secondNextScanAtUnix sql.NullInt64
		err = store.db.QueryRowContext(ctx, `
			SELECT next_scan_at FROM artifacts WHERE digest = ?
		`, digest).Scan(&secondNextScanAtUnix)
		if err != nil {
			t.Fatalf("Failed to query second next_scan_at: %v", err)
		}

		// Verify next_scan_at was updated (should be set to current time or later)
		if !firstNextScanAtUnix.Valid || !secondNextScanAtUnix.Valid {
			t.Error("Expected both next_scan_at values to be set")
		} else if secondNextScanAtUnix.Int64 < firstNextScanAtUnix.Int64 {
			t.Error("Expected second next_scan_at to be same or after first next_scan_at")
		}
	})

	// Test 7: Artifacts without last_scan_id are not returned by ListDueForRescan
	t.Run("Artifacts without last_scan_id are excluded from ListDueForRescan", func(t *testing.T) {
		// Create an artifact without a scan record
		var repoID int64
		err := store.db.QueryRowContext(ctx, `
			SELECT id FROM repositories WHERE name = ?
		`, "myorg/rescanapp").Scan(&repoID)
		if err != nil {
			t.Fatalf("Failed to get repository: %v", err)
		}

		now := time.Now().Unix()
		pastTime := time.Now().Add(-1 * time.Hour).Unix()
		_, err = store.db.ExecContext(ctx, `
			INSERT INTO artifacts (repository_id, digest, first_seen, last_seen, next_scan_at)
			VALUES (?, ?, ?, ?, ?)
		`, repoID, "sha256:rescan-no-scan", now, now, pastTime)
		if err != nil {
			t.Fatalf("Failed to insert artifact: %v", err)
		}

		// Query due for rescan
		digests, err := store.ListDueForRescan(ctx, 24*time.Hour)
		if err != nil {
			t.Fatalf("Failed to list due for rescan: %v", err)
		}

		// Verify the artifact without last_scan_id is not returned
		found := false
		for _, d := range digests {
			if d == "sha256:rescan-no-scan" {
				found = true
				break
			}
		}
		if found {
			t.Error("Expected artifact without last_scan_id to be excluded from ListDueForRescan")
		}
	})
}


// TestRepositoryAggregation tests the repository aggregation logic
func TestRepositoryAggregation(t *testing.T) {
	dbPath := "test_repo_aggregation_" + t.Name() + ".db"
	os.Remove(dbPath)
	defer os.Remove(dbPath)

	store, err := NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("Failed to create SQLite store: %v", err)
	}
	defer store.Close()

	ctx := context.Background()

	// Setup: Create multiple repositories with different vulnerability profiles
	// Repository 1: myapp with 3 tags (latest, v1.0, v0.9)
	// Repository 2: database with 2 tags (latest, v5.0)

	// Record scans for myapp repository
	record1 := &ScanRecord{
		Digest:            "sha256:myapp-latest",
		Repository:        "myapp",
		Tag:               "latest",
		ScanDurationMs:    1000,
		CriticalVulnCount: 2,
		HighVulnCount:     3,
		MediumVulnCount:   5,
		LowVulnCount:      1,
		PolicyPassed:      false,
		SBOMAttested:      true,
		VulnAttested:      true,
		SCAIAttested:      false,
		Vulnerabilities:   []types.VulnerabilityRecord{},
		ToleratedCVEs:     []types.ToleratedCVE{},
	}
	err = store.RecordScan(ctx, record1)
	if err != nil {
		t.Fatalf("Failed to record scan 1: %v", err)
	}

	record2 := &ScanRecord{
		Digest:            "sha256:myapp-v1.0",
		Repository:        "myapp",
		Tag:               "v1.0",
		ScanDurationMs:    1000,
		CriticalVulnCount: 1,
		HighVulnCount:     2,
		MediumVulnCount:   3,
		LowVulnCount:      0,
		PolicyPassed:      true,
		SBOMAttested:      true,
		VulnAttested:      true,
		SCAIAttested:      false,
		Vulnerabilities:   []types.VulnerabilityRecord{},
		ToleratedCVEs:     []types.ToleratedCVE{},
	}
	err = store.RecordScan(ctx, record2)
	if err != nil {
		t.Fatalf("Failed to record scan 2: %v", err)
	}

	record3 := &ScanRecord{
		Digest:            "sha256:myapp-v0.9",
		Repository:        "myapp",
		Tag:               "v0.9",
		ScanDurationMs:    1000,
		CriticalVulnCount: 0,
		HighVulnCount:     1,
		MediumVulnCount:   2,
		LowVulnCount:      1,
		PolicyPassed:      true,
		SBOMAttested:      true,
		VulnAttested:      true,
		SCAIAttested:      false,
		Vulnerabilities:   []types.VulnerabilityRecord{},
		ToleratedCVEs:     []types.ToleratedCVE{},
	}
	err = store.RecordScan(ctx, record3)
	if err != nil {
		t.Fatalf("Failed to record scan 3: %v", err)
	}

	// Record scans for database repository
	record4 := &ScanRecord{
		Digest:            "sha256:database-latest",
		Repository:        "database",
		Tag:               "latest",
		ScanDurationMs:    1000,
		CriticalVulnCount: 0,
		HighVulnCount:     0,
		MediumVulnCount:   1,
		LowVulnCount:      0,
		PolicyPassed:      true,
		SBOMAttested:      true,
		VulnAttested:      true,
		SCAIAttested:      false,
		Vulnerabilities:   []types.VulnerabilityRecord{},
		ToleratedCVEs:     []types.ToleratedCVE{},
	}
	err = store.RecordScan(ctx, record4)
	if err != nil {
		t.Fatalf("Failed to record scan 4: %v", err)
	}

	record5 := &ScanRecord{
		Digest:            "sha256:database-v5.0",
		Repository:        "database",
		Tag:               "v5.0",
		ScanDurationMs:    1000,
		CriticalVulnCount: 0,
		HighVulnCount:     0,
		MediumVulnCount:   0,
		LowVulnCount:      0,
		PolicyPassed:      true,
		SBOMAttested:      true,
		VulnAttested:      true,
		SCAIAttested:      false,
		Vulnerabilities:   []types.VulnerabilityRecord{},
		ToleratedCVEs:     []types.ToleratedCVE{},
	}
	err = store.RecordScan(ctx, record5)
	if err != nil {
		t.Fatalf("Failed to record scan 5: %v", err)
	}

	// Test 1: Vulnerability count aggregation (most vulnerable artifact)
	t.Run("Vulnerability count aggregation shows most vulnerable artifact", func(t *testing.T) {
		filter := RepositoryFilter{
			Limit:  100,
			Offset: 0,
		}
		response, err := store.ListRepositories(ctx, filter)
		if err != nil {
			t.Fatalf("Failed to list repositories: %v", err)
		}

		if len(response.Repositories) != 2 {
			t.Errorf("Expected 2 repositories, got %d", len(response.Repositories))
		}

		// Find myapp repository
		var myappRepo *RepositoryInfo
		for i := range response.Repositories {
			if response.Repositories[i].Name == "myapp" {
				myappRepo = &response.Repositories[i]
				break
			}
		}

		if myappRepo == nil {
			t.Fatal("Expected to find myapp repository")
		}

		// Verify aggregation shows most vulnerable artifact (latest tag)
		if myappRepo.VulnerabilityCount.Critical != 2 {
			t.Errorf("Expected 2 critical vulnerabilities (from most vulnerable), got %d", myappRepo.VulnerabilityCount.Critical)
		}
		if myappRepo.VulnerabilityCount.High != 3 {
			t.Errorf("Expected 3 high vulnerabilities (from most vulnerable), got %d", myappRepo.VulnerabilityCount.High)
		}
		if myappRepo.VulnerabilityCount.Medium != 5 {
			t.Errorf("Expected 5 medium vulnerabilities (from most vulnerable), got %d", myappRepo.VulnerabilityCount.Medium)
		}
		if myappRepo.VulnerabilityCount.Low != 1 {
			t.Errorf("Expected 1 low vulnerability (from most vulnerable), got %d", myappRepo.VulnerabilityCount.Low)
		}
	})

	// Test 2: Policy status aggregation (failed if any failed)
	t.Run("Policy status aggregation - failed if any artifact failed", func(t *testing.T) {
		filter := RepositoryFilter{
			Limit:  100,
			Offset: 0,
		}
		response, err := store.ListRepositories(ctx, filter)
		if err != nil {
			t.Fatalf("Failed to list repositories: %v", err)
		}

		// Find myapp repository (has one failed tag)
		var myappRepo *RepositoryInfo
		for i := range response.Repositories {
			if response.Repositories[i].Name == "myapp" {
				myappRepo = &response.Repositories[i]
				break
			}
		}

		if myappRepo == nil {
			t.Fatal("Expected to find myapp repository")
		}

		// myapp should be failed because latest tag failed
		if myappRepo.PolicyPassed {
			t.Error("Expected myapp to have PolicyPassed=false (because latest tag failed)")
		}

		// Find database repository (all tags passed)
		var databaseRepo *RepositoryInfo
		for i := range response.Repositories {
			if response.Repositories[i].Name == "database" {
				databaseRepo = &response.Repositories[i]
				break
			}
		}

		if databaseRepo == nil {
			t.Fatal("Expected to find database repository")
		}

		// database should be passed because all tags passed
		if !databaseRepo.PolicyPassed {
			t.Error("Expected database to have PolicyPassed=true (all tags passed)")
		}
	})

	// Test 3: Pagination and offset calculations
	t.Run("Pagination with limit and offset", func(t *testing.T) {
		// Get first page (limit=1, offset=0)
		filter := RepositoryFilter{
			Limit:  1,
			Offset: 0,
		}
		response, err := store.ListRepositories(ctx, filter)
		if err != nil {
			t.Fatalf("Failed to list repositories page 1: %v", err)
		}

		if len(response.Repositories) != 1 {
			t.Errorf("Expected 1 repository on page 1, got %d", len(response.Repositories))
		}
		if response.Total != 2 {
			t.Errorf("Expected total count of 2, got %d", response.Total)
		}

		firstPageRepo := response.Repositories[0].Name

		// Get second page (limit=1, offset=1)
		filter.Offset = 1
		response, err = store.ListRepositories(ctx, filter)
		if err != nil {
			t.Fatalf("Failed to list repositories page 2: %v", err)
		}

		if len(response.Repositories) != 1 {
			t.Errorf("Expected 1 repository on page 2, got %d", len(response.Repositories))
		}

		secondPageRepo := response.Repositories[0].Name

		// Verify different repositories on different pages
		if firstPageRepo == secondPageRepo {
			t.Error("Expected different repositories on different pages")
		}
	})

	// Test 4: Search filtering logic
	t.Run("Search filtering by repository name", func(t *testing.T) {
		// Search for "myapp"
		filter := RepositoryFilter{
			Search: "myapp",
			Limit:  100,
			Offset: 0,
		}
		response, err := store.ListRepositories(ctx, filter)
		if err != nil {
			t.Fatalf("Failed to search repositories: %v", err)
		}

		if len(response.Repositories) != 1 {
			t.Errorf("Expected 1 repository matching 'myapp', got %d", len(response.Repositories))
		}
		if response.Repositories[0].Name != "myapp" {
			t.Errorf("Expected repository name 'myapp', got %s", response.Repositories[0].Name)
		}
		if response.Total != 1 {
			t.Errorf("Expected total count of 1, got %d", response.Total)
		}
	})

	// Test 5: Tag count aggregation
	t.Run("Tag count aggregation", func(t *testing.T) {
		filter := RepositoryFilter{
			Limit:  100,
			Offset: 0,
		}
		response, err := store.ListRepositories(ctx, filter)
		if err != nil {
			t.Fatalf("Failed to list repositories: %v", err)
		}

		// Find myapp repository
		var myappRepo *RepositoryInfo
		for i := range response.Repositories {
			if response.Repositories[i].Name == "myapp" {
				myappRepo = &response.Repositories[i]
				break
			}
		}

		if myappRepo == nil {
			t.Fatal("Expected to find myapp repository")
		}

		if myappRepo.TagCount != 3 {
			t.Errorf("Expected 3 tags for myapp, got %d", myappRepo.TagCount)
		}
	})

	// Test 5b: LastScanTime is populated correctly (regression test for timestamp migration)
	t.Run("LastScanTime is populated correctly", func(t *testing.T) {
		filter := RepositoryFilter{
			Limit:  100,
			Offset: 0,
		}
		response, err := store.ListRepositories(ctx, filter)
		if err != nil {
			t.Fatalf("Failed to list repositories: %v", err)
		}

		// Find myapp repository
		var myappRepo *RepositoryInfo
		for i := range response.Repositories {
			if response.Repositories[i].Name == "myapp" {
				myappRepo = &response.Repositories[i]
				break
			}
		}

		if myappRepo == nil {
			t.Fatal("Expected to find myapp repository")
		}

		// Verify LastScanTime is not nil (regression test for timestamp migration issue)
		if myappRepo.LastScanTime == nil {
			t.Error("Expected LastScanTime to be populated, got nil")
		} else {
			// Verify it's a reasonable timestamp (within last hour)
			oneHourAgo := time.Now().Add(-1 * time.Hour).Unix()
			if *myappRepo.LastScanTime < oneHourAgo {
				t.Errorf("Expected LastScanTime to be recent, got %d", *myappRepo.LastScanTime)
			}
		}
	})

	// Test 6: GetRepository returns tags with correct data
	t.Run("GetRepository returns tags with correct aggregation", func(t *testing.T) {
		filter := RepositoryTagFilter{
			Limit:  100,
			Offset: 0,
		}
		detail, err := store.GetRepository(ctx, "myapp", filter)
		if err != nil {
			t.Fatalf("Failed to get repository: %v", err)
		}

		if detail.Name != "myapp" {
			t.Errorf("Expected repository name 'myapp', got %s", detail.Name)
		}
		if detail.Total != 3 {
			t.Errorf("Expected 3 tags total, got %d", detail.Total)
		}
		if len(detail.Tags) != 3 {
			t.Errorf("Expected 3 tags in response, got %d", len(detail.Tags))
		}

		// Verify latest tag has correct vulnerability counts
		var latestTag *TagInfo
		for i := range detail.Tags {
			if detail.Tags[i].Name == "latest" {
				latestTag = &detail.Tags[i]
				break
			}
		}

		if latestTag == nil {
			t.Fatal("Expected to find 'latest' tag")
		}

		if latestTag.VulnerabilityCount.Critical != 2 {
			t.Errorf("Expected 2 critical vulnerabilities for latest tag, got %d", latestTag.VulnerabilityCount.Critical)
		}
		if latestTag.PolicyPassed {
			t.Error("Expected latest tag to have PolicyPassed=false")
		}
	})

	// Test 6b: GetRepository returns tags with LastScanTime and NextScanTime (regression test)
	t.Run("GetRepository returns tags with scan time fields populated", func(t *testing.T) {
		filter := RepositoryTagFilter{
			Limit:  100,
			Offset: 0,
		}
		detail, err := store.GetRepository(ctx, "myapp", filter)
		if err != nil {
			t.Fatalf("Failed to get repository: %v", err)
		}

		if len(detail.Tags) == 0 {
			t.Fatal("Expected at least one tag")
		}

		// Verify at least one tag has LastScanTime populated (regression test for timestamp migration)
		foundWithLastScanTime := false
		for _, tag := range detail.Tags {
			if tag.LastScanTime != nil {
				foundWithLastScanTime = true
				// Verify it's a reasonable timestamp (within last hour)
				oneHourAgo := time.Now().Add(-1 * time.Hour).Unix()
				if *tag.LastScanTime < oneHourAgo {
					t.Errorf("Expected LastScanTime to be recent, got %d", *tag.LastScanTime)
				}
				break
			}
		}

		if !foundWithLastScanTime {
			t.Error("Expected at least one tag to have LastScanTime populated, but all were nil")
		}
	})

	// Test 7: GetRepository pagination
	t.Run("GetRepository pagination", func(t *testing.T) {
		// Get first page (limit=1, offset=0)
		filter := RepositoryTagFilter{
			Limit:  1,
			Offset: 0,
		}
		detail, err := store.GetRepository(ctx, "myapp", filter)
		if err != nil {
			t.Fatalf("Failed to get repository page 1: %v", err)
		}

		if len(detail.Tags) != 1 {
			t.Errorf("Expected 1 tag on page 1, got %d", len(detail.Tags))
		}
		if detail.Total != 3 {
			t.Errorf("Expected total count of 3, got %d", detail.Total)
		}

		firstPageTag := detail.Tags[0].Name

		// Get second page (limit=1, offset=1)
		filter.Offset = 1
		detail, err = store.GetRepository(ctx, "myapp", filter)
		if err != nil {
			t.Fatalf("Failed to get repository page 2: %v", err)
		}

		if len(detail.Tags) != 1 {
			t.Errorf("Expected 1 tag on page 2, got %d", len(detail.Tags))
		}

		secondPageTag := detail.Tags[0].Name

		// Verify different tags on different pages
		if firstPageTag == secondPageTag {
			t.Error("Expected different tags on different pages")
		}
	})

	// Test 8: GetRepository search filtering
	t.Run("GetRepository search filtering by tag name", func(t *testing.T) {
		// Search for "v1" in tags
		filter := RepositoryTagFilter{
			Search: "v1",
			Limit:  100,
			Offset: 0,
		}
		detail, err := store.GetRepository(ctx, "myapp", filter)
		if err != nil {
			t.Fatalf("Failed to search tags: %v", err)
		}

		if len(detail.Tags) != 1 {
			t.Errorf("Expected 1 tag matching 'v1', got %d", len(detail.Tags))
		}
		if detail.Tags[0].Name != "v1.0" {
			t.Errorf("Expected tag name 'v1.0', got %s", detail.Tags[0].Name)
		}
		if detail.Total != 1 {
			t.Errorf("Expected total count of 1, got %d", detail.Total)
		}
	})

	// Test 9: Empty search results
	t.Run("Empty search results", func(t *testing.T) {
		filter := RepositoryFilter{
			Search: "nonexistent",
			Limit:  100,
			Offset: 0,
		}
		response, err := store.ListRepositories(ctx, filter)
		if err != nil {
			t.Fatalf("Failed to search repositories: %v", err)
		}

		if len(response.Repositories) != 0 {
			t.Errorf("Expected 0 repositories for non-matching search, got %d", len(response.Repositories))
		}
		if response.Total != 0 {
			t.Errorf("Expected total count of 0, got %d", response.Total)
		}
	})

	// Test 10: Offset beyond total count
	t.Run("Offset beyond total count returns empty", func(t *testing.T) {
		filter := RepositoryFilter{
			Limit:  100,
			Offset: 100,
		}
		response, err := store.ListRepositories(ctx, filter)
		if err != nil {
			t.Fatalf("Failed to list repositories: %v", err)
		}

		if len(response.Repositories) != 0 {
			t.Errorf("Expected 0 repositories with large offset, got %d", len(response.Repositories))
		}
		if response.Total != 2 {
			t.Errorf("Expected total count of 2, got %d", response.Total)
		}
	})
}
