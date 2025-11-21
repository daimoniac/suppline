package statestore

import (
	"context"
	"github.com/daimoniac/suppline/internal/types"
	"os"
	"testing"
	"time"
)

func TestSQLiteStore(t *testing.T) {
	// Create temporary database file
	dbPath := "test_statestore.db"
	defer os.Remove(dbPath)

	store, err := NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("Failed to create SQLite store: %v", err)
	}
	defer store.Close()

	ctx := context.Background()

	// Test RecordScan
	t.Run("RecordScan", func(t *testing.T) {
		expiresAt := time.Now().Add(30 * 24 * time.Hour)
		record := &ScanRecord{
			Digest:            "sha256:abc123",
			Repository:        "myorg/myapp",
			Tag:               "v1.0.0",
			ScannedAt:         time.Now(),
			CriticalVulnCount: 2,
			HighVulnCount:     5,
			MediumVulnCount:   10,
			LowVulnCount:      3,
			PolicyPassed:      false,
			SBOMAttested:      true,
			VulnAttested:      true,
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
					ToleratedAt: time.Now(),
					ExpiresAt:   &expiresAt,
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
		// Add another scan for the same digest
		record := &ScanRecord{
			Digest:            "sha256:abc123",
			Repository:        "myorg/myapp",
			Tag:               "v1.0.1",
			ScannedAt:         time.Now().Add(1 * time.Hour),
			CriticalVulnCount: 0,
			HighVulnCount:     3,
			MediumVulnCount:   5,
			LowVulnCount:      2,
			PolicyPassed:      true,
			SBOMAttested:      true,
			VulnAttested:      true,
			Vulnerabilities:   []types.VulnerabilityRecord{},
			ToleratedCVEs:     []types.ToleratedCVE{},
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
	})

	// Test ListDueForRescan
	t.Run("ListDueForRescan", func(t *testing.T) {
		// Add an old scan
		oldRecord := &ScanRecord{
			Digest:            "sha256:old123",
			Repository:        "myorg/oldapp",
			Tag:               "v0.1.0",
			ScannedAt:         time.Now().Add(-48 * time.Hour),
			CriticalVulnCount: 0,
			HighVulnCount:     0,
			MediumVulnCount:   0,
			LowVulnCount:      0,
			PolicyPassed:      true,
			SBOMAttested:      true,
			VulnAttested:      true,
			Vulnerabilities:   []types.VulnerabilityRecord{},
			ToleratedCVEs:     []types.ToleratedCVE{},
		}
		err := store.RecordScan(ctx, oldRecord)
		if err != nil {
			t.Fatalf("Failed to record old scan: %v", err)
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
			CVEID: "CVE-2024-1234",
			Limit: 10,
		}
		vulns, err := store.QueryVulnerabilities(ctx, filter)
		if err != nil {
			t.Fatalf("Failed to query vulnerabilities: %v", err)
		}
		if len(vulns) == 0 {
			t.Error("Expected at least one vulnerability")
		}
		if vulns[0].CVEID != "CVE-2024-1234" {
			t.Errorf("Expected CVE-2024-1234, got %s", vulns[0].CVEID)
		}
	})

	// Test GetImagesByCVE
	t.Run("GetImagesByCVE", func(t *testing.T) {
		images, err := store.GetImagesByCVE(ctx, "CVE-2024-1234")
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
}
