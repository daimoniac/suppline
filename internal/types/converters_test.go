package types

import (
	"testing"
	"time"
)

// Example tests demonstrating how to test the types package

func TestToVulnerabilityRecord(t *testing.T) {
	vuln := Vulnerability{
		ID:           "CVE-2024-1234",
		Severity:     "HIGH",
		PackageName:  "openssl",
		Version:      "1.0.0",
		FixedVersion: "1.0.1",
		Title:        "Test Vulnerability",
		Description:  "Test description",
		PrimaryURL:   "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-1234",
	}

	scannedAt := time.Now()
	record := ToVulnerabilityRecord(
		vuln,
		"myrepo/myimage",
		"v1.0.0",
		"sha256:abc123",
		scannedAt,
	)

	// Verify vulnerability fields
	if record.CVEID != "CVE-2024-1234" {
		t.Errorf("Expected CVEID CVE-2024-1234, got %s", record.CVEID)
	}
	if record.Severity != "HIGH" {
		t.Errorf("Expected Severity HIGH, got %s", record.Severity)
	}

	// Verify image context
	if record.Repository != "myrepo/myimage" {
		t.Errorf("Expected Repository myrepo/myimage, got %s", record.Repository)
	}
	if record.Tag != "v1.0.0" {
		t.Errorf("Expected Tag v1.0.0, got %s", record.Tag)
	}
	if record.Digest != "sha256:abc123" {
		t.Errorf("Expected Digest sha256:abc123, got %s", record.Digest)
	}
	if !record.ScannedAt.Equal(scannedAt) {
		t.Errorf("Expected ScannedAt %v, got %v", scannedAt, record.ScannedAt)
	}
}

func TestFilterToleratedCVEs(t *testing.T) {
	tolerations := []CVEToleration{
		{ID: "CVE-2024-1234", Statement: "Tolerated 1"},
		{ID: "CVE-2024-5678", Statement: "Tolerated 2"},
		{ID: "CVE-2024-9999", Statement: "Not tolerated"},
	}

	toleratedSet := map[string]bool{
		"CVE-2024-1234": true,
		"CVE-2024-5678": true,
	}

	filtered := FilterToleratedCVEs(tolerations, toleratedSet, time.Now())

	if len(filtered) != 2 {
		t.Errorf("Expected 2 filtered tolerations, got %d", len(filtered))
	}

	// Verify only tolerated CVEs are included
	for _, tc := range filtered {
		if !toleratedSet[tc.CVEID] {
			t.Errorf("Unexpected CVE in filtered results: %s", tc.CVEID)
		}
	}

	// Verify excluded CVE is not present
	for _, tc := range filtered {
		if tc.CVEID == "CVE-2024-9999" {
			t.Errorf("CVE-2024-9999 should not be in filtered results")
		}
	}
}

// Note: Adapter tests removed in Phase 4
// Since scanner.Vulnerability = types.Vulnerability (type alias)
// and queue.CVEToleration = types.CVEToleration (type alias),
// no adapter functions or tests are needed anymore.
