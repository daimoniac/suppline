package types

import (
	"testing"
	"time"
)

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

	scannedAt := time.Now().Unix()
	record := ToVulnerabilityRecord(
		vuln,
		"myrepo/myimage",
		"v1.0.0",
		"sha256:abc123",
		scannedAt,
	)

	if record.CVEID != "CVE-2024-1234" {
		t.Errorf("Expected CVEID CVE-2024-1234, got %s", record.CVEID)
	}
	if record.Severity != "HIGH" {
		t.Errorf("Expected Severity HIGH, got %s", record.Severity)
	}

	if record.Repository != "myrepo/myimage" {
		t.Errorf("Expected Repository myrepo/myimage, got %s", record.Repository)
	}
	if record.Tag != "v1.0.0" {
		t.Errorf("Expected Tag v1.0.0, got %s", record.Tag)
	}
	if record.Digest != "sha256:abc123" {
		t.Errorf("Expected Digest sha256:abc123, got %s", record.Digest)
	}
	if record.ScannedAt != scannedAt {
		t.Errorf("Expected ScannedAt %d, got %d", scannedAt, record.ScannedAt)
	}
}
