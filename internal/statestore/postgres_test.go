package statestore

import (
	"os"
	"testing"

	"github.com/daimoniac/suppline/internal/types"
)

func TestPostgresStoreRoundTrip(t *testing.T) {
	url := os.Getenv("SUPPLINE_TEST_POSTGRES_URL")
	if url == "" {
		t.Skip("set SUPPLINE_TEST_POSTGRES_URL to run postgres smoke tests")
	}

	store, err := NewPostgresStore(url)
	if err != nil {
		t.Fatalf("NewPostgresStore: %v", err)
	}
	defer store.Close()

	ctx := t.Context()
	if err := store.RecordScan(ctx, &ScanRecord{
		Repository:        "library/alpine",
		Digest:            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Tag:               "3.20",
		PolicyPassed:      true,
		PolicyStatus:      "passed",
		CriticalVulnCount: 0,
		HighVulnCount:     0,
		MediumVulnCount:   0,
		LowVulnCount:      0,
		Vulnerabilities: []types.VulnerabilityRecord{
			{CVEID: "CVE-2024-0001", Severity: "LOW", PackageName: "musl", Title: "test"},
		},
	}); err != nil {
		t.Fatalf("RecordScan: %v", err)
	}

	// A rescan commonly has no image-created timestamp. PostgreSQL must still be
	// able to type the NULL parameter when updating the existing artifact.
	if err := store.RecordScan(ctx, &ScanRecord{
		Repository:        "library/alpine",
		Digest:            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Tag:               "3.20",
		PolicyPassed:      true,
		PolicyStatus:      "passed",
		CriticalVulnCount: 0,
		HighVulnCount:     0,
		MediumVulnCount:   0,
		LowVulnCount:      0,
	}); err != nil {
		t.Fatalf("RecordScan existing artifact with unknown image timestamp: %v", err)
	}

	got, err := store.GetLastScan(ctx, "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	if err != nil {
		t.Fatalf("GetLastScan: %v", err)
	}
	if got == nil || !got.PolicyPassed || len(got.Vulnerabilities) != 1 {
		t.Fatalf("unexpected last scan: %+v", got)
	}
}

func TestNormalizeCopyValueBool(t *testing.T) {
	if got := normalizeCopyValue("policy_passed", int64(1)); got != true {
		t.Fatalf("got %v", got)
	}
	if got := normalizeCopyValue("policy_passed", int64(0)); got != false {
		t.Fatalf("got %v", got)
	}
}
