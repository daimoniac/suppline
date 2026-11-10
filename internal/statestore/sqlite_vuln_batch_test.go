package statestore

import (
	"context"
	"testing"

	"github.com/daimoniac/suppline/internal/types"
)

func TestLoadVulnerabilitiesByScanIDsBatchesFindings(t *testing.T) {
	store, err := NewSQLiteStore(t.TempDir() + "/vuln-batch.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	ctx := context.Background()
	record := func(digest, cve string) {
		t.Helper()
		scan := &ScanRecord{
			Repository:   "example/app",
			Digest:       digest,
			Tag:          digest,
			PolicyPassed: true,
			PolicyStatus: "passed",
			Vulnerabilities: []types.VulnerabilityRecord{{
				CVEID: cve, Severity: "LOW", PackageName: "libc", InstalledVersion: "1",
			}},
		}
		if err := store.RecordScan(ctx, scan); err != nil {
			t.Fatal(err)
		}
	}
	record("sha256:one", "CVE-1")
	record("sha256:two", "CVE-2")

	listed, err := store.ListScans(ctx, ScanFilter{})
	if err != nil {
		t.Fatal(err)
	}
	ids := make([]int64, 0, len(listed))
	for _, scan := range listed {
		ids = append(ids, scan.ID)
	}
	got, err := store.LoadVulnerabilitiesByScanIDs(ctx, append(ids, ids...))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("scans with findings = %d, want 2", len(got))
	}
	seen := map[string]bool{}
	for _, vulns := range got {
		if len(vulns) != 1 {
			t.Fatalf("findings = %+v", vulns)
		}
		seen[vulns[0].CVEID] = true
	}
	if !seen["CVE-1"] || !seen["CVE-2"] {
		t.Fatalf("cves = %v", seen)
	}

	empty, err := store.LoadVulnerabilitiesByScanIDs(ctx, nil)
	if err != nil || len(empty) != 0 {
		t.Fatalf("empty load = %v, %v", empty, err)
	}
}
