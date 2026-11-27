package statestore

import (
	"testing"

	"github.com/daimoniac/suppline/internal/types"
)

func TestDistroFactsRoundTrip(t *testing.T) {
	store, err := NewPostgresStore(testDatabaseURL(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	ctx := t.Context()
	const digest = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	if err := store.RecordScan(ctx, &ScanRecord{
		Repository:   "example/app",
		Digest:       digest,
		Tag:          "1",
		PolicyPassed: false,
		PolicyStatus: "failed",
		OSEndOfLife:  true,
		Vulnerabilities: []types.VulnerabilityRecord{{
			CVEID:          "CVE-2026-1",
			Severity:       "CRITICAL",
			PackageName:    "openssl",
			VendorStatus:   "affected",
			VendorSeverity: "LOW",
			AttackVector:   "LOCAL",
		}},
	}); err != nil {
		t.Fatal(err)
	}

	got, err := store.GetLastScan(ctx, digest)
	if err != nil {
		t.Fatal(err)
	}
	if !got.OSEndOfLife {
		t.Fatal("os end of life was not stored")
	}
	if len(got.Vulnerabilities) != 1 {
		t.Fatalf("findings = %+v", got.Vulnerabilities)
	}
	finding := got.Vulnerabilities[0]
	if finding.VendorStatus != "affected" || finding.VendorSeverity != "LOW" || finding.AttackVector != "LOCAL" {
		t.Fatalf("finding = %+v", finding)
	}

	listed, err := store.ListScans(ctx, ScanFilter{Repository: "example/app"})
	if err != nil {
		t.Fatal(err)
	}
	var scanID int64
	for _, scan := range listed {
		if scan.Digest == digest {
			scanID = scan.ID
			if !scan.OSEndOfLife {
				t.Fatal("list scans dropped os end of life")
			}
		}
	}
	if scanID == 0 {
		t.Fatal("scan missing from list")
	}
	history, err := store.GetScanHistory(ctx, digest, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(history) != 1 || !history[0].OSEndOfLife || len(history[0].Vulnerabilities) != 1 || history[0].Vulnerabilities[0].AttackVector != "LOCAL" {
		t.Fatalf("history = %+v", history)
	}

	byScan, err := store.LoadVulnerabilitiesByScanIDs(ctx, []int64{scanID})
	if err != nil {
		t.Fatal(err)
	}
	loaded := byScan[scanID]
	if len(loaded) != 1 || loaded[0].VendorStatus != "affected" || loaded[0].VendorSeverity != "LOW" || loaded[0].AttackVector != "LOCAL" {
		t.Fatalf("replay findings = %+v", loaded)
	}
}
