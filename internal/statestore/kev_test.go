package statestore

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/daimoniac/suppline/internal/types"
)

func recordKEVScan(t *testing.T, store *Store, repository, digest, tag string, passed bool, cves []string, exempted []string) {
	t.Helper()
	record := &ScanRecord{
		Digest:       digest,
		Repository:   repository,
		Tag:          tag,
		PolicyPassed: passed,
	}
	for _, cve := range cves {
		record.Vulnerabilities = append(record.Vulnerabilities, types.VulnerabilityRecord{
			CVEID: cve, Severity: "HIGH", PackageName: "pkg-" + cve, InstalledVersion: "1",
		})
	}
	for _, cve := range exempted {
		record.AppliedVEXStatements = append(record.AppliedVEXStatements, types.AppliedVEXStatement{
			CVEID: cve, State: types.VEXStateNotAffected, AppliedAt: time.Now().Unix(),
		})
	}
	if err := store.RecordScan(context.Background(), record); err != nil {
		t.Fatalf("record scan: %v", err)
	}
}

func TestListKEVImagesSkipsExemptedFindings(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	// app: one listed CVE exempted, one not.
	recordKEVScan(t, store, "reg/app", "sha256:a", "1.0", true, []string{"CVE-1", "CVE-2", "CVE-9"}, []string{"CVE-1"})
	// The same digest under a second tag must count once.
	recordKEVScan(t, store, "reg/app", "sha256:a", "latest", true, []string{"CVE-1", "CVE-2", "CVE-9"}, []string{"CVE-1"})
	// exempt: its only listed CVE is exempted.
	recordKEVScan(t, store, "reg/exempt", "sha256:b", "1", true, []string{"CVE-1"}, []string{"CVE-1"})
	// failing: listed CVE, policy failed.
	recordKEVScan(t, store, "reg/failing", "sha256:c", "1", false, []string{"CVE-1", "CVE-3"}, nil)
	// clean: no listed CVE.
	recordKEVScan(t, store, "reg/clean", "sha256:d", "1", true, []string{"CVE-9"}, nil)

	images, err := store.ListKEVImages(ctx, []string{"CVE-1", "CVE-2", "CVE-3"})
	if err != nil {
		t.Fatal(err)
	}
	want := []KEVImage{
		{Repository: "reg/app", Digest: "sha256:a", Tags: []string{"1.0", "latest"}, PolicyPassed: true, CVEs: []string{"CVE-2"}},
		{Repository: "reg/failing", Digest: "sha256:c", Tags: []string{"1"}, PolicyPassed: false, CVEs: []string{"CVE-1", "CVE-3"}},
	}
	if !reflect.DeepEqual(images, want) {
		t.Fatalf("images = %+v\nwant     %+v", images, want)
	}

	if none, err := store.ListKEVImages(ctx, nil); err != nil || len(none) != 0 {
		t.Fatalf("no IDs must list nothing: %v %v", none, err)
	}
}

func TestVulnerabilityPageOnlyCVEIDs(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	recordKEVScan(t, store, "reg/app", "sha256:a", "1", true, []string{"CVE-1", "CVE-2", "CVE-3"}, nil)

	ids, total, err := store.ListVulnerabilityCVEPage(ctx, VulnFilter{OnlyCVEIDs: []string{"CVE-3", "CVE-1", "CVE-404"}}, "cve_id", "asc", 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if total != 2 || !reflect.DeepEqual(ids, []string{"CVE-1", "CVE-3"}) {
		t.Fatalf("ids=%v total=%d", ids, total)
	}
	ids, total, err = store.ListVulnerabilityCVEPage(ctx, VulnFilter{OnlyCVEIDs: []string{}}, "cve_id", "asc", 10, 0)
	if err != nil || total != 0 || len(ids) != 0 {
		t.Fatalf("an empty restriction must match nothing: ids=%v total=%d err=%v", ids, total, err)
	}
	if _, total, err = store.ListVulnerabilityCVEPage(ctx, VulnFilter{}, "cve_id", "asc", 10, 0); err != nil || total != 3 {
		t.Fatalf("nil restriction must match all: total=%d err=%v", total, err)
	}
}
