package triage

import (
	"testing"

	"github.com/daimoniac/suppline/internal/statestore"
	"github.com/daimoniac/suppline/internal/types"
)

func TestCVEHashIgnoresDigestAndDescription(t *testing.T) {
	base := Job{
		CVEID:    "CVE-1",
		Severity: "HIGH",
		Packages: []PackageFact{
			{Name: "nginx", Installed: "1.2.3", Fixed: "1.2.4"},
			{Name: "nginx", Installed: "1.1.0", Fixed: "1.2.4"},
		},
		Description: "first",
		Digest:      "sha256:aaa",
	}
	same := base
	same.Description = "different wording"
	same.Digest = "sha256:bbb"
	same.Packages = []PackageFact{
		{Name: "nginx", Installed: "1.1.0", Fixed: "1.2.4"},
		{Name: "nginx", Installed: "1.2.3", Fixed: "1.2.4"},
	}
	if base.cveHash() != same.cveHash() {
		t.Fatalf("hash changed for the same package set: %s vs %s", base.cveHash(), same.cveHash())
	}
	changed := base
	changed.Packages = []PackageFact{{Name: "nginx", Installed: "1.2.3", Fixed: "1.2.5"}}
	if base.cveHash() == changed.cveHash() {
		t.Fatal("hash ignored a fixed-version change")
	}
	legacy := Job{CVEID: "CVE-1", PackageName: "nginx", Version: "1.2.3", FixedVersion: "1.2.4", Severity: "HIGH", Description: "ignored"}
	other := legacy
	other.Description = "still ignored"
	if legacy.cveHash() != other.cveHash() {
		t.Fatal("legacy hash still includes the description")
	}
}

func TestResolveGroupPicksNewestInUseDigest(t *testing.T) {
	records := []*statestore.ScanRecord{
		scanRow("app", "sha256:old", "9.4.0", 100, true, 1, "CVE-1", "nginx", "1.1.0", "1.3.0", "HIGH"),
		scanRow("app", "sha256:new", "9.5.1", 200, true, 4, "CVE-1", "nginx", "1.2.3", "1.3.0", "HIGH"),
		scanRow("app", "sha256:idle", "8.0.0", 300, false, 0, "CVE-1", "nginx", "1.0.0", "1.3.0", "CRITICAL"),
		scanRow("app", "sha256:new", "9.5.1-extra", 200, true, 4, "CVE-2", "openssl", "3", "4", "MEDIUM"),
	}
	jobs := resolveGroup(records, "app", []string{"CVE-1", "CVE-2", "CVE-missing"}, true)
	if len(jobs) != 2 {
		t.Fatalf("jobs = %+v", jobs)
	}
	if jobs[0].CVEID != "CVE-1" || jobs[0].Digest != "sha256:new" || jobs[0].Tag != "9.5.1" {
		t.Fatalf("representative = %+v", jobs[0])
	}
	if jobs[0].Version != "1.2.3" || jobs[0].Severity != "CRITICAL" {
		t.Fatalf("facts = %+v", jobs[0])
	}
	if len(jobs[0].Packages) != 3 {
		t.Fatalf("packages = %+v", jobs[0].Packages)
	}
	if len(jobs[0].InUse) != 2 {
		t.Fatalf("in use = %+v", jobs[0].InUse)
	}
	if jobs[1].CVEID != "CVE-2" || jobs[1].Digest != "sha256:new" {
		t.Fatalf("second = %+v", jobs[1])
	}
	if jobs[0].cveHash() == jobs[1].cveHash() {
		t.Fatal("different CVEs hashed the same")
	}
}

func TestResolveGroupDropsIdleOnlyCVEWhenInUse(t *testing.T) {
	records := []*statestore.ScanRecord{
		scanRow("app", "sha256:run", "1", 10, true, 1, "CVE-run", "nginx", "1", "2", "LOW"),
		scanRow("app", "sha256:idle", "2", 20, false, 0, "CVE-idle", "nginx", "1", "2", "LOW"),
	}
	jobs := resolveGroup(records, "app", []string{"CVE-idle", "CVE-run"}, true)
	if len(jobs) != 1 || jobs[0].CVEID != "CVE-run" {
		t.Fatalf("jobs = %+v", jobs)
	}
	all := resolveGroup(records, "app", []string{"CVE-idle"}, false)
	if len(all) != 1 || all[0].CVEID != "CVE-idle" || all[0].Digest != "sha256:run" || all[0].Version != "1" {
		t.Fatalf("representative should stay the in-use digest: %+v", all)
	}
	idleOnly := []*statestore.ScanRecord{
		scanRow("app", "sha256:idle", "2", 20, false, 0, "CVE-idle", "nginx", "1", "2", "LOW"),
	}
	fallback := resolveGroup(idleOnly, "app", []string{"CVE-idle"}, false)
	if len(fallback) != 1 || fallback[0].Digest != "sha256:idle" {
		t.Fatalf("idle fallback = %+v", fallback)
	}
	if resolveGroup(records, "app", []string{"CVE-idle"}, true) != nil {
		t.Fatal("idle CVE was triaged while only_in_use is on")
	}
}

func TestResolveGroupSkipsWhenNothingIsRunning(t *testing.T) {
	records := []*statestore.ScanRecord{
		scanRow("app", "sha256:idle", "1", 10, false, 0, "CVE-1", "nginx", "1", "2", "LOW"),
	}
	if resolveGroup(records, "app", []string{"CVE-1"}, true) != nil {
		t.Fatal("queued a repository with no in-use digest")
	}
}

func scanRow(repo, digest, tag string, created int64, inUse bool, placements int, cve, pkg, installed, fixed, severity string) *statestore.ScanRecord {
	record := &statestore.ScanRecord{
		Repository:     repo,
		Digest:         digest,
		Tag:            tag,
		ImageCreatedAt: created,
		RuntimeUsed:    inUse,
		Vulnerabilities: []types.VulnerabilityRecord{{
			CVEID:            cve,
			PackageName:      pkg,
			InstalledVersion: installed,
			FixedVersion:     fixed,
			Severity:         severity,
			Description:      "details for " + cve,
		}},
		PolicyFailureFindings: []types.PolicyFailureFinding{{CVEID: cve, PackageName: pkg}},
	}
	if placements > 0 {
		images := make([]statestore.RuntimeImage, placements)
		for i := range images {
			images[i] = statestore.RuntimeImage{ImageRef: repo, Tag: tag, Digest: digest}
		}
		record.Runtime = statestore.RuntimeInventory{"c": {"ns": images}}
	}
	return record
}
