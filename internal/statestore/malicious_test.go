package statestore

import (
	"context"
	"reflect"
	"testing"

	"github.com/daimoniac/suppline/internal/types"
)

const maliciousTestDigest = "sha256:aaaa1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234"

func TestRecordScanStoresMaliciousCheck(t *testing.T) {
	store, cleanup := createTestStore(t)
	defer cleanup()
	ctx := context.Background()

	check := &types.MaliciousCheck{
		Status:     types.MaliciousCheckOK,
		Commit:     "abc123",
		SnapshotAt: 1700000000,
		Findings: []types.MaliciousFinding{{
			ID: "MAL-2025-1", Ecosystem: "npm", PackageName: "evil", Version: "1.0.0",
			PURL: "pkg:npm/evil@1.0.0", Summary: "Malicious code in evil (npm)", URL: "https://osv.dev/vulnerability/MAL-2025-1",
		}},
	}
	err := store.RecordScan(ctx, &ScanRecord{
		Repository: "library/app", Digest: maliciousTestDigest, Tag: "1.0",
		PolicyPassed: false, PolicyStatus: "failed",
		PolicyFailureFindings: []types.PolicyFailureFinding{{CVEID: "MAL-2025-1", PackageName: "evil", Kind: types.PolicyFailureKindMalicious}},
		Malicious:             check,
	})
	if err != nil {
		t.Fatalf("RecordScan: %v", err)
	}

	last, err := store.GetLastScan(ctx, maliciousTestDigest)
	if err != nil {
		t.Fatalf("GetLastScan: %v", err)
	}
	if !reflect.DeepEqual(last.Malicious, check) {
		t.Fatalf("malicious check mismatch\n got: %+v\nwant: %+v", last.Malicious, check)
	}
	if len(last.PolicyFailureFindings) != 1 || !last.PolicyFailureFindings[0].IsMalicious() {
		t.Fatalf("expected a malicious failure finding, got %+v", last.PolicyFailureFindings)
	}

	listed, err := store.(*Store).ListScans(ctx, ScanFilter{})
	if err != nil {
		t.Fatalf("ListScans: %v", err)
	}
	if len(listed) != 1 || !reflect.DeepEqual(listed[0].Malicious, check) {
		t.Fatalf("ListScans malicious check mismatch: %+v", listed)
	}

	// A scan without a check stores none.
	if err := store.RecordScan(ctx, &ScanRecord{Repository: "library/app", Digest: maliciousTestDigest, Tag: "1.0", PolicyPassed: true, PolicyStatus: "passed"}); err != nil {
		t.Fatalf("RecordScan without check: %v", err)
	}
	last, err = store.GetLastScan(ctx, maliciousTestDigest)
	if err != nil {
		t.Fatalf("GetLastScan: %v", err)
	}
	if last.Malicious != nil {
		t.Fatalf("expected no check, got %+v", last.Malicious)
	}
}

func TestPackageInventoryReplaceAndCleanup(t *testing.T) {
	store, cleanup := createTestStore(t)
	defer cleanup()
	pgStore := store.(*Store)
	ctx := context.Background()

	for _, tag := range []string{"1.0", "latest"} {
		if err := store.RecordScan(ctx, &ScanRecord{Repository: "library/app", Digest: maliciousTestDigest, Tag: tag, PolicyPassed: true, PolicyStatus: "passed"}); err != nil {
			t.Fatalf("RecordScan(%s): %v", tag, err)
		}
	}

	first := []types.PackageRef{
		{Ecosystem: "npm", Name: "a", Version: "1.0.0", PURL: "pkg:npm/a@1.0.0"},
		{Ecosystem: "npm", Name: "a", Version: "1.0.0", PURL: "pkg:npm/a@1.0.0"},
		{Ecosystem: "PyPI", Name: "b", Version: "2.0", PURL: "pkg:pypi/b@2.0"},
	}
	if err := pgStore.ReplacePackageInventory(ctx, maliciousTestDigest, first); err != nil {
		t.Fatalf("ReplacePackageInventory: %v", err)
	}
	second := []types.PackageRef{{Ecosystem: "npm", Name: "c", Version: "3.0.0", PURL: "pkg:npm/c@3.0.0"}}
	if err := pgStore.ReplacePackageInventory(ctx, maliciousTestDigest, second); err != nil {
		t.Fatalf("ReplacePackageInventory: %v", err)
	}
	got, err := pgStore.ListPackageInventory(ctx, maliciousTestDigest)
	if err != nil {
		t.Fatalf("ListPackageInventory: %v", err)
	}
	if !reflect.DeepEqual(got, second) {
		t.Fatalf("inventory not replaced: %+v", got)
	}

	// Removing one of two tags keeps the digest, so the inventory stays.
	if err := store.CleanupArtifactTag(ctx, "library/app", maliciousTestDigest, "1.0"); err != nil {
		t.Fatalf("CleanupArtifactTag: %v", err)
	}
	if got, _ := pgStore.ListPackageInventory(ctx, maliciousTestDigest); len(got) != 1 {
		t.Fatalf("inventory must survive while a tag remains, got %+v", got)
	}

	// Removing the last tag drops the digest and its inventory.
	if err := store.CleanupArtifactTag(ctx, "library/app", maliciousTestDigest, "latest"); err != nil {
		t.Fatalf("CleanupArtifactTag: %v", err)
	}
	if got, _ := pgStore.ListPackageInventory(ctx, maliciousTestDigest); len(got) != 0 {
		t.Fatalf("inventory must be removed with the digest, got %+v", got)
	}
}

func TestPackageInventoryRemovedWithRepositoryAndDigest(t *testing.T) {
	store, cleanup := createTestStore(t)
	defer cleanup()
	pgStore := store.(*Store)
	ctx := context.Background()
	other := "sha256:bbbb1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234"
	pkgs := []types.PackageRef{{Ecosystem: "npm", Name: "a", Version: "1.0.0", PURL: "pkg:npm/a@1.0.0"}}

	for _, digest := range []string{maliciousTestDigest, other} {
		if err := store.RecordScan(ctx, &ScanRecord{Repository: "library/app", Digest: digest, Tag: digest[7:12], PolicyPassed: true, PolicyStatus: "passed"}); err != nil {
			t.Fatalf("RecordScan: %v", err)
		}
		if err := pgStore.ReplacePackageInventory(ctx, digest, pkgs); err != nil {
			t.Fatalf("ReplacePackageInventory: %v", err)
		}
	}

	if err := store.CleanupArtifactScans(ctx, maliciousTestDigest); err != nil {
		t.Fatalf("CleanupArtifactScans: %v", err)
	}
	if got, _ := pgStore.ListPackageInventory(ctx, maliciousTestDigest); len(got) != 0 {
		t.Fatalf("inventory must be removed with the digest, got %+v", got)
	}
	if got, _ := pgStore.ListPackageInventory(ctx, other); len(got) != 1 {
		t.Fatalf("other digest must keep its inventory, got %+v", got)
	}

	if err := store.CleanupRepository(ctx, "library/app"); err != nil {
		t.Fatalf("CleanupRepository: %v", err)
	}
	if got, _ := pgStore.ListPackageInventory(ctx, other); len(got) != 0 {
		t.Fatalf("inventory must be removed with the repository, got %+v", got)
	}
}
