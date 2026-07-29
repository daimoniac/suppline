package statestore

import (
	"context"
	"testing"
)

// Regression for 782e982/3fa1adf interaction with multi-tag digests:
// when aliases share last_scan_id pointing at a scan owned by one artifact,
// removing that artifact must not strip scan results from surviving siblings.
func TestCleanupArtifactTag_PreservesSharedScanOnSiblingAlias(t *testing.T) {
	store, cleanup := createTestStore(t)
	defer cleanup()

	sqliteStore := store.(*SQLiteStore)
	ctx := context.Background()
	repo := "hostingmaloonde/kong"
	digest := "sha256:c944149b4d0aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

	// Scan under canonical tag first, then bind the alias (inherits last_scan_id).
	if err := store.RecordScan(ctx, &ScanRecord{
		Repository:        repo,
		Digest:            digest,
		Tag:               "3.0",
		CriticalVulnCount: 2,
		PolicyPassed:      false,
		PolicyStatus:      "failed",
		PolicyReason:      "critical",
	}); err != nil {
		t.Fatalf("RecordScan(3.0): %v", err)
	}
	created, err := store.EnsureArtifactTagBinding(ctx, repo, digest, "3.0.2")
	if err != nil || !created {
		t.Fatalf("EnsureArtifactTagBinding: created=%v err=%v", created, err)
	}

	// Registry drops tag 3.0 but keeps 3.0.2 on the same digest.
	if err := store.CleanupArtifactTag(ctx, repo, digest, "3.0"); err != nil {
		t.Fatalf("CleanupArtifactTag(3.0): %v", err)
	}

	detail, err := sqliteStore.GetRepository(ctx, repo, RepositoryTagFilter{})
	if err != nil {
		t.Fatalf("GetRepository: %v", err)
	}
	if len(detail.Tags) != 1 || detail.Tags[0].Name != "3.0.2" {
		t.Fatalf("expected only surviving alias 3.0.2, got %+v", detail.Tags)
	}
	surviving := detail.Tags[0]
	if surviving.Digest != digest {
		t.Fatalf("surviving digest=%s want %s", surviving.Digest, digest)
	}
	if surviving.PolicyStatus != "failed" || surviving.VulnerabilityCount.Critical != 2 {
		t.Fatalf("surviving alias lost shared scan results: %+v", surviving)
	}
}

func TestRecordScan_RetagPreservesSiblingSharedScan(t *testing.T) {
	store, cleanup := createTestStore(t)
	defer cleanup()

	sqliteStore := store.(*SQLiteStore)
	ctx := context.Background()
	repo := "hostingmaloonde/dhi_grafana"
	oldDigest := "sha256:245a7ae34af1f3503a8dffadca09032ca86e26b59dae07164982a356ce6fa08c"
	newDigest := "sha256:cbad2dcfb2ae3b44bcfcff14f68cdc9b4bcf6ce45bc9990b46dc1d6e0f513a84"

	// Sibling first, then canonical — so the shared last_scan_id is owned by "13.1".
	if err := store.RecordScan(ctx, &ScanRecord{
		Repository:        repo,
		Digest:            oldDigest,
		Tag:               "13.1.1",
		CriticalVulnCount: 1,
		PolicyPassed:      false,
		PolicyStatus:      "failed",
	}); err != nil {
		t.Fatalf("RecordScan(13.1.1): %v", err)
	}
	if err := store.RecordScan(ctx, &ScanRecord{
		Repository:        repo,
		Digest:            oldDigest,
		Tag:               "13.1",
		CriticalVulnCount: 1,
		PolicyPassed:      false,
		PolicyStatus:      "failed",
	}); err != nil {
		t.Fatalf("RecordScan(13.1 old): %v", err)
	}

	// Tag 13.1 moves; prune must not wipe 13.1.1's shared scan.
	if err := store.RecordScan(ctx, &ScanRecord{
		Repository:   repo,
		Digest:       newDigest,
		Tag:          "13.1",
		PolicyPassed: true,
		PolicyStatus: "passed",
	}); err != nil {
		t.Fatalf("RecordScan(13.1 new): %v", err)
	}

	detail, err := sqliteStore.GetRepository(ctx, repo, RepositoryTagFilter{})
	if err != nil {
		t.Fatalf("GetRepository: %v", err)
	}
	byTag := map[string]TagInfo{}
	for _, tag := range detail.Tags {
		byTag[tag.Name] = tag
	}
	if got := byTag["13.1"]; got.Digest != newDigest || !got.PolicyPassed {
		t.Fatalf("expected 13.1 on new digest passed, got %+v", got)
	}
	if got := byTag["13.1.1"]; got.Digest != oldDigest || got.PolicyStatus != "failed" || got.VulnerabilityCount.Critical != 1 {
		t.Fatalf("expected 13.1.1 to keep shared failed scan on old digest, got %+v", got)
	}
}
