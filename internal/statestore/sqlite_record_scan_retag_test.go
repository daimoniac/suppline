package statestore

import (
	"context"
	"testing"
)

func TestRecordScan_PrunesSupersededTagDigestBindings(t *testing.T) {
	store, cleanup := createTestStore(t)
	defer cleanup()

	sqliteStore := store.(*SQLiteStore)
	ctx := context.Background()
	repo := "hostingmaloonde/dhi_grafana"
	oldDigest := "sha256:245a7ae34af1f3503a8dffadca09032ca86e26b59dae07164982a356ce6fa08c"
	newDigest := "sha256:cbad2dcfb2ae3b44bcfcff14f68cdc9b4bcf6ce45bc9990b46dc1d6e0f513a84"

	// Old digest scanned for both aliases; policy failed.
	for _, tag := range []string{"13.1", "13.1.1"} {
		if err := store.RecordScan(ctx, &ScanRecord{
			Repository:        repo,
			Digest:            oldDigest,
			Tag:               tag,
			CriticalVulnCount: 1,
			PolicyPassed:      false,
			PolicyStatus:      "failed",
			PolicyReason:      "fixable critical vulnerabilities found",
		}); err != nil {
			t.Fatalf("RecordScan(old,%s): %v", tag, err)
		}
	}

	// Tag 13.1 moves to a new digest and passes.
	if err := store.RecordScan(ctx, &ScanRecord{
		Repository:   repo,
		Digest:       newDigest,
		Tag:          "13.1",
		PolicyPassed: true,
		PolicyStatus: "passed",
		PolicyReason: "policy passed",
	}); err != nil {
		t.Fatalf("RecordScan(new,13.1): %v", err)
	}

	oldTags, err := sqliteStore.GetTagsForDigest(ctx, oldDigest)
	if err != nil {
		t.Fatalf("GetTagsForDigest(old): %v", err)
	}
	if len(oldTags) != 1 || oldTags[0].Tag != "13.1.1" {
		t.Fatalf("expected only superseded sibling 13.1.1 on old digest, got %+v", oldTags)
	}

	newTags, err := sqliteStore.GetTagsForDigest(ctx, newDigest)
	if err != nil {
		t.Fatalf("GetTagsForDigest(new): %v", err)
	}
	if len(newTags) != 1 || newTags[0].Tag != "13.1" {
		t.Fatalf("expected only 13.1 on new digest, got %+v", newTags)
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
		t.Fatalf("expected current 13.1 on new digest passed, got %+v", got)
	}
	if got := byTag["13.1.1"]; got.Digest != oldDigest || got.PolicyPassed {
		t.Fatalf("expected 13.1.1 still on old failed digest until rescanned, got %+v", got)
	}
}
