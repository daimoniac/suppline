package statestore

import (
	"context"
	"testing"
)

func TestCleanupArtifactTag_RemovesOnlyMatchingTag(t *testing.T) {
	store, cleanup := createTestStore(t)
	defer cleanup()

	sqliteStore, ok := store.(*SQLiteStore)
	if !ok {
		t.Fatal("expected *SQLiteStore from createTestStore")
	}

	ctx := context.Background()
	digest := "sha256:1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd"
	repo := "library/nginx"

	for _, tag := range []string{"8.8", "8.8.0"} {
		err := store.RecordScan(ctx, &ScanRecord{
			Repository:        repo,
			Digest:            digest,
			Tag:               tag,
			ScanDurationMs:    10,
			CriticalVulnCount: 0,
			PolicyPassed:      true,
			PolicyStatus:      "passed",
		})
		if err != nil {
			t.Fatalf("RecordScan(%s): %v", tag, err)
		}
	}

	if err := store.CleanupArtifactTag(ctx, repo, digest, "8.8"); err != nil {
		t.Fatalf("CleanupArtifactTag: %v", err)
	}

	tags, err := sqliteStore.GetTagsForDigest(ctx, digest)
	if err != nil {
		t.Fatalf("GetTagsForDigest: %v", err)
	}
	if len(tags) != 1 {
		t.Fatalf("expected 1 remaining tag, got %d (%+v)", len(tags), tags)
	}
	if tags[0].Tag != "8.8.0" {
		t.Fatalf("expected remaining tag 8.8.0, got %q", tags[0].Tag)
	}

	lastScan, err := store.GetLastScan(ctx, digest)
	if err != nil {
		t.Fatalf("GetLastScan after tag cleanup: %v", err)
	}
	if lastScan == nil {
		t.Fatal("expected sibling digest scan to remain")
	}
}

func TestCleanupArtifactTag_RemovesEmptyRepository(t *testing.T) {
	store, cleanup := createTestStore(t)
	defer cleanup()

	sqliteStore, ok := store.(*SQLiteStore)
	if !ok {
		t.Fatal("expected *SQLiteStore from createTestStore")
	}

	ctx := context.Background()
	digest := "sha256:abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd"
	repo := "library/only-one-tag"

	err := store.RecordScan(ctx, &ScanRecord{
		Repository:   repo,
		Digest:       digest,
		Tag:          "1.0",
		PolicyPassed: true,
		PolicyStatus: "passed",
	})
	if err != nil {
		t.Fatalf("RecordScan: %v", err)
	}

	if err := store.CleanupArtifactTag(ctx, repo, digest, "1.0"); err != nil {
		t.Fatalf("CleanupArtifactTag: %v", err)
	}

	tags, err := sqliteStore.GetTagsForDigest(ctx, digest)
	if err != nil {
		t.Fatalf("GetTagsForDigest: %v", err)
	}
	if len(tags) != 0 {
		t.Fatalf("expected no tags remaining, got %+v", tags)
	}

	var repoCount int
	if err := sqliteStore.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM repositories WHERE name = ?`, repo).Scan(&repoCount); err != nil {
		t.Fatalf("count repositories: %v", err)
	}
	if repoCount != 0 {
		t.Fatalf("expected repository to be removed, count=%d", repoCount)
	}
}

func TestCleanupArtifactTag_NoopWhenMissing(t *testing.T) {
	store, cleanup := createTestStore(t)
	defer cleanup()

	err := store.CleanupArtifactTag(context.Background(), "missing/repo", "sha256:dead", "gone")
	if err != nil {
		t.Fatalf("expected nil for missing tag, got %v", err)
	}
}
