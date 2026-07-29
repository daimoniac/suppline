package statestore

import (
	"context"
	"fmt"
	"testing"
)

func TestCleanupRepository_RemovesAllArtifactsAndRepo(t *testing.T) {
	store, cleanup := createTestStore(t)
	defer cleanup()

	sqliteStore, ok := store.(*SQLiteStore)
	if !ok {
		t.Fatal("expected *SQLiteStore from createTestStore")
	}

	ctx := context.Background()
	repo := "hostingmaloonde/orphaned"
	keepRepo := "hostingmaloonde/kept"

	for i, tag := range []string{"1.0", "1.1", "2.0"} {
		digest := fmt.Sprintf("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa%d", i)
		err := store.RecordScan(ctx, &ScanRecord{
			Repository:   repo,
			Digest:       digest,
			Tag:          tag,
			PolicyPassed: true,
			PolicyStatus: "passed",
		})
		if err != nil {
			t.Fatalf("RecordScan(%s): %v", tag, err)
		}
	}
	err := store.RecordScan(ctx, &ScanRecord{
		Repository:   keepRepo,
		Digest:       "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		Tag:          "latest",
		PolicyPassed: true,
		PolicyStatus: "passed",
	})
	if err != nil {
		t.Fatalf("RecordScan(kept): %v", err)
	}

	names, err := store.ListStoredRepositoryNames(ctx)
	if err != nil {
		t.Fatalf("ListStoredRepositoryNames: %v", err)
	}
	if len(names) != 2 {
		t.Fatalf("expected 2 repos before cleanup, got %v", names)
	}

	bindings, err := store.ListArtifactTags(ctx, repo)
	if err != nil {
		t.Fatalf("ListArtifactTags: %v", err)
	}
	if len(bindings) != 3 {
		t.Fatalf("expected 3 bindings, got %d", len(bindings))
	}

	if err := store.CleanupRepository(ctx, repo); err != nil {
		t.Fatalf("CleanupRepository: %v", err)
	}

	bindings, err = store.ListArtifactTags(ctx, repo)
	if err != nil {
		t.Fatalf("ListArtifactTags after cleanup: %v", err)
	}
	if len(bindings) != 0 {
		t.Fatalf("expected no bindings after cleanup, got %+v", bindings)
	}

	names, err = store.ListStoredRepositoryNames(ctx)
	if err != nil {
		t.Fatalf("ListStoredRepositoryNames after cleanup: %v", err)
	}
	if len(names) != 1 || names[0] != keepRepo {
		t.Fatalf("expected only %q remaining, got %v", keepRepo, names)
	}

	var repoCount int
	if err := sqliteStore.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM repositories WHERE name = ?`, repo).Scan(&repoCount); err != nil {
		t.Fatalf("count repositories: %v", err)
	}
	if repoCount != 0 {
		t.Fatalf("expected orphaned repository removed, count=%d", repoCount)
	}
}

func TestCleanupRepository_NoopWhenMissing(t *testing.T) {
	store, cleanup := createTestStore(t)
	defer cleanup()

	if err := store.CleanupRepository(context.Background(), "missing/repo"); err != nil {
		t.Fatalf("expected nil for missing repo, got %v", err)
	}
}

func TestListArtifactTags_ReturnsBindings(t *testing.T) {
	store, cleanup := createTestStore(t)
	defer cleanup()

	ctx := context.Background()
	repo := "hostingmaloonde/tagged"
	err := store.RecordScan(ctx, &ScanRecord{
		Repository:   repo,
		Digest:       "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
		Tag:          "1.0.0",
		PolicyPassed: true,
		PolicyStatus: "passed",
	})
	if err != nil {
		t.Fatalf("RecordScan: %v", err)
	}

	bindings, err := store.ListArtifactTags(ctx, repo)
	if err != nil {
		t.Fatalf("ListArtifactTags: %v", err)
	}
	if len(bindings) != 1 || bindings[0].Tag != "1.0.0" {
		t.Fatalf("expected one tagged binding, got %+v", bindings)
	}
}
