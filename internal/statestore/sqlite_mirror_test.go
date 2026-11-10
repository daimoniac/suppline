package statestore

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestMirrorStoreRetentionAndPrune(t *testing.T) {
	store, err := NewSQLiteStore(filepath.Join(t.TempDir(), "mirror.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	ctx := context.Background()
	now := time.Now()

	syncs := []MirrorSync{
		{Key: "a", Source: "src/a", Target: "dst/app", Type: "repository", Schedule: "15m", Position: 0},
		{Key: "b", Source: "src/b", Target: "dst/app", Type: "repository", Schedule: "15m", Position: 1},
	}
	if err := store.ReplaceMirrorSyncs(ctx, syncs); err != nil {
		t.Fatal(err)
	}
	if err := store.ObserveMirrorImage(ctx, "a", "dst/app", "1.2.3", now); err != nil {
		t.Fatal(err)
	}
	if err := store.ObserveMirrorImage(ctx, "b", "dst/app", "2.0.0", now); err != nil {
		t.Fatal(err)
	}
	if err := store.RecordMirrorTagDeletion(ctx, "a", "dst/app", "0.9.0", now); err != nil {
		t.Fatal(err)
	}
	if err := store.RecordMirrorTagDeletion(ctx, "b", "dst/app", "0.9.0", now); err != nil {
		t.Fatal(err)
	}
	if err := store.RecordMirrorHubDeletion(ctx, "old/repo", now.Add(-8*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := store.RecordMirrorHubDeletion(ctx, "docker.io/library/old", now); err != nil {
		t.Fatal(err)
	}
	if err := store.FinishMirrorSync(ctx, "a", "ok", "", now); err != nil {
		t.Fatal(err)
	}

	listed, err := store.ListMirrorSyncs(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(listed) != 2 || listed[0].Key != "a" || listed[0].ImageCount != 1 || listed[0].TagDeletionCount != 1 {
		t.Fatalf("syncs = %+v", listed)
	}
	if listed[0].Status != "ok" || listed[0].FinishedAt == nil {
		t.Fatalf("status = %+v", listed[0])
	}

	hubs, total, err := store.ListMirrorHubDeletions(ctx, 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if total != 1 || len(hubs) != 1 || hubs[0].Repository != "docker.io/library/old" {
		t.Fatalf("hub deletions = %+v total %d", hubs, total)
	}

	if err := store.ObserveMirrorImage(ctx, "a", "docker.io/library/old", "1", now); err != nil {
		t.Fatal(err)
	}
	if _, total, err = store.ListMirrorHubDeletions(ctx, 10, 0); err != nil {
		t.Fatal(err)
	} else if total != 0 {
		t.Fatalf("hub deletions after restore = %d", total)
	}
	tags, _, err := store.ListMirrorTagDeletions(ctx, "a", 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(tags) != 1 {
		t.Fatalf("tag deletions = %+v", tags)
	}

	if err := store.ReplaceMirrorSyncs(ctx, syncs[:1]); err != nil {
		t.Fatal(err)
	}
	listed, err = store.ListMirrorSyncs(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(listed) != 1 || listed[0].Key != "a" {
		t.Fatalf("after config prune = %+v", listed)
	}
	if _, total, err = store.ListMirrorTagDeletions(ctx, "b", 10, 0); err != nil {
		t.Fatal(err)
	} else if total != 0 {
		t.Fatalf("removed sync deletions = %d", total)
	}
	images, total, err := store.ListMirrorImages(ctx, "b", 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if total != 0 || len(images) != 0 {
		t.Fatalf("removed sync images = %+v", images)
	}

	if err := store.PruneMirrorImages(ctx, "a", []MirrorImage{{Repository: "dst/app", Tag: "9.9.9"}}); err != nil {
		t.Fatal(err)
	}
	if _, total, err = store.ListMirrorImages(ctx, "a", 10, 0); err != nil {
		t.Fatal(err)
	} else if total != 0 {
		t.Fatalf("pruned images = %d", total)
	}
}
