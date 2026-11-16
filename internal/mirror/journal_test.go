package mirror

import (
	"context"
	"errors"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/daimoniac/suppline/internal/config"
	"github.com/daimoniac/suppline/internal/statestore"
)

func testMirrorConfig(t *testing.T, body string) *config.RegsyncConfig {
	t.Helper()
	path := writeConfig(t, body)
	cfg, err := config.ParseRegsync(path)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func testJournal(t *testing.T, cfg *config.RegsyncConfig) (*journal, *statestore.SQLiteStore) {
	t.Helper()
	store, err := statestore.NewSQLiteStore(filepath.Join(t.TempDir(), "mirror.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	journal := newJournal(store, NewActivity(), cfg, slog.New(slog.DiscardHandler))
	if err := journal.Bind(context.Background()); err != nil {
		t.Fatal(err)
	}
	return journal, store
}

func TestJournalPartialFailurePrunesUnobserved(t *testing.T) {
	cfg := testMirrorConfig(t, `
version: 1
sync:
  - source: docker.io/library/alpine
    target: registry.example/alpine
    type: repository
    interval: 60m
`)
	journal, store := testJournal(t, cfg)
	key := journal.entries[0].key
	ctx := context.Background()
	repo := "registry.example/alpine"
	now := time.Now()

	journal.Begin(key)
	journal.Observe(ctx, key, repo, "1.0", now)
	journal.Observe(ctx, key, repo, "1.1", now)
	journal.Finish(ctx, key, nil)

	journal.Begin(key)
	journal.Observe(ctx, key, repo, "1.1", now.Add(time.Minute))
	journal.Finish(ctx, key, errors.New("copy 1.0: registry timeout"))

	images, total, err := store.ListMirrorImages(ctx, key, 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if total != 1 || len(images) != 1 || images[0].Tag != "1.1" {
		t.Fatalf("images = %+v total %d", images, total)
	}
	syncs, err := store.ListMirrorSyncs(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(syncs) != 1 || syncs[0].Status != "failed" || syncs[0].Error == "" {
		t.Fatalf("sync = %+v", syncs)
	}
	if journal.activity.Running(key) {
		t.Fatal("finished sync still running")
	}
}

func TestJournalSharedTargetAndConfigPrune(t *testing.T) {
	cfg := testMirrorConfig(t, `
version: 1
sync:
  - source: docker.io/library/alpine
    target: registry.example/alpine
    type: repository
    interval: 60m
    tags:
      allow: ["1\\..*"]
  - source: docker.io/library/alpine
    target: registry.example/alpine
    type: repository
    interval: 60m
    tags:
      allow: ["2\\..*"]
`)
	journal, store := testJournal(t, cfg)
	ctx := context.Background()
	repo := "registry.example/alpine"
	now := time.Now()
	keyA := journal.entries[0].key
	keyB := journal.entries[1].key
	if keyA == keyB {
		t.Fatal("sync keys collided")
	}

	journal.Observe(ctx, "", repo, "1.2.3", now)
	journal.Observe(ctx, "", repo, "2.0.0", now)
	journal.RecordTagDeletion(ctx, repo, "0.9.0", now)
	journal.RecordHubDeletion(ctx, "docker.io/old/repo", now)

	imagesA, _, err := store.ListMirrorImages(ctx, keyA, 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(imagesA) != 1 || imagesA[0].Tag != "1.2.3" {
		t.Fatalf("sync A images = %+v", imagesA)
	}
	imagesB, _, err := store.ListMirrorImages(ctx, keyB, 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(imagesB) != 1 || imagesB[0].Tag != "2.0.0" {
		t.Fatalf("sync B images = %+v", imagesB)
	}
	for _, key := range []string{keyA, keyB} {
		deletions, total, err := store.ListMirrorTagDeletions(ctx, key, 10, 0)
		if err != nil {
			t.Fatal(err)
		}
		if total != 1 || deletions[0].Tag != "0.9.0" {
			t.Fatalf("sync %s deletions = %+v", key, deletions)
		}
	}

	shrunk := testMirrorConfig(t, `
version: 1
sync:
  - source: docker.io/library/alpine
    target: registry.example/alpine
    type: repository
    interval: 60m
    tags:
      allow: ["1\\..*"]
`)
	journal.entries = assignSyncKeys(shrunk.Sync)
	if err := journal.Bind(ctx); err != nil {
		t.Fatal(err)
	}
	syncs, err := store.ListMirrorSyncs(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(syncs) != 1 || syncs[0].Key != keyA {
		t.Fatalf("syncs after prune = %+v", syncs)
	}
	if _, total, err := store.ListMirrorImages(ctx, keyB, 10, 0); err != nil {
		t.Fatal(err)
	} else if total != 0 {
		t.Fatalf("removed sync images = %d", total)
	}
	if _, total, err := store.ListMirrorTagDeletions(ctx, keyB, 10, 0); err != nil {
		t.Fatal(err)
	} else if total != 0 {
		t.Fatalf("removed sync deletions = %d", total)
	}
	hubs, total, err := store.ListMirrorHubDeletions(ctx, 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if total != 1 || hubs[0].Repository != "docker.io/old/repo" {
		t.Fatalf("hub deletions = %+v", hubs)
	}
}

func TestJournalFailedListingDoesNotPrune(t *testing.T) {
	cfg := testMirrorConfig(t, `
version: 1
sync:
  - source: docker.io/library/alpine
    target: registry.example/alpine
    type: repository
    interval: 60m
`)
	journal, store := testJournal(t, cfg)
	key := journal.entries[0].key
	ctx := context.Background()
	repo := "registry.example/alpine"
	now := time.Now()

	journal.Begin(key)
	journal.Observe(ctx, key, repo, "1.0", now)
	journal.Finish(ctx, key, nil)

	journal.Begin(key)
	journal.FailListing(key)
	journal.Finish(ctx, key, errors.New("list tags: registry timeout"))

	images, total, err := store.ListMirrorImages(ctx, key, 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if total != 1 || len(images) != 1 || images[0].Tag != "1.0" {
		t.Fatalf("images = %+v", images)
	}
}

func TestJournalRestoresDeletion(t *testing.T) {
	cfg := testMirrorConfig(t, `
version: 1
sync:
  - source: docker.io/library/alpine
    target: registry.example/alpine
    type: repository
    interval: 60m
`)
	journal, store := testJournal(t, cfg)
	ctx := context.Background()
	key := journal.entries[0].key
	repo := "registry.example/alpine"
	now := time.Now()
	journal.RecordTagDeletion(ctx, repo, "1.2.3", now)
	journal.Observe(ctx, key, repo, "1.2.3", now.Add(time.Second))
	deletions, total, err := store.ListMirrorTagDeletions(ctx, key, 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if total != 0 || len(deletions) != 0 {
		t.Fatalf("deletion remained after restore: %+v", deletions)
	}
	images, _, err := store.ListMirrorImages(ctx, key, 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(images) != 1 || images[0].Tag != "1.2.3" {
		t.Fatalf("images = %+v", images)
	}
}
