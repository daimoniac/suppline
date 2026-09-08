package statestore

import (
	"context"
	"testing"
	"time"
)

func TestEnsureArtifactTagBinding_CreatesAliasFromSiblingScan(t *testing.T) {
	store, cleanup := createTestStore(t)
	defer cleanup()

	sqliteStore, ok := store.(*SQLiteStore)
	if !ok {
		t.Fatal("expected *SQLiteStore from createTestStore")
	}

	ctx := context.Background()
	repo := "hostingmaloonde/kong"
	digest := "sha256:c944149b4d0aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

	err := store.RecordScan(ctx, &ScanRecord{
		Repository:        repo,
		Digest:            digest,
		Tag:               "3.0",
		CriticalVulnCount: 1,
		PolicyPassed:      false,
		PolicyStatus:      "failed",
		PolicyReason:      "critical",
	})
	if err != nil {
		t.Fatalf("RecordScan: %v", err)
	}

	created, err := store.EnsureArtifactTagBinding(ctx, repo, digest, "3.0.2")
	if err != nil {
		t.Fatalf("EnsureArtifactTagBinding: %v", err)
	}
	if !created {
		t.Fatal("expected alias binding to be created")
	}

	createdAgain, err := store.EnsureArtifactTagBinding(ctx, repo, digest, "3.0.2")
	if err != nil {
		t.Fatalf("EnsureArtifactTagBinding second call: %v", err)
	}
	if createdAgain {
		t.Fatal("expected second call to be a no-op create")
	}

	detail, err := sqliteStore.GetRepository(ctx, repo, RepositoryTagFilter{})
	if err != nil {
		t.Fatalf("GetRepository: %v", err)
	}
	tags := map[string]TagInfo{}
	for _, tag := range detail.Tags {
		tags[tag.Name] = tag
	}
	if _, ok := tags["3.0"]; !ok {
		t.Fatal("expected original tag 3.0")
	}
	alias, ok := tags["3.0.2"]
	if !ok {
		t.Fatal("expected alias tag 3.0.2 in repository detail")
	}
	if alias.Digest != digest {
		t.Fatalf("alias digest=%s want %s", alias.Digest, digest)
	}
	if alias.PolicyStatus != "failed" {
		t.Fatalf("alias policy_status=%q want failed", alias.PolicyStatus)
	}
	if alias.VulnerabilityCount.Critical != 1 {
		t.Fatalf("alias critical=%d want 1", alias.VulnerabilityCount.Critical)
	}
}

func TestEnsureArtifactTagBinding_ExistingAliasDoesNotUpgradeReadTransaction(t *testing.T) {
	store, cleanup := createTestStore(t)
	defer cleanup()

	sqliteStore := store.(*SQLiteStore)
	ctx := context.Background()
	repo := "hostingmaloonde/supabase_edge-runtime"
	digest := "sha256:e8d000000000000000000000000000000000000000000000000000000000000"

	if err := store.RecordScan(ctx, &ScanRecord{
		Repository:   repo,
		Digest:       digest,
		Tag:          "v1.73.12",
		PolicyPassed: true,
		PolicyStatus: "passed",
	}); err != nil {
		t.Fatalf("RecordScan: %v", err)
	}

	// Hold a concurrent SQLite writer open. The old implementation first read the
	// alias in a deferred transaction, then tried to upgrade that stale snapshot
	// to UPDATE after this writer committed, which returned SQLITE_BUSY.
	writer, err := sqliteStore.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin writer: %v", err)
	}
	if _, err := writer.ExecContext(ctx, `UPDATE repositories SET registry = ? WHERE name = ?`, "test", repo); err != nil {
		t.Fatalf("hold write lock: %v", err)
	}

	errCh := make(chan error, 1)
	go func() {
		_, err := store.EnsureArtifactTagBinding(ctx, repo, digest, "v1.73.12")
		errCh <- err
	}()

	time.Sleep(100 * time.Millisecond)
	if err := writer.Commit(); err != nil {
		t.Fatalf("commit writer: %v", err)
	}

	if err := <-errCh; err != nil {
		t.Fatalf("EnsureArtifactTagBinding with concurrent writer: %v", err)
	}
}

func TestEnsureArtifactTagBinding_NoopForEmptyTag(t *testing.T) {
	store, cleanup := createTestStore(t)
	defer cleanup()

	ctx := context.Background()
	repo := "hostingmaloonde/kong"
	digest := "sha256:c944149b4d0aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if err := store.RecordScan(ctx, &ScanRecord{
		Repository:   repo,
		Digest:       digest,
		Tag:          "3.0",
		PolicyPassed: true,
		PolicyStatus: "passed",
	}); err != nil {
		t.Fatalf("RecordScan: %v", err)
	}

	created, err := store.EnsureArtifactTagBinding(ctx, repo, digest, "")
	if err != nil {
		t.Fatalf("EnsureArtifactTagBinding: %v", err)
	}
	if created {
		t.Fatal("expected empty tag binding to be rejected")
	}
}

func TestRecordScan_RejectsEmptyTag(t *testing.T) {
	store, cleanup := createTestStore(t)
	defer cleanup()

	err := store.RecordScan(context.Background(), &ScanRecord{
		Repository:   "hostingmaloonde/n8nio_n8n",
		Digest:       "sha256:9991e52f5fbf289d246bece86b7e5f205690b94ce1dc88db5a5c8156566b66d9",
		Tag:          "",
		PolicyPassed: false,
		PolicyStatus: "failed",
	})
	if err == nil {
		t.Fatal("expected error recording empty tag")
	}
}
