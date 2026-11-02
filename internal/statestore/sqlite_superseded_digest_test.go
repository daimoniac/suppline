package statestore

import (
	"context"
	"testing"
	"time"
)

func TestRecordScan_RetainsInUseDigestWhenTagMoves(t *testing.T) {
	store, cleanup := createTestStore(t)
	defer cleanup()

	sqliteStore := store.(*SQLiteStore)
	ctx := context.Background()
	repo := "hostingmaloonde/dhi_traefik"
	tag := "3.7.13-debian13"
	oldDigest := "sha256:f3f03c346b8ef599c1ef8a975066d96561270c9737884dab222414e8d0fee473"
	newDigest := "sha256:1a64c035a0d036ffbcfa94d085a53290b0dccbfd9ad199f188f555e118f234aa"

	if err := store.RecordScan(ctx, &ScanRecord{
		Repository:   repo,
		Digest:       oldDigest,
		Tag:          tag,
		PolicyPassed: true,
		PolicyStatus: "passed",
	}); err != nil {
		t.Fatalf("RecordScan(old): %v", err)
	}
	if err := sqliteStore.RecordClusterInventory(ctx, "hetzner-1", []ClusterImageEntry{
		{Namespace: "traefik", ImageRef: "docker.io/hostingmaloonde/dhi_traefik", Tag: tag, Digest: oldDigest},
	}, time.Now().UTC()); err != nil {
		t.Fatalf("RecordClusterInventory: %v", err)
	}
	if err := store.RecordScan(ctx, &ScanRecord{
		Repository:   repo,
		Digest:       newDigest,
		Tag:          tag,
		PolicyPassed: true,
		PolicyStatus: "passed",
	}); err != nil {
		t.Fatalf("RecordScan(new): %v", err)
	}

	if got := artifactSuperseded(t, sqliteStore, repo, oldDigest, tag); got != 1 {
		t.Fatalf("old digest superseded=%d, want 1", got)
	}
	if got := artifactSuperseded(t, sqliteStore, repo, newDigest, tag); got != 0 {
		t.Fatalf("new digest superseded=%d, want 0", got)
	}

	detail, err := sqliteStore.GetRepository(ctx, repo, RepositoryTagFilter{})
	if err != nil {
		t.Fatalf("GetRepository: %v", err)
	}
	if detail.Total != 1 || len(detail.Tags) != 1 || detail.Tags[0].Digest != newDigest {
		t.Fatalf("repository view = total %d tags %+v, want only the new digest", detail.Total, detail.Tags)
	}

	if _, err := sqliteStore.GetLastRepositoryScan(ctx, repo, oldDigest); err != nil {
		t.Fatalf("old digest scan was dropped: %v", err)
	}

	// A later renewal of the pinned digest must not become the tag's current binding.
	if err := store.RecordScan(ctx, &ScanRecord{
		Repository:       repo,
		Digest:           oldDigest,
		Tag:              tag,
		PolicyPassed:     true,
		PolicyStatus:     "passed",
		RetainSuperseded: true,
	}); err != nil {
		t.Fatalf("RecordScan(retain): %v", err)
	}
	detail, err = sqliteStore.GetRepository(ctx, repo, RepositoryTagFilter{})
	if err != nil {
		t.Fatalf("GetRepository after renewal: %v", err)
	}
	if detail.Total != 1 || detail.Tags[0].Digest != newDigest {
		t.Fatalf("renewal took over the tag: %+v", detail.Tags)
	}
	if got := artifactSuperseded(t, sqliteStore, repo, oldDigest, tag); got != 1 {
		t.Fatalf("renewed digest superseded=%d, want 1", got)
	}
}

func TestRecordScan_TagOnlyRuntimeUseDoesNotRetainOldDigest(t *testing.T) {
	store, cleanup := createTestStore(t)
	defer cleanup()

	sqliteStore := store.(*SQLiteStore)
	ctx := context.Background()
	repo := "hostingmaloonde/dhi_traefik"
	tag := "3.7.13-debian13"
	oldDigest := "sha256:f3f03c346b8ef599c1ef8a975066d96561270c9737884dab222414e8d0fee473"
	newDigest := "sha256:1a64c035a0d036ffbcfa94d085a53290b0dccbfd9ad199f188f555e118f234aa"

	if err := store.RecordScan(ctx, &ScanRecord{
		Repository:   repo,
		Digest:       oldDigest,
		Tag:          tag,
		PolicyPassed: true,
		PolicyStatus: "passed",
	}); err != nil {
		t.Fatalf("RecordScan(old): %v", err)
	}
	if err := sqliteStore.RecordClusterInventory(ctx, "hetzner-1", []ClusterImageEntry{
		{Namespace: "traefik", ImageRef: "docker.io/hostingmaloonde/dhi_traefik", Tag: tag},
	}, time.Now().UTC()); err != nil {
		t.Fatalf("RecordClusterInventory: %v", err)
	}
	if err := store.RecordScan(ctx, &ScanRecord{
		Repository:   repo,
		Digest:       newDigest,
		Tag:          tag,
		PolicyPassed: true,
		PolicyStatus: "passed",
	}); err != nil {
		t.Fatalf("RecordScan(new): %v", err)
	}

	if _, err := sqliteStore.GetLastRepositoryScan(ctx, repo, oldDigest); err == nil {
		t.Fatal("tag-only inventory kept the old digest")
	} else if err != ErrScanNotFound {
		t.Fatalf("GetLastRepositoryScan(old): %v", err)
	}
}

func TestReconcileSupersededDigests_RenewsStalePinAndDropsUnused(t *testing.T) {
	store, cleanup := createTestStore(t)
	defer cleanup()

	sqliteStore := store.(*SQLiteStore)
	ctx := context.Background()
	repo := "hostingmaloonde/dhi_traefik"
	tag := "3.7.13-debian13"
	oldDigest := "sha256:f3f03c346b8ef599c1ef8a975066d96561270c9737884dab222414e8d0fee473"
	newDigest := "sha256:1a64c035a0d036ffbcfa94d085a53290b0dccbfd9ad199f188f555e118f234aa"

	if err := store.RecordScan(ctx, &ScanRecord{
		Repository:   repo,
		Digest:       oldDigest,
		Tag:          tag,
		PolicyPassed: true,
		PolicyStatus: "passed",
	}); err != nil {
		t.Fatalf("RecordScan(old): %v", err)
	}
	if err := sqliteStore.RecordClusterInventory(ctx, "hetzner-1", []ClusterImageEntry{
		{Namespace: "traefik", ImageRef: "docker.io/hostingmaloonde/dhi_traefik", Tag: tag, Digest: oldDigest},
	}, time.Now().UTC()); err != nil {
		t.Fatalf("RecordClusterInventory: %v", err)
	}
	if err := store.RecordScan(ctx, &ScanRecord{
		Repository:   repo,
		Digest:       newDigest,
		Tag:          tag,
		PolicyPassed: true,
		PolicyStatus: "passed",
	}); err != nil {
		t.Fatalf("RecordScan(new): %v", err)
	}

	fresh, err := sqliteStore.ReconcileSupersededDigests(ctx, repo, []string{newDigest}, 7*24*time.Hour)
	if err != nil {
		t.Fatalf("Reconcile fresh: %v", err)
	}
	if len(fresh) != 0 {
		t.Fatalf("fresh pin returned %+v, want none", fresh)
	}

	oldScanAt := time.Now().UTC().Add(-8 * 24 * time.Hour).Unix()
	if _, err := sqliteStore.db.ExecContext(ctx, `
		UPDATE scan_records SET created_at = ?
		WHERE artifact_id IN (
			SELECT a.id FROM artifacts a
			JOIN repositories r ON r.id = a.repository_id
			WHERE r.name = ? AND a.digest = ?
		)
	`, oldScanAt, repo, oldDigest); err != nil {
		t.Fatalf("backdate scan: %v", err)
	}

	due, err := sqliteStore.ReconcileSupersededDigests(ctx, repo, []string{newDigest}, 7*24*time.Hour)
	if err != nil {
		t.Fatalf("Reconcile due: %v", err)
	}
	if len(due) != 1 || due[0].Digest != oldDigest || due[0].Tag != tag || due[0].Repository != repo {
		t.Fatalf("due renewals = %+v", due)
	}

	// The tag moved back to the pinned digest before the next rescan.
	restored, err := sqliteStore.EnsureArtifactTagBinding(ctx, repo, oldDigest, tag)
	if err != nil {
		t.Fatalf("EnsureArtifactTagBinding: %v", err)
	}
	if restored {
		t.Fatal("restoring an existing binding reported a new alias")
	}
	if got := artifactSuperseded(t, sqliteStore, repo, oldDigest, tag); got != 0 {
		t.Fatalf("restored digest superseded=%d, want 0", got)
	}
	detail, err := sqliteStore.GetRepository(ctx, repo, RepositoryTagFilter{})
	if err != nil {
		t.Fatalf("GetRepository after restore: %v", err)
	}
	if detail.Total != 1 || detail.Tags[0].Digest != oldDigest {
		t.Fatalf("restored tag view = %+v, want old digest", detail.Tags)
	}

	// Pin goes away. The retained successor from the earlier move was deleted
	// because it was not in use; record it again as superseded and then drop it.
	if err := store.RecordScan(ctx, &ScanRecord{
		Repository:   repo,
		Digest:       newDigest,
		Tag:          tag,
		PolicyPassed: true,
		PolicyStatus: "passed",
	}); err != nil {
		t.Fatalf("RecordScan(new again): %v", err)
	}
	reportedAt := time.Now().UTC()
	if err := sqliteStore.RecordClusterInventory(ctx, "hetzner-1", []ClusterImageEntry{
		{Namespace: "traefik", ImageRef: "docker.io/hostingmaloonde/dhi_traefik", Tag: tag, Digest: oldDigest},
	}, reportedAt); err != nil {
		t.Fatalf("re-record inventory: %v", err)
	}
	if _, err := sqliteStore.db.ExecContext(ctx, `
		UPDATE cluster_images_seen SET last_seen_at = ?
	`, reportedAt.Add(-2*time.Hour).Unix()); err != nil {
		t.Fatalf("age inventory: %v", err)
	}
	if _, err := sqliteStore.db.ExecContext(ctx, `
		UPDATE clusters SET last_reported_at = ?
	`, reportedAt.Unix()); err != nil {
		t.Fatalf("bump cluster report: %v", err)
	}

	left, err := sqliteStore.ReconcileSupersededDigests(ctx, repo, []string{newDigest}, time.Hour)
	if err != nil {
		t.Fatalf("Reconcile unused: %v", err)
	}
	if len(left) != 0 {
		t.Fatalf("unused digest still renewing: %+v", left)
	}
	if _, err := sqliteStore.GetLastRepositoryScan(ctx, repo, oldDigest); err == nil {
		t.Fatal("unused superseded digest was kept")
	} else if err != ErrScanNotFound {
		t.Fatalf("GetLastRepositoryScan(old): %v", err)
	}
}

func artifactSuperseded(t *testing.T, store *SQLiteStore, repo, digest, tag string) int {
	t.Helper()
	var superseded int
	err := store.db.QueryRowContext(context.Background(), `
		SELECT a.superseded
		FROM artifacts a
		JOIN repositories r ON r.id = a.repository_id
		WHERE r.name = ? AND a.digest = ? AND a.tag = ?
	`, repo, digest, tag).Scan(&superseded)
	if err != nil {
		t.Fatalf("superseded flag for %s: %v", digest, err)
	}
	return superseded
}
