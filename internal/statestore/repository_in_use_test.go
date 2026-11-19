package statestore

import (
	"context"
	"testing"
	"time"
)

// A cluster that pulls an image from its source registry runs the digest
// suppline mirrored, under another repository name. The mirror target is
// still in use.
func TestRepositoryInUse_MatchesMirroredDigestUnderSourceName(t *testing.T) {
	store, cleanup := createTestStore(t)
	defer cleanup()

	sqliteStore := store.(*SQLiteStore)
	ctx := context.Background()
	const (
		repo   = "hostingmaloonde/shcomp"
		source = "registry.gitlab.com/cmd/dev/shcomp"
		tag    = "sha7602689c"
		digest = "sha256:ea1c443dad154ea1c443dad154ea1c443dad154ea1c443dad154ea1c443"
		other  = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
	)

	if err := store.RecordScan(ctx, &ScanRecord{Repository: repo, Digest: digest, Tag: tag, PolicyStatus: "failed"}); err != nil {
		t.Fatalf("RecordScan: %v", err)
	}

	report := func(entries ...ClusterImageEntry) {
		t.Helper()
		if err := sqliteStore.RecordClusterInventory(ctx, "c1", entries, time.Now()); err != nil {
			t.Fatalf("RecordClusterInventory: %v", err)
		}
	}
	inUse := func() bool {
		t.Helper()
		used, err := sqliteStore.RepositoryInUse(ctx, repo)
		if err != nil {
			t.Fatalf("RepositoryInUse: %v", err)
		}
		return used
	}

	report(ClusterImageEntry{Namespace: "integration", ImageRef: source, Tag: tag, Digest: other})
	if inUse() {
		t.Fatal("a source image with a digest suppline never stored must not count")
	}

	report(ClusterImageEntry{Namespace: "integration", ImageRef: source, Tag: tag, Digest: digest})
	if !inUse() {
		t.Fatal("the mirrored digest runs under its source name; the repository is in use")
	}
}
