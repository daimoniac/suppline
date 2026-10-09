package statestore

import (
	"context"
	"errors"
	"testing"
)

func TestGetLastRepositoryScan_IgnoresOtherRepository(t *testing.T) {
	raw, cleanup := createTestStore(t)
	defer cleanup()
	store, ok := raw.(*SQLiteStore)
	if !ok {
		t.Fatal("expected *SQLiteStore")
	}

	ctx := context.Background()
	digest := "sha256:shared"
	dockerRepo := "hostingmaloonde/rabbitmqoperator_cluster-operator"
	ghcrRepo := "hostingmaloonde/rabbitmq_cluster-operator"

	for _, repo := range []string{dockerRepo, ghcrRepo} {
		if err := store.RecordScan(ctx, &ScanRecord{
			Repository:   repo,
			Digest:       digest,
			Tag:          "2.19.2",
			PolicyPassed: true,
			PolicyStatus: "passed",
		}); err != nil {
			t.Fatalf("RecordScan %s: %v", repo, err)
		}
	}

	got, err := store.GetLastRepositoryScan(ctx, ghcrRepo, digest)
	if err != nil {
		t.Fatalf("GetLastRepositoryScan: %v", err)
	}
	if got.Repository != ghcrRepo {
		t.Fatalf("repository = %s, want %s", got.Repository, ghcrRepo)
	}

	_, err = store.GetLastRepositoryScan(ctx, "hostingmaloonde/missing", digest)
	if !errors.Is(err, ErrScanNotFound) {
		t.Fatalf("missing repository err = %v, want ErrScanNotFound", err)
	}
}
