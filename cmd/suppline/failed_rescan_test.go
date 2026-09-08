package main

import (
	"testing"

	"github.com/daimoniac/suppline/internal/statestore"
)

func TestPartitionArtifactsByRuntimeUsage(t *testing.T) {
	a := &statestore.ScanRecord{Digest: "sha256:a", Repository: "repo/a", Tag: "1"}
	b := &statestore.ScanRecord{Digest: "sha256:b", Repository: "repo/b", Tag: "1", RuntimeUsed: true}
	c := &statestore.ScanRecord{Digest: "sha256:c", Repository: "repo/c", Tag: "1"}
	d := &statestore.ScanRecord{Digest: "sha256:d", Repository: "repo/d", Tag: "1", RuntimeUsed: true}

	inUse, notInUse := partitionArtifactsByRuntimeUsage([]*statestore.ScanRecord{a, b, c, d, nil})

	if len(inUse) != 2 || inUse[0] != b || inUse[1] != d {
		t.Fatalf("in-use order: got %+v, want [b, d]", digests(inUse))
	}
	if len(notInUse) != 2 || notInUse[0] != a || notInUse[1] != c {
		t.Fatalf("not-in-use order: got %+v, want [a, c]", digests(notInUse))
	}
}

func TestPartitionArtifactsByRuntimeUsage_empty(t *testing.T) {
	inUse, notInUse := partitionArtifactsByRuntimeUsage(nil)
	if len(inUse) != 0 || len(notInUse) != 0 {
		t.Fatalf("expected empty buckets, got inUse=%d notInUse=%d", len(inUse), len(notInUse))
	}
}

func digests(records []*statestore.ScanRecord) []string {
	out := make([]string, 0, len(records))
	for _, r := range records {
		out = append(out, r.Digest)
	}
	return out
}
