package main

import (
	"testing"

	"github.com/daimoniac/suppline/internal/statestore"
)

func TestPartitionFailedArtifactsByRuntimeUsage(t *testing.T) {
	a := &statestore.ScanRecord{Digest: "sha256:a", Repository: "repo/a", Tag: "1"}
	b := &statestore.ScanRecord{Digest: "sha256:b", Repository: "repo/b", Tag: "1"}
	c := &statestore.ScanRecord{Digest: "sha256:c", Repository: "repo/c", Tag: "1"}
	d := &statestore.ScanRecord{Digest: "sha256:d", Repository: "repo/d", Tag: "1"}

	usage := map[string]statestore.RuntimeUsage{
		"sha256:b": {RuntimeUsed: true},
		"sha256:d": {RuntimeUsed: true},
		"sha256:a": {RuntimeUsed: false},
	}

	inUse, notInUse := partitionFailedArtifactsByRuntimeUsage([]*statestore.ScanRecord{a, b, c, d, nil}, usage)

	if len(inUse) != 2 || inUse[0] != b || inUse[1] != d {
		t.Fatalf("in-use order: got %+v, want [b, d]", digests(inUse))
	}
	if len(notInUse) != 2 || notInUse[0] != a || notInUse[1] != c {
		t.Fatalf("not-in-use order: got %+v, want [a, c]", digests(notInUse))
	}
}

func TestPartitionFailedArtifactsByRuntimeUsage_empty(t *testing.T) {
	inUse, notInUse := partitionFailedArtifactsByRuntimeUsage(nil, nil)
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
