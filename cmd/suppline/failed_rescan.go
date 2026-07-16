package main

import "github.com/daimoniac/suppline/internal/statestore"

// partitionFailedArtifactsByRuntimeUsage splits failed artifacts into in-use and
// not-in-use buckets based on runtime usage keyed by digest. Relative order within
// each bucket is preserved.
func partitionFailedArtifactsByRuntimeUsage(
	artifacts []*statestore.ScanRecord,
	usageByDigest map[string]statestore.RuntimeUsage,
) (inUse, notInUse []*statestore.ScanRecord) {
	inUse = make([]*statestore.ScanRecord, 0, len(artifacts))
	notInUse = make([]*statestore.ScanRecord, 0, len(artifacts))
	for _, artifact := range artifacts {
		if artifact == nil {
			continue
		}
		if usageByDigest[artifact.Digest].RuntimeUsed {
			inUse = append(inUse, artifact)
		} else {
			notInUse = append(notInUse, artifact)
		}
	}
	return inUse, notInUse
}
