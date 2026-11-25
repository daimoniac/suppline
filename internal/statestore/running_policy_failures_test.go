package statestore

import (
	"context"
	"sort"
	"testing"
	"time"
)

// A tag moved to a passing digest while pods still run the old failing digests.
// The runtime policy count and the running-failures list must both report the old
// digests, labelled as superseded, until the pods are rolled.
func TestListRunningPolicyFailures_SupersededDigestStillRunning(t *testing.T) {
	store, cleanup := createTestStore(t)
	defer cleanup()

	pgStore := store.(*Store)
	ctx := context.Background()
	const (
		repo      = "hostingmaloonde/memcached"
		imageRef  = "docker.io/hostingmaloonde/memcached"
		tag       = "1.6.45"
		failingA  = "sha256:57f76c81aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		failingB  = "sha256:af555492bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
		passingC  = "sha256:b09d8056cccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
		cluster   = "hetzner-1"
		namespace = "monitoring"
	)

	recordInventory := func(reportedAt time.Time, entries ...ClusterImageEntry) {
		t.Helper()
		if err := pgStore.RecordClusterInventory(ctx, cluster, entries, reportedAt); err != nil {
			t.Fatalf("RecordClusterInventory: %v", err)
		}
	}
	recordScan := func(digest string, passed bool) {
		t.Helper()
		status := "failed"
		if passed {
			status = "passed"
		}
		if err := store.RecordScan(ctx, &ScanRecord{
			Repository:        repo,
			Digest:            digest,
			Tag:               tag,
			PolicyPassed:      passed,
			PolicyStatus:      status,
			CriticalVulnCount: map[bool]int{true: 0, false: 3}[passed],
		}); err != nil {
			t.Fatalf("RecordScan(%s): %v", digest, err)
		}
	}

	runningOld := []ClusterImageEntry{
		{Namespace: namespace, ImageRef: imageRef, Tag: tag, Digest: failingA, Workloads: []string{"StatefulSet/cortex-memcached-frontend"}},
		{Namespace: namespace, ImageRef: imageRef, Tag: tag, Digest: failingB, Workloads: []string{"StatefulSet/cortex-memcached-frontend", "StatefulSet/cortex-memcached-blocks"}},
	}
	wantWorkloads := map[string][]string{
		failingA: {"StatefulSet/cortex-memcached-frontend"},
		failingB: {"StatefulSet/cortex-memcached-blocks", "StatefulSet/cortex-memcached-frontend"},
	}
	recordScan(failingA, false)
	// An image is in use while the cluster's latest report contains it.
	recordInventory(time.Now().UTC().Add(-10*time.Minute), runningOld...)
	recordScan(failingB, false)
	recordScan(passingC, true)

	// The current-binding list only knows the passing digest: this is what the
	// dashboard card used to read.
	current, err := pgStore.ListScans(ctx, ScanFilter{ImageUsage: ImageUsageInUse, PolicyStatus: "failed"})
	if err != nil {
		t.Fatalf("ListScans: %v", err)
	}
	if len(current) != 0 {
		t.Fatalf("ListScans(in_use, failed) = %d records, want 0 (tag now points at the passing digest)", len(current))
	}

	running, err := pgStore.ListRunningPolicyFailures(ctx)
	if err != nil {
		t.Fatalf("ListRunningPolicyFailures: %v", err)
	}
	if got := runningDigests(running); !equalStrings(got, []string{failingA, failingB}) {
		t.Fatalf("running failures = %v, want %v", got, []string{failingA, failingB})
	}
	for _, record := range running {
		if !record.Superseded || record.CurrentDigest != passingC {
			t.Fatalf("%s: Superseded=%v CurrentDigest=%q, want superseded by %s", record.Digest, record.Superseded, record.CurrentDigest, passingC)
		}
		if record.Tag != tag || record.Repository != repo {
			t.Fatalf("%s: repository/tag = %s:%s, want %s:%s", record.Digest, record.Repository, record.Tag, repo, tag)
		}
		images := record.Runtime[cluster][namespace]
		if len(images) != 1 || images[0].Digest != record.Digest {
			t.Fatalf("%s: runtime = %+v, want only its own digest in %s/%s", record.Digest, record.Runtime, cluster, namespace)
		}
		if got := images[0].Workloads; !equalStrings(got, wantWorkloads[record.Digest]) {
			t.Fatalf("%s: workloads = %v, want %v", record.Digest, got, wantWorkloads[record.Digest])
		}
	}

	summary, err := pgStore.GetPolicyOutcomeSummary(ctx)
	if err != nil {
		t.Fatalf("GetPolicyOutcomeSummary: %v", err)
	}
	if summary.Failed.Runtime != 2 {
		t.Fatalf("Failed.Runtime = %d, want 2 (same set as ListRunningPolicyFailures)", summary.Failed.Runtime)
	}

	// Pods rolled onto the new digest: the tag-only and the new-digest observations
	// belong to the passing current binding, not to the superseded digests.
	recordInventory(time.Now().UTC(),
		ClusterImageEntry{Namespace: namespace, ImageRef: imageRef, Tag: tag, Digest: passingC},
		ClusterImageEntry{Namespace: "other", ImageRef: imageRef, Tag: tag},
	)
	running, err = pgStore.ListRunningPolicyFailures(ctx)
	if err != nil {
		t.Fatalf("ListRunningPolicyFailures after roll: %v", err)
	}
	if len(running) != 0 {
		t.Fatalf("running failures after roll = %v, want none", runningDigests(running))
	}
	summary, err = pgStore.GetPolicyOutcomeSummary(ctx)
	if err != nil {
		t.Fatalf("GetPolicyOutcomeSummary after roll: %v", err)
	}
	if summary.Failed.Runtime != 0 {
		t.Fatalf("Failed.Runtime after roll = %d, want 0", summary.Failed.Runtime)
	}
}

// A failing current binding is not running just because pods run an older,
// passing digest of the same tag.
func TestListRunningPolicyFailures_CurrentBindingNotCreditedWithOldDigest(t *testing.T) {
	store, cleanup := createTestStore(t)
	defer cleanup()

	pgStore := store.(*Store)
	ctx := context.Background()
	const (
		repo     = "hostingmaloonde/redis"
		imageRef = "docker.io/hostingmaloonde/redis"
		tag      = "8.2"
		oldPass  = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
		newFail  = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
	)

	if err := store.RecordScan(ctx, &ScanRecord{Repository: repo, Digest: oldPass, Tag: tag, PolicyPassed: true, PolicyStatus: "passed"}); err != nil {
		t.Fatalf("RecordScan(old): %v", err)
	}
	if err := pgStore.RecordClusterInventory(ctx, "c1", []ClusterImageEntry{
		{Namespace: "cache", ImageRef: imageRef, Tag: tag, Digest: oldPass},
	}, time.Now().UTC()); err != nil {
		t.Fatalf("RecordClusterInventory: %v", err)
	}
	if err := store.RecordScan(ctx, &ScanRecord{Repository: repo, Digest: newFail, Tag: tag, PolicyPassed: false, PolicyStatus: "failed"}); err != nil {
		t.Fatalf("RecordScan(new): %v", err)
	}

	running, err := pgStore.ListRunningPolicyFailures(ctx)
	if err != nil {
		t.Fatalf("ListRunningPolicyFailures: %v", err)
	}
	if len(running) != 0 {
		t.Fatalf("running failures = %v, want none: no cluster runs %s", runningDigests(running), newFail)
	}
}

func runningDigests(records []*ScanRecord) []string {
	out := make([]string, 0, len(records))
	for _, record := range records {
		out = append(out, record.Digest)
	}
	sort.Strings(out)
	return out
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
