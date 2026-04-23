package statestore

import (
	"context"
	"database/sql"
	"os"
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/daimoniac/suppline/internal/types"
)

func TestRecordClusterInventory_ReplacesSnapshot(t *testing.T) {
	dbPath := "test_cluster_inventory_" + t.Name() + ".db"
	_ = os.Remove(dbPath)
	defer os.Remove(dbPath)

	store, err := NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("Failed to create SQLite store: %v", err)
	}
	defer store.Close()

	ctx := context.Background()
	cluster := "prod-eu-1"

	t1 := time.Now().UTC().Add(-2 * time.Minute)
	first := []ClusterImageEntry{
		{Namespace: "default", ImageRef: "nginx:1.25", Tag: "1.25", Digest: "sha256:aaa"},
		{Namespace: "payments", ImageRef: "registry.example.com/app@sha256:bbb", Digest: "sha256:bbb"},
	}
	if err := store.RecordClusterInventory(ctx, cluster, first, t1); err != nil {
		t.Fatalf("RecordClusterInventory(first) failed: %v", err)
	}

	t2 := time.Now().UTC()
	second := []ClusterImageEntry{
		{Namespace: "default", ImageRef: "nginx:1.26", Tag: "1.26", Digest: "sha256:ccc"},
	}
	if err := store.RecordClusterInventory(ctx, cluster, second, t2); err != nil {
		t.Fatalf("RecordClusterInventory(second) failed: %v", err)
	}

	rows, err := queryClusterImages(store.db, cluster)
	if err != nil {
		t.Fatalf("queryClusterImages failed: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("Expected 1 image row after replacement, got %d", len(rows))
	}

	if rows[0].namespace != "default" || rows[0].imageRef != "nginx:1.26" || rows[0].digest != "sha256:ccc" {
		t.Fatalf("Unexpected row after replacement: %+v", rows[0])
	}

	lastReportedAt, err := queryClusterLastReportedAt(store.db, cluster)
	if err != nil {
		t.Fatalf("queryClusterLastReportedAt failed: %v", err)
	}
	if lastReportedAt != t2.Unix() {
		t.Fatalf("Expected last_reported_at %d, got %d", t2.Unix(), lastReportedAt)
	}
}

func TestRecordClusterInventory_EmptyImagesClearsExisting(t *testing.T) {
	dbPath := "test_cluster_inventory_" + t.Name() + ".db"
	_ = os.Remove(dbPath)
	defer os.Remove(dbPath)

	store, err := NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("Failed to create SQLite store: %v", err)
	}
	defer store.Close()

	ctx := context.Background()
	cluster := "prod-us-1"

	if err := store.RecordClusterInventory(ctx, cluster, []ClusterImageEntry{
		{Namespace: "default", ImageRef: "busybox:latest", Tag: "latest"},
	}, time.Now().UTC().Add(-time.Minute)); err != nil {
		t.Fatalf("RecordClusterInventory(seed) failed: %v", err)
	}

	if err := store.RecordClusterInventory(ctx, cluster, []ClusterImageEntry{}, time.Now().UTC()); err != nil {
		t.Fatalf("RecordClusterInventory(empty) failed: %v", err)
	}

	rows, err := queryClusterImages(store.db, cluster)
	if err != nil {
		t.Fatalf("queryClusterImages failed: %v", err)
	}
	if len(rows) != 0 {
		t.Fatalf("Expected 0 image rows after empty replacement, got %d", len(rows))
	}
}

func TestRecordClusterInventory_PrefersDigestRowsOverDigestlessDuplicates(t *testing.T) {
	dbPath := "test_cluster_inventory_" + t.Name() + ".db"
	_ = os.Remove(dbPath)
	defer os.Remove(dbPath)

	store, err := NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("Failed to create SQLite store: %v", err)
	}
	defer store.Close()

	ctx := context.Background()
	cluster := "staging-a"

	images := []ClusterImageEntry{
		{Namespace: "default", ImageRef: "docker.io/library/nginx", Tag: "1.29.5", Digest: ""},
		{Namespace: "default", ImageRef: "docker.io/library/nginx", Tag: "1.29.5", Digest: "sha256:a"},
		{Namespace: "default", ImageRef: "docker.io/library/nginx", Tag: "1.29.5", Digest: "sha256:b"},
		{Namespace: "default", ImageRef: "docker.io/library/nginx", Tag: "1.29.5", Digest: "sha256:a"},
		{Namespace: "ops", ImageRef: "busybox", Tag: "latest", Digest: ""},
		{Namespace: "ops", ImageRef: "busybox", Tag: "latest", Digest: ""},
	}

	if err := store.RecordClusterInventory(ctx, cluster, images, time.Now().UTC()); err != nil {
		t.Fatalf("RecordClusterInventory failed: %v", err)
	}

	rows, err := queryClusterImages(store.db, cluster)
	if err != nil {
		t.Fatalf("queryClusterImages failed: %v", err)
	}

	if len(rows) != 3 {
		t.Fatalf("Expected 3 deduplicated rows, got %d", len(rows))
	}

	seen := make(map[string]bool)
	for _, row := range rows {
		key := row.namespace + "|" + row.imageRef + "|" + row.tag + "|" + row.digest
		seen[key] = true
	}

	if !seen["default|docker.io/library/nginx|1.29.5|sha256:a"] {
		t.Fatalf("Expected nginx digest sha256:a row")
	}
	if !seen["default|docker.io/library/nginx|1.29.5|sha256:b"] {
		t.Fatalf("Expected nginx digest sha256:b row")
	}
	if !seen["ops|busybox|latest|"] {
		t.Fatalf("Expected single busybox digestless row")
	}
	if seen["default|docker.io/library/nginx|1.29.5|"] {
		t.Fatalf("Did not expect digestless nginx row when digests exist")
	}
}

func TestListClusterSummaries(t *testing.T) {
	dbPath := "test_cluster_summary_" + t.Name() + ".db"
	_ = os.Remove(dbPath)
	defer os.Remove(dbPath)

	store, err := NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("Failed to create SQLite store: %v", err)
	}
	defer store.Close()

	ctx := context.Background()
	tA := time.Now().UTC().Add(-2 * time.Minute)
	tB := time.Now().UTC().Add(-1 * time.Minute)

	if err := store.RecordClusterInventory(ctx, "cluster-b", []ClusterImageEntry{
		{Namespace: "default", ImageRef: "nginx:1.26", Tag: "1.26", Digest: "sha256:b1"},
		{Namespace: "payments", ImageRef: "redis:7", Tag: "7", Digest: "sha256:b2"},
	}, tB); err != nil {
		t.Fatalf("RecordClusterInventory(cluster-b) failed: %v", err)
	}

	if err := store.RecordClusterInventory(ctx, "cluster-a", []ClusterImageEntry{
		{Namespace: "default", ImageRef: "busybox:latest", Tag: "latest", Digest: "sha256:a1"},
	}, tA); err != nil {
		t.Fatalf("RecordClusterInventory(cluster-a) failed: %v", err)
	}

	summaries, err := store.ListClusterSummaries(ctx)
	if err != nil {
		t.Fatalf("ListClusterSummaries failed: %v", err)
	}

	if len(summaries) != 2 {
		t.Fatalf("Expected 2 cluster summaries, got %d", len(summaries))
	}

	if summaries[0].Name != "cluster-a" || summaries[0].ImageCount != 1 {
		t.Fatalf("Unexpected first summary: %+v", summaries[0])
	}
	if summaries[0].LastReported == nil || *summaries[0].LastReported != tA.Unix() {
		t.Fatalf("Unexpected first last reported: %+v", summaries[0].LastReported)
	}

	if summaries[1].Name != "cluster-b" || summaries[1].ImageCount != 2 {
		t.Fatalf("Unexpected second summary: %+v", summaries[1])
	}
	if summaries[1].LastReported == nil || *summaries[1].LastReported != tB.Unix() {
		t.Fatalf("Unexpected second last reported: %+v", summaries[1].LastReported)
	}
}

func TestDeleteClusterInventory(t *testing.T) {
	dbPath := "test_cluster_delete_" + t.Name() + ".db"
	_ = os.Remove(dbPath)
	defer os.Remove(dbPath)

	store, err := NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("Failed to create SQLite store: %v", err)
	}
	defer store.Close()

	ctx := context.Background()

	if err := store.RecordClusterInventory(ctx, "cluster-a", []ClusterImageEntry{{
		Namespace: "default",
		ImageRef:  "nginx:1.25",
		Tag:       "1.25",
		Digest:    "sha256:a1",
	}}, time.Now().UTC()); err != nil {
		t.Fatalf("RecordClusterInventory(cluster-a) failed: %v", err)
	}

	if err := store.RecordClusterInventory(ctx, "cluster-b", []ClusterImageEntry{{
		Namespace: "default",
		ImageRef:  "busybox:latest",
		Tag:       "latest",
		Digest:    "sha256:b1",
	}}, time.Now().UTC()); err != nil {
		t.Fatalf("RecordClusterInventory(cluster-b) failed: %v", err)
	}

	if err := store.DeleteClusterInventory(ctx, "cluster-a"); err != nil {
		t.Fatalf("DeleteClusterInventory failed: %v", err)
	}

	summaries, err := store.ListClusterSummaries(ctx)
	if err != nil {
		t.Fatalf("ListClusterSummaries failed: %v", err)
	}

	if len(summaries) != 1 {
		t.Fatalf("Expected 1 cluster summary after delete, got %d", len(summaries))
	}
	if summaries[0].Name != "cluster-b" {
		t.Fatalf("Expected remaining cluster to be cluster-b, got %s", summaries[0].Name)
	}

	rows, err := queryClusterImages(store.db, "cluster-a")
	if err != nil {
		t.Fatalf("queryClusterImages failed: %v", err)
	}
	if len(rows) != 0 {
		t.Fatalf("Expected deleted cluster to have 0 image rows, got %d", len(rows))
	}
}

func TestGetRuntimeUsageForScan_DigestMatch(t *testing.T) {
	dbPath := "test_cluster_runtime_digest_" + t.Name() + ".db"
	_ = os.Remove(dbPath)
	defer os.Remove(dbPath)

	store, err := NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("Failed to create SQLite store: %v", err)
	}
	defer store.Close()

	ctx := context.Background()
	record := &ScanRecord{
		Repository:           "docker.io/library/nginx",
		Tag:                  "1.25",
		Digest:               "sha256:scan-digest",
		PolicyPassed:         true,
		SBOMAttested:         true,
		VulnAttested:         true,
		SCAIAttested:         true,
		Vulnerabilities:      []types.VulnerabilityRecord{},
		AppliedVEXStatements: []types.AppliedVEXStatement{},
	}
	if err := store.RecordScan(ctx, record); err != nil {
		t.Fatalf("RecordScan failed: %v", err)
	}

	if err := store.RecordClusterInventory(ctx, "cluster-a", []ClusterImageEntry{
		{Namespace: "default", ImageRef: "docker.io/library/nginx", Tag: "1.25", Digest: "sha256:scan-digest"},
	}, time.Now().UTC()); err != nil {
		t.Fatalf("RecordClusterInventory failed: %v", err)
	}

	usage, err := store.GetRuntimeUsageForScan(ctx, record.Digest, record.Repository, record.Tag)
	if err != nil {
		t.Fatalf("GetRuntimeUsageForScan failed: %v", err)
	}
	if !usage.RuntimeUsed {
		t.Fatalf("Expected runtime usage to be true")
	}
	if got := runtimeClusterNames(usage.Runtime); !reflect.DeepEqual(got, []string{"cluster-a"}) {
		t.Fatalf("Unexpected runtime clusters: %+v", got)
	}
	if images := usage.Runtime["cluster-a"]["default"]; len(images) != 1 || images[0].ImageRef != "docker.io/library/nginx" || images[0].Tag != "1.25" || images[0].Digest != "sha256:scan-digest" {
		t.Fatalf("Unexpected runtime payload: %+v", usage.Runtime)
	}

	bulk, err := store.GetRuntimeUsageForScans(ctx, []RuntimeLookupInput{{
		Digest:     record.Digest,
		Repository: record.Repository,
		Tag:        record.Tag,
	}})
	if err != nil {
		t.Fatalf("GetRuntimeUsageForScans failed: %v", err)
	}

	bulkUsage, ok := bulk[record.Digest]
	if !ok || !bulkUsage.RuntimeUsed {
		t.Fatalf("Expected digest runtime usage in bulk map, got: %+v", bulk)
	}
}

func TestGetRuntimeUsageForScan_FallbackRepositoryTagMatch(t *testing.T) {
	dbPath := "test_cluster_runtime_fallback_" + t.Name() + ".db"
	_ = os.Remove(dbPath)
	defer os.Remove(dbPath)

	store, err := NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("Failed to create SQLite store: %v", err)
	}
	defer store.Close()

	ctx := context.Background()
	record := &ScanRecord{
		Repository:           "docker.io/library/nginx",
		Tag:                  "1.26",
		Digest:               "sha256:unmatched-scan-digest",
		PolicyPassed:         true,
		SBOMAttested:         true,
		VulnAttested:         true,
		SCAIAttested:         true,
		Vulnerabilities:      []types.VulnerabilityRecord{},
		AppliedVEXStatements: []types.AppliedVEXStatement{},
	}
	if err := store.RecordScan(ctx, record); err != nil {
		t.Fatalf("RecordScan failed: %v", err)
	}

	if err := store.RecordClusterInventory(ctx, "cluster-b", []ClusterImageEntry{
		{Namespace: "kube-system", ImageRef: "nginx", Tag: "1.26", Digest: ""},
	}, time.Now().UTC()); err != nil {
		t.Fatalf("RecordClusterInventory failed: %v", err)
	}

	usage, err := store.GetRuntimeUsageForScan(ctx, record.Digest, record.Repository, record.Tag)
	if err != nil {
		t.Fatalf("GetRuntimeUsageForScan failed: %v", err)
	}
	if !usage.RuntimeUsed {
		t.Fatalf("Expected fallback runtime usage to be true")
	}
	if got := runtimeClusterNames(usage.Runtime); !reflect.DeepEqual(got, []string{"cluster-b"}) {
		t.Fatalf("Unexpected runtime clusters: %+v", got)
	}
	if images := usage.Runtime["cluster-b"]["kube-system"]; len(images) != 1 || images[0].ImageRef != "nginx" || images[0].Tag != "1.26" || images[0].Digest != "" {
		t.Fatalf("Unexpected fallback runtime payload: %+v", usage.Runtime)
	}
}

func TestGetRuntimeUsageForScan_MergesDigestAndDigestlessTagFallback(t *testing.T) {
	dbPath := "test_cluster_runtime_merge_" + t.Name() + ".db"
	_ = os.Remove(dbPath)
	defer os.Remove(dbPath)

	store, err := NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("Failed to create SQLite store: %v", err)
	}
	defer store.Close()

	ctx := context.Background()
	record := &ScanRecord{
		Repository:           "docker.io/library/nginx",
		Tag:                  "1.28",
		Digest:               "sha256:merge-digest",
		PolicyPassed:         true,
		SBOMAttested:         true,
		VulnAttested:         true,
		SCAIAttested:         true,
		Vulnerabilities:      []types.VulnerabilityRecord{},
		AppliedVEXStatements: []types.AppliedVEXStatement{},
	}
	if err := store.RecordScan(ctx, record); err != nil {
		t.Fatalf("RecordScan failed: %v", err)
	}

	if err := store.RecordClusterInventory(ctx, "cluster-digest", []ClusterImageEntry{{
		Namespace: "default",
		ImageRef:  "docker.io/library/nginx",
		Tag:       "1.28",
		Digest:    "sha256:merge-digest",
	}}, time.Now().UTC()); err != nil {
		t.Fatalf("RecordClusterInventory(cluster-digest) failed: %v", err)
	}

	if err := store.RecordClusterInventory(ctx, "cluster-tag-only", []ClusterImageEntry{{
		Namespace: "default",
		ImageRef:  "nginx",
		Tag:       "1.28",
		Digest:    "",
	}}, time.Now().UTC()); err != nil {
		t.Fatalf("RecordClusterInventory(cluster-tag-only) failed: %v", err)
	}

	usage, err := store.GetRuntimeUsageForScan(ctx, record.Digest, record.Repository, record.Tag)
	if err != nil {
		t.Fatalf("GetRuntimeUsageForScan failed: %v", err)
	}
	if !usage.RuntimeUsed {
		t.Fatalf("Expected merged runtime usage to be true")
	}
	wantClusters := []string{"cluster-digest", "cluster-tag-only"}
	if got := runtimeClusterNames(usage.Runtime); !reflect.DeepEqual(wantClusters, got) {
		t.Fatalf("Unexpected runtime clusters: got %+v want %+v", got, wantClusters)
	}

	bulk, err := store.GetRuntimeUsageForScans(ctx, []RuntimeLookupInput{{
		Digest:     record.Digest,
		Repository: record.Repository,
		Tag:        record.Tag,
	}})
	if err != nil {
		t.Fatalf("GetRuntimeUsageForScans failed: %v", err)
	}

	bulkUsage, ok := bulk[record.Digest]
	if !ok || !bulkUsage.RuntimeUsed {
		t.Fatalf("Expected digest runtime usage in bulk map, got: %+v", bulk)
	}
	if got := runtimeClusterNames(bulkUsage.Runtime); !reflect.DeepEqual(wantClusters, got) {
		t.Fatalf("Unexpected bulk runtime clusters: got %+v want %+v", got, wantClusters)
	}
}

func TestGetRuntimeUsageForScan_IncludesDistinctDigestVariantForMatchingTag(t *testing.T) {
	dbPath := "test_cluster_runtime_include_distinct_digest_variant_" + t.Name() + ".db"
	_ = os.Remove(dbPath)
	defer os.Remove(dbPath)

	store, err := NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("Failed to create SQLite store: %v", err)
	}
	defer store.Close()

	ctx := context.Background()
	if err := store.RecordClusterInventory(ctx, "cluster-has-other-digest", []ClusterImageEntry{{
		Namespace: "default",
		ImageRef:  "nginx",
		Tag:       "1.29",
		Digest:    "sha256:other-digest",
	}}, time.Now().UTC()); err != nil {
		t.Fatalf("RecordClusterInventory failed: %v", err)
	}

	usage, err := store.GetRuntimeUsageForScan(ctx, "sha256:expected-digest", "docker.io/library/nginx", "1.29")
	if err != nil {
		t.Fatalf("GetRuntimeUsageForScan failed: %v", err)
	}
	if !usage.RuntimeUsed {
		t.Fatalf("Expected runtime usage when a matching repo+tag exists with a distinct digest")
	}
	if got := runtimeClusterNames(usage.Runtime); !reflect.DeepEqual(got, []string{"cluster-has-other-digest"}) {
		t.Fatalf("Unexpected runtime clusters: %+v", got)
	}
	if images := usage.Runtime["cluster-has-other-digest"]["default"]; len(images) != 1 || images[0].Digest != "sha256:other-digest" {
		t.Fatalf("Expected runtime payload to include the distinct digest variant, got %+v", usage.Runtime)
	}

	bulk, err := store.GetRuntimeUsageForScans(ctx, []RuntimeLookupInput{{
		Digest:     "sha256:expected-digest",
		Repository: "docker.io/library/nginx",
		Tag:        "1.29",
	}})
	if err != nil {
		t.Fatalf("GetRuntimeUsageForScans failed: %v", err)
	}
	bulkUsage, ok := bulk["sha256:expected-digest"]
	if !ok || !bulkUsage.RuntimeUsed {
		t.Fatalf("Expected bulk runtime usage when only a distinct digest variant exists, got %+v", bulk)
	}
	if images := bulkUsage.Runtime["cluster-has-other-digest"]["default"]; len(images) != 1 || images[0].Digest != "sha256:other-digest" {
		t.Fatalf("Expected bulk runtime payload to include the distinct digest variant, got %+v", bulkUsage.Runtime)
	}
}

func runtimeClusterNames(runtime RuntimeInventory) []string {
	clusters := make([]string, 0, len(runtime))
	for cluster := range runtime {
		clusters = append(clusters, cluster)
	}
	sort.Strings(clusters)
	return clusters
}

func TestGetRuntimeUsageForScan_NoMatch(t *testing.T) {
	dbPath := "test_cluster_runtime_nomatch_" + t.Name() + ".db"
	_ = os.Remove(dbPath)
	defer os.Remove(dbPath)

	store, err := NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("Failed to create SQLite store: %v", err)
	}
	defer store.Close()

	ctx := context.Background()
	if err := store.RecordClusterInventory(ctx, "cluster-c", []ClusterImageEntry{
		{Namespace: "default", ImageRef: "busybox", Tag: "latest", Digest: "sha256:busybox"},
	}, time.Now().UTC()); err != nil {
		t.Fatalf("RecordClusterInventory failed: %v", err)
	}

	usage, err := store.GetRuntimeUsageForScan(ctx, "sha256:not-found", "docker.io/library/nginx", "1.25")
	if err != nil {
		t.Fatalf("GetRuntimeUsageForScan failed: %v", err)
	}
	if usage.RuntimeUsed {
		t.Fatalf("Expected no runtime usage, got %+v", usage)
	}
}

func TestListScans_InUseFilter_UsesCanonicalRepositoryTagFallback(t *testing.T) {
	dbPath := "test_cluster_runtime_scan_in_use_canonical_" + t.Name() + ".db"
	_ = os.Remove(dbPath)
	defer os.Remove(dbPath)

	store, err := NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("Failed to create SQLite store: %v", err)
	}
	defer store.Close()

	ctx := context.Background()
	record := &ScanRecord{
		Repository:           "hostingmaloonde/falcosecurity_falco",
		Tag:                  "0.41.3",
		Digest:               "sha256:scan-digest-not-in-runtime",
		PolicyPassed:         true,
		SBOMAttested:         true,
		VulnAttested:         true,
		SCAIAttested:         true,
		Vulnerabilities:      []types.VulnerabilityRecord{},
		AppliedVEXStatements: []types.AppliedVEXStatement{},
	}
	if err := store.RecordScan(ctx, record); err != nil {
		t.Fatalf("RecordScan failed: %v", err)
	}

	if err := store.RecordClusterInventory(ctx, "cluster-falco", []ClusterImageEntry{{
		Namespace: "falco",
		ImageRef:  "docker.io/hostingmaloonde/falcosecurity_falco",
		Tag:       "0.41.3",
		Digest:    "",
	}}, time.Now().UTC()); err != nil {
		t.Fatalf("RecordClusterInventory failed: %v", err)
	}

	inUseScans, err := store.ListScans(ctx, ScanFilter{ImageUsage: ImageUsageInUse, Limit: 100, Offset: 0})
	if err != nil {
		t.Fatalf("ListScans(in_use=true) failed: %v", err)
	}
	if len(inUseScans) != 1 || inUseScans[0].Digest != record.Digest {
		t.Fatalf("expected one in-use scan for %s, got %+v", record.Digest, inUseScans)
	}

	inUseCount, err := store.CountScans(ctx, ScanFilter{ImageUsage: ImageUsageInUse})
	if err != nil {
		t.Fatalf("CountScans(in_use=true) failed: %v", err)
	}
	if inUseCount != 1 {
		t.Fatalf("expected CountScans(in_use=true)=1, got %d", inUseCount)
	}

	notInUseScans, err := store.ListScans(ctx, ScanFilter{ImageUsage: ImageUsageNotInUse, Limit: 100, Offset: 0})
	if err != nil {
		t.Fatalf("ListScans(in_use=false) failed: %v", err)
	}
	if len(notInUseScans) != 0 {
		t.Fatalf("expected no scans for in_use=false, got %+v", notInUseScans)
	}
}

func TestListScans_InUseOrNewerSemver(t *testing.T) {
	dbPath := "test_cluster_in_use_newer_" + t.Name() + ".db"
	_ = os.Remove(dbPath)
	defer os.Remove(dbPath)

	store, err := NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("Failed to create SQLite store: %v", err)
	}
	defer store.Close()

	const repo = "docker.io/lib/semverapp"
	digV100 := "sha256:semver-100"
	digV110 := "sha256:semver-110"
	digV090 := "sha256:semver-090"
	ctx := context.Background()

	records := []*ScanRecord{
		{Repository: repo, Tag: "1.0.0", Digest: digV100, PolicyPassed: true, SBOMAttested: true, VulnAttested: true, SCAIAttested: true, Vulnerabilities: []types.VulnerabilityRecord{}, AppliedVEXStatements: []types.AppliedVEXStatement{}},
		{Repository: repo, Tag: "1.1.0", Digest: digV110, PolicyPassed: true, SBOMAttested: true, VulnAttested: true, SCAIAttested: true, Vulnerabilities: []types.VulnerabilityRecord{}, AppliedVEXStatements: []types.AppliedVEXStatement{}},
		{Repository: repo, Tag: "0.9.0", Digest: digV090, PolicyPassed: true, SBOMAttested: true, VulnAttested: true, SCAIAttested: true, Vulnerabilities: []types.VulnerabilityRecord{}, AppliedVEXStatements: []types.AppliedVEXStatement{}},
	}
	for _, r := range records {
		if err := store.RecordScan(ctx, r); err != nil {
			t.Fatalf("RecordScan %s: %v", r.Tag, err)
		}
	}
	if err := store.RecordClusterInventory(ctx, "c1", []ClusterImageEntry{{
		Namespace: "default", ImageRef: repo, Tag: "1.0.0", Digest: digV100,
	}}, time.Now().UTC()); err != nil {
		t.Fatalf("RecordClusterInventory: %v", err)
	}

	strict, err := store.ListScans(ctx, ScanFilter{ImageUsage: ImageUsageInUse, Limit: 100, Offset: 0})
	if err != nil {
		t.Fatalf("ListScans strict: %v", err)
	}
	if len(strict) != 1 || strict[0].Tag != "1.0.0" {
		t.Fatalf("in_use only: want one row 1.0.0, got %+v", strict)
	}

	newer, err := store.ListScans(ctx, ScanFilter{ImageUsage: ImageUsageInUseOrNewerSemver, Limit: 100, Offset: 0})
	if err != nil {
		t.Fatalf("ListScans in_use_newer: %v", err)
	}
	if len(newer) != 2 {
		t.Fatalf("in_use+newer: want 2 rows, got %d: %+v", len(newer), tagNames(newer))
	}
	tagSet := map[string]struct{}{}
	for _, s := range newer {
		tagSet[s.Tag] = struct{}{}
	}
	if _, ok := tagSet["1.0.0"]; !ok {
		t.Fatal("expected 1.0.0 in in_use+newer list")
	}
	if _, ok := tagSet["1.1.0"]; !ok {
		t.Fatal("expected 1.1.0 in in_use+newer list (newer semver than max in use)")
	}
	if _, ok := tagSet["0.9.0"]; ok {
		t.Fatal("did not expect 0.9.0 in in_use+newer list (older than in-use 1.0.0)")
	}

	n, err := store.CountScans(ctx, ScanFilter{ImageUsage: ImageUsageInUseOrNewerSemver})
	if err != nil {
		t.Fatalf("CountScans: %v", err)
	}
	if n != 2 {
		t.Fatalf("CountScans in_use+newer: want 2, got %d", n)
	}
}

func tagNames(scans []*ScanRecord) []string {
	out := make([]string, 0, len(scans))
	for _, s := range scans {
		out = append(out, s.Tag)
	}
	sort.Strings(out)
	return out
}

func TestListRepositories_RuntimeUsageFallbackRepositoryTag(t *testing.T) {
	dbPath := "test_cluster_runtime_repo_list_fallback_" + t.Name() + ".db"
	_ = os.Remove(dbPath)
	defer os.Remove(dbPath)

	store, err := NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("Failed to create SQLite store: %v", err)
	}
	defer store.Close()

	ctx := context.Background()
	record := &ScanRecord{
		Repository:           "docker.io/library/nginx",
		Tag:                  "1.27",
		Digest:               "sha256:repo-list-fallback-digest",
		PolicyPassed:         true,
		SBOMAttested:         true,
		VulnAttested:         true,
		SCAIAttested:         true,
		Vulnerabilities:      []types.VulnerabilityRecord{},
		AppliedVEXStatements: []types.AppliedVEXStatement{},
	}
	if err := store.RecordScan(ctx, record); err != nil {
		t.Fatalf("RecordScan failed: %v", err)
	}

	other := &ScanRecord{
		Repository:           "docker.io/library/busybox",
		Tag:                  "latest",
		Digest:               "sha256:repo-list-not-in-use",
		PolicyPassed:         true,
		SBOMAttested:         true,
		VulnAttested:         true,
		SCAIAttested:         true,
		Vulnerabilities:      []types.VulnerabilityRecord{},
		AppliedVEXStatements: []types.AppliedVEXStatement{},
	}
	if err := store.RecordScan(ctx, other); err != nil {
		t.Fatalf("RecordScan(other) failed: %v", err)
	}

	// Digest intentionally omitted to force repository+tag fallback matching.
	if err := store.RecordClusterInventory(ctx, "cluster-d", []ClusterImageEntry{
		{Namespace: "default", ImageRef: "nginx", Tag: "1.27", Digest: ""},
	}, time.Now().UTC()); err != nil {
		t.Fatalf("RecordClusterInventory failed: %v", err)
	}

	resp, err := store.ListRepositories(ctx, RepositoryFilter{Limit: 100, Offset: 0})
	if err != nil {
		t.Fatalf("ListRepositories failed: %v", err)
	}

	if len(resp.Repositories) != 2 {
		t.Fatalf("Expected 2 repositories, got %d", len(resp.Repositories))
	}

	repoRuntime := map[string]bool{}
	for _, repo := range resp.Repositories {
		repoRuntime[repo.Name] = repo.RuntimeUsed
	}

	if !repoRuntime["docker.io/library/nginx"] {
		t.Fatalf("Expected nginx RuntimeUsed=true via repository+tag fallback")
	}
	if repoRuntime["docker.io/library/busybox"] {
		t.Fatalf("Expected busybox RuntimeUsed=false")
	}

	inUseResp, err := store.ListRepositories(ctx, RepositoryFilter{ImageUsage: ImageUsageInUse, Limit: 100, Offset: 0})
	if err != nil {
		t.Fatalf("ListRepositories(in_use=true) failed: %v", err)
	}
	if inUseResp.Total != 1 {
		t.Fatalf("Expected total=1 for in_use=true, got %d", inUseResp.Total)
	}
	if len(inUseResp.Repositories) != 1 || inUseResp.Repositories[0].Name != "docker.io/library/nginx" {
		t.Fatalf("Expected only nginx repository for in_use=true, got %+v", inUseResp.Repositories)
	}

	notInUseResp, err := store.ListRepositories(ctx, RepositoryFilter{ImageUsage: ImageUsageNotInUse, Limit: 100, Offset: 0})
	if err != nil {
		t.Fatalf("ListRepositories(in_use=false) failed: %v", err)
	}
	if notInUseResp.Total != 1 {
		t.Fatalf("Expected total=1 for in_use=false, got %d", notInUseResp.Total)
	}
	if len(notInUseResp.Repositories) != 1 || notInUseResp.Repositories[0].Name != "docker.io/library/busybox" {
		t.Fatalf("Expected only busybox repository for in_use=false, got %+v", notInUseResp.Repositories)
	}
}

func TestGetRuntimeUsageForScan_RespectsRuntimeInUseWindowAndLatestSync(t *testing.T) {
	dbPath := "test_cluster_runtime_window_" + t.Name() + ".db"
	_ = os.Remove(dbPath)
	defer os.Remove(dbPath)

	store, err := NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("Failed to create SQLite store: %v", err)
	}
	defer store.Close()
	store.SetRuntimeInUseWindow(60 * time.Minute)

	ctx := context.Background()
	record := &ScanRecord{
		Repository:           "docker.io/library/nginx",
		Tag:                  "1.25",
		Digest:               "sha256:window-digest",
		PolicyPassed:         true,
		SBOMAttested:         true,
		VulnAttested:         true,
		SCAIAttested:         true,
		Vulnerabilities:      []types.VulnerabilityRecord{},
		AppliedVEXStatements: []types.AppliedVEXStatement{},
	}
	if err := store.RecordScan(ctx, record); err != nil {
		t.Fatalf("RecordScan failed: %v", err)
	}

	staleSeenAt := time.Now().UTC().Add(-2 * time.Hour)
	if err := store.RecordClusterInventory(ctx, "cluster-a", []ClusterImageEntry{{
		Namespace: "default",
		ImageRef:  "docker.io/library/nginx",
		Tag:       "1.25",
		Digest:    "sha256:window-digest",
	}}, staleSeenAt); err != nil {
		t.Fatalf("RecordClusterInventory(initial stale) failed: %v", err)
	}

	usage, err := store.GetRuntimeUsageForScan(ctx, record.Digest, record.Repository, record.Tag)
	if err != nil {
		t.Fatalf("GetRuntimeUsageForScan(after initial sync) failed: %v", err)
	}
	if !usage.RuntimeUsed {
		t.Fatalf("expected image to be in use when it was present in the most recent cluster sync")
	}

	if err := store.RecordClusterInventory(ctx, "cluster-a", []ClusterImageEntry{}, time.Now().UTC()); err != nil {
		t.Fatalf("RecordClusterInventory(fresh sync without image) failed: %v", err)
	}

	usage, err = store.GetRuntimeUsageForScan(ctx, record.Digest, record.Repository, record.Tag)
	if err != nil {
		t.Fatalf("GetRuntimeUsageForScan(after image omitted) failed: %v", err)
	}
	if usage.RuntimeUsed {
		t.Fatalf("expected image to be not in use after latest sync omitted it and it is older than the runtime window")
	}
}

func TestListRepositories_RuntimeUsedWhenRepositorySeenWithDifferentTag(t *testing.T) {
	dbPath := "test_cluster_runtime_repo_seen_diff_tag_" + t.Name() + ".db"
	_ = os.Remove(dbPath)
	defer os.Remove(dbPath)

	store, err := NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("Failed to create SQLite store: %v", err)
	}
	defer store.Close()
	store.SetRuntimeInUseWindow(7 * 24 * time.Hour)

	ctx := context.Background()
	if err := store.RecordScan(ctx, &ScanRecord{
		Repository:           "hostingmaloonde/minio_minio",
		Tag:                  "RELEASE.2024-11-07T00-52-20Z",
		Digest:               "sha256:minio-scanned",
		PolicyPassed:         true,
		SBOMAttested:         true,
		VulnAttested:         true,
		SCAIAttested:         true,
		Vulnerabilities:      []types.VulnerabilityRecord{},
		AppliedVEXStatements: []types.AppliedVEXStatement{},
	}); err != nil {
		t.Fatalf("RecordScan failed: %v", err)
	}

	if err := store.RecordClusterInventory(ctx, "cluster-a", []ClusterImageEntry{{
		Namespace: "gitlab-runner",
		ImageRef:  "hostingmaloonde/minio_minio",
		Tag:       "RELEASE.2024-12-18T13-15-44Z",
		Digest:    "",
	}}, time.Now().UTC()); err != nil {
		t.Fatalf("RecordClusterInventory failed: %v", err)
	}

	resp, err := store.ListRepositories(ctx, RepositoryFilter{Limit: 100, Offset: 0})
	if err != nil {
		t.Fatalf("ListRepositories failed: %v", err)
	}

	var found *RepositoryInfo
	for i := range resp.Repositories {
		if resp.Repositories[i].Name == "hostingmaloonde/minio_minio" {
			found = &resp.Repositories[i]
			break
		}
	}
	if found == nil {
		t.Fatalf("expected repository hostingmaloonde/minio_minio in response")
	}
	if !found.RuntimeUsed {
		t.Fatalf("expected RuntimeUsed=true when repository was seen recently with a different tag")
	}

	notInUseResp, err := store.ListRepositories(ctx, RepositoryFilter{ImageUsage: ImageUsageNotInUse, Limit: 100, Offset: 0})
	if err != nil {
		t.Fatalf("ListRepositories(in_use=false) failed: %v", err)
	}
	for _, repo := range notInUseResp.Repositories {
		if repo.Name == "hostingmaloonde/minio_minio" {
			t.Fatalf("did not expect hostingmaloonde/minio_minio in in_use=false results")
		}
	}
}

type clusterImageRow struct {
	namespace string
	imageRef  string
	tag       string
	digest    string
}

func queryClusterImages(db *sql.DB, cluster string) ([]clusterImageRow, error) {
	rows, err := db.Query(`
		SELECT ci.namespace, ci.image_ref, COALESCE(ci.tag, ''), COALESCE(ci.digest, '')
		FROM cluster_images ci
		JOIN clusters c ON c.id = ci.cluster_id
		WHERE c.name = ?
		ORDER BY ci.namespace, ci.image_ref
	`, cluster)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []clusterImageRow
	for rows.Next() {
		var r clusterImageRow
		if err := rows.Scan(&r.namespace, &r.imageRef, &r.tag, &r.digest); err != nil {
			return nil, err
		}
		result = append(result, r)
	}

	return result, rows.Err()
}

func queryClusterLastReportedAt(db *sql.DB, cluster string) (int64, error) {
	var lastReportedAt sql.NullInt64
	err := db.QueryRow(`SELECT last_reported_at FROM clusters WHERE name = ?`, cluster).Scan(&lastReportedAt)
	if err != nil {
		return 0, err
	}
	if !lastReportedAt.Valid {
		return 0, nil
	}
	return lastReportedAt.Int64, nil
}
