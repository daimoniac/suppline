package statestore

import (
	"context"
	"database/sql"
	"os"
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
		Repository:      "docker.io/library/nginx",
		Tag:             "1.25",
		Digest:          "sha256:scan-digest",
		PolicyPassed:    true,
		SBOMAttested:    true,
		VulnAttested:    true,
		SCAIAttested:    true,
		Vulnerabilities: []types.VulnerabilityRecord{},
		ToleratedCVEs:   []types.ToleratedCVE{},
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
	if len(usage.RuntimeClusters) != 1 || usage.RuntimeClusters[0] != "cluster-a" {
		t.Fatalf("Unexpected runtime clusters: %+v", usage.RuntimeClusters)
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
		Repository:      "docker.io/library/nginx",
		Tag:             "1.26",
		Digest:          "sha256:unmatched-scan-digest",
		PolicyPassed:    true,
		SBOMAttested:    true,
		VulnAttested:    true,
		SCAIAttested:    true,
		Vulnerabilities: []types.VulnerabilityRecord{},
		ToleratedCVEs:   []types.ToleratedCVE{},
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
	if len(usage.RuntimeClusters) != 1 || usage.RuntimeClusters[0] != "cluster-b" {
		t.Fatalf("Unexpected runtime clusters: %+v", usage.RuntimeClusters)
	}
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
