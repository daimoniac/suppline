package statestore

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/daimoniac/suppline/internal/types"
)

func TestCountDueForRescan_UsesLastScanAge(t *testing.T) {
	dbPath := "test_count_due_" + t.Name() + ".db"
	_ = os.Remove(dbPath)
	defer os.Remove(dbPath)

	store, err := NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	defer store.Close()

	ctx := context.Background()
	fresh := &ScanRecord{
		Repository: "docker.io/lib/fresh", Tag: "1.0.0", Digest: "sha256:fresh",
		PolicyPassed: true, SBOMAttested: true, VulnAttested: true, SCAIAttested: true,
		Vulnerabilities: []types.VulnerabilityRecord{}, AppliedVEXStatements: []types.AppliedVEXStatement{},
	}
	stale := &ScanRecord{
		Repository: "docker.io/lib/stale", Tag: "1.0.0", Digest: "sha256:stale",
		PolicyPassed: true, SBOMAttested: true, VulnAttested: true, SCAIAttested: true,
		Vulnerabilities: []types.VulnerabilityRecord{}, AppliedVEXStatements: []types.AppliedVEXStatement{},
	}
	for _, r := range []*ScanRecord{fresh, stale} {
		if err := store.RecordScan(ctx, r); err != nil {
			t.Fatalf("RecordScan: %v", err)
		}
	}

	// Backdate the stale scan to 10 days ago.
	if _, err := store.db.ExecContext(ctx, `
		UPDATE scan_records SET created_at = ?
		WHERE artifact_id = (SELECT id FROM artifacts WHERE digest = ?)
	`, time.Now().UTC().Add(-10*24*time.Hour).Unix(), stale.Digest); err != nil {
		t.Fatalf("backdate stale scan: %v", err)
	}

	due, err := store.CountDueForRescan(ctx, 7*24*time.Hour)
	if err != nil {
		t.Fatalf("CountDueForRescan: %v", err)
	}
	if due != 1 {
		t.Fatalf("CountDueForRescan=%d, want 1", due)
	}
}

func TestCountCurrentDigests_TotalAndInUse(t *testing.T) {
	dbPath := "test_count_digests_" + t.Name() + ".db"
	_ = os.Remove(dbPath)
	defer os.Remove(dbPath)

	store, err := NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	defer store.Close()

	ctx := context.Background()
	inUse := &ScanRecord{
		Repository: "docker.io/lib/inuse", Tag: "1.0.0", Digest: "sha256:inuse",
		PolicyPassed: true, SBOMAttested: true, VulnAttested: true, SCAIAttested: true,
		Vulnerabilities: []types.VulnerabilityRecord{}, AppliedVEXStatements: []types.AppliedVEXStatement{},
	}
	idle := &ScanRecord{
		Repository: "docker.io/lib/idle", Tag: "1.0.0", Digest: "sha256:idle",
		PolicyPassed: true, SBOMAttested: true, VulnAttested: true, SCAIAttested: true,
		Vulnerabilities: []types.VulnerabilityRecord{}, AppliedVEXStatements: []types.AppliedVEXStatement{},
	}
	for _, r := range []*ScanRecord{inUse, idle} {
		if err := store.RecordScan(ctx, r); err != nil {
			t.Fatalf("RecordScan: %v", err)
		}
	}

	if err := store.RecordClusterInventory(ctx, "c1", []ClusterImageEntry{{
		Namespace: "default", ImageRef: inUse.Repository, Tag: inUse.Tag, Digest: inUse.Digest,
	}}, time.Now().UTC()); err != nil {
		t.Fatalf("RecordClusterInventory: %v", err)
	}

	total, used, err := store.CountCurrentDigests(ctx)
	if err != nil {
		t.Fatalf("CountCurrentDigests: %v", err)
	}
	if total != 2 {
		t.Fatalf("total=%d, want 2", total)
	}
	if used != 1 {
		t.Fatalf("inUse=%d, want 1", used)
	}
}

// Runtime inventory often reports images without a digest, so the in-use digest count must
// use the same repository+tag fallback as the in_use list filters.
func TestCountCurrentDigests_CountsDigestlessRuntimeMatch(t *testing.T) {
	dbPath := "test_count_digests_fallback_" + t.Name() + ".db"
	_ = os.Remove(dbPath)
	defer os.Remove(dbPath)

	store, err := NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	defer store.Close()

	ctx := context.Background()
	record := &ScanRecord{
		Repository: "docker.io/library/nginx", Tag: "1.28", Digest: "sha256:registry-only-digest",
		PolicyPassed: true, SBOMAttested: true, VulnAttested: true, SCAIAttested: true,
		Vulnerabilities: []types.VulnerabilityRecord{}, AppliedVEXStatements: []types.AppliedVEXStatement{},
	}
	if err := store.RecordScan(ctx, record); err != nil {
		t.Fatalf("RecordScan: %v", err)
	}

	// Cluster reports the same repository+tag under a bare ref and without a digest.
	if err := store.RecordClusterInventory(ctx, "c1", []ClusterImageEntry{{
		Namespace: "default", ImageRef: "nginx", Tag: "1.28", Digest: "",
	}}, time.Now().UTC()); err != nil {
		t.Fatalf("RecordClusterInventory: %v", err)
	}

	total, used, err := store.CountCurrentDigests(ctx)
	if err != nil {
		t.Fatalf("CountCurrentDigests: %v", err)
	}
	if total != 1 {
		t.Fatalf("total=%d, want 1", total)
	}
	if used != 1 {
		t.Fatalf("inUse=%d, want 1 (repository+tag fallback must count)", used)
	}
}
