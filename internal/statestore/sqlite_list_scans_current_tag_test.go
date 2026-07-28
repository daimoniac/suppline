package statestore

import (
	"context"
	"testing"
)

func TestListScans_OnlyLatestArtifactPerRepositoryTag(t *testing.T) {
	store, cleanup := createTestStore(t)
	defer cleanup()

	sqliteStore := store.(*SQLiteStore)
	ctx := context.Background()
	repo := "hostingmaloonde/dhi_grafana"
	oldDigest := "sha256:olddigestolddigestolddigestolddigestolddigestolddigestolddigestold"
	newDigest := "sha256:newdigestnewdigestnewdigestnewdigestnewdigestnewdigestnewdigestnew"

	if err := store.RecordScan(ctx, &ScanRecord{
		Repository:        repo,
		Digest:            oldDigest,
		Tag:               "13.1",
		CriticalVulnCount: 1,
		PolicyPassed:      false,
		PolicyStatus:      "failed",
	}); err != nil {
		t.Fatalf("RecordScan(old): %v", err)
	}

	// Simulate a historical superseded binding that RecordScan would normally prune:
	// insert a newer artifact for the same tag on a different digest with a passing scan.
	var repoID, oldArtifactID int64
	if err := sqliteStore.db.QueryRowContext(ctx, `
		SELECT r.id, a.id
		FROM repositories r
		JOIN artifacts a ON a.repository_id = r.id
		WHERE r.name = ? AND a.digest = ? AND a.tag = ?
	`, repo, oldDigest, "13.1").Scan(&repoID, &oldArtifactID); err != nil {
		t.Fatalf("lookup old artifact: %v", err)
	}

	res, err := sqliteStore.db.ExecContext(ctx, `
		INSERT INTO artifacts (repository_id, digest, tag, first_seen, last_seen)
		VALUES (?, ?, '13.1', strftime('%s','now'), strftime('%s','now'))
	`, repoID, newDigest)
	if err != nil {
		t.Fatalf("insert new artifact: %v", err)
	}
	newArtifactID, err := res.LastInsertId()
	if err != nil {
		t.Fatalf("new artifact id: %v", err)
	}
	if newArtifactID <= oldArtifactID {
		t.Fatalf("expected newer artifact id > %d, got %d", oldArtifactID, newArtifactID)
	}

	scanRes, err := sqliteStore.db.ExecContext(ctx, `
		INSERT INTO scan_records (
			artifact_id, scan_duration_ms,
			critical_vuln_count, high_vuln_count, medium_vuln_count, low_vuln_count,
			policy_passed, policy_status, policy_reason, error_message,
			sbom_attested, vuln_attested, scai_attested
		) VALUES (?, 10, 0, 0, 0, 0, 1, 'passed', 'ok', '', 1, 1, 0)
	`, newArtifactID)
	if err != nil {
		t.Fatalf("insert passing scan: %v", err)
	}
	newScanID, err := scanRes.LastInsertId()
	if err != nil {
		t.Fatalf("new scan id: %v", err)
	}
	if _, err := sqliteStore.db.ExecContext(ctx, `
		UPDATE artifacts SET last_scan_id = ? WHERE id = ?
	`, newScanID, newArtifactID); err != nil {
		t.Fatalf("point new artifact at scan: %v", err)
	}

	policyFailed := false
	failed, err := sqliteStore.ListScans(ctx, ScanFilter{PolicyPassed: &policyFailed, Limit: 100})
	if err != nil {
		t.Fatalf("ListScans(failed): %v", err)
	}
	for _, scan := range failed {
		if scan.Repository == repo && scan.Tag == "13.1" {
			t.Fatalf("ListScans must hide superseded failed binding, got %+v", scan)
		}
	}

	policyPassed := true
	passed, err := sqliteStore.ListScans(ctx, ScanFilter{PolicyPassed: &policyPassed, Limit: 100})
	if err != nil {
		t.Fatalf("ListScans(passed): %v", err)
	}
	found := false
	for _, scan := range passed {
		if scan.Repository == repo && scan.Tag == "13.1" {
			found = true
			if scan.Digest != newDigest || !scan.PolicyPassed {
				t.Fatalf("expected current 13.1 passing on new digest, got %+v", scan)
			}
		}
	}
	if !found {
		t.Fatal("expected current passing 13.1 in ListScans")
	}

	failedCount, err := sqliteStore.CountScans(ctx, ScanFilter{PolicyPassed: &policyFailed})
	if err != nil {
		t.Fatalf("CountScans(failed): %v", err)
	}
	if failedCount != 0 {
		t.Fatalf("CountScans(failed)=%d, want 0", failedCount)
	}
}
