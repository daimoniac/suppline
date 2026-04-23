package statestore

import (
	"context"
	"database/sql"
	"os"
	"testing"
	"time"
)

func TestListRepositories_RepositorySummaryMatchesAggregates(t *testing.T) {
	ctx := context.Background()
	dbPath := "test_repo_summary_list_" + t.Name() + ".db"
	defer os.Remove(dbPath)

	store, err := NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	defer store.Close()

	repoName := "registry.example/ns/app"
	now := time.Now().Unix()
	if err := store.RecordScan(ctx, &ScanRecord{
		Repository:        repoName,
		Digest:            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Tag:               "1.0.0",
		CriticalVulnCount: 2,
		HighVulnCount:     1,
		MediumVulnCount:   0,
		LowVulnCount:      0,
		PolicyPassed:      true,
		PolicyStatus:      "passed",
		CreatedAt:         now,
	}); err != nil {
		t.Fatalf("RecordScan: %v", err)
	}

	var ac int
	var lst sql.NullInt64
	var mc, mh, mm, ml int
	var pp int
	var ps string
	err = store.db.QueryRowContext(ctx, `
		SELECT artifact_count, last_scan_time, max_critical, max_high, max_medium, max_low,
		       policy_passed, policy_status
		FROM repository_summary rs
		JOIN repositories r ON r.id = rs.repository_id
		WHERE r.name = ?
	`, repoName).Scan(&ac, &lst, &mc, &mh, &mm, &ml, &pp, &ps)
	if err != nil {
		t.Fatalf("query summary: %v", err)
	}
	if ac != 1 || !lst.Valid || lst.Int64 != now {
		t.Fatalf("unexpected summary row: count=%d last=%v", ac, lst)
	}
	if mc != 2 || mh != 1 || mm != 0 || ml != 0 {
		t.Fatalf("unexpected vuln max in summary: %d %d %d %d", mc, mh, mm, ml)
	}
	if pp != 1 || ps != "passed" {
		t.Fatalf("unexpected policy in summary: %d %q", pp, ps)
	}

	resp, err := store.ListRepositories(ctx, RepositoryFilter{Limit: 10, Offset: 0})
	if err != nil {
		t.Fatalf("ListRepositories: %v", err)
	}
	if resp.Total != 1 || len(resp.Repositories) != 1 {
		t.Fatalf("list total=%d repos=%d", resp.Total, len(resp.Repositories))
	}
	r := resp.Repositories[0]
	if r.Name != repoName || r.ArtifactCount != 1 || r.PolicyStatus != "passed" {
		t.Fatalf("unexpected list row: %+v", r)
	}
	if r.VulnerabilityCount.Critical != 2 || r.VulnerabilityCount.High != 1 {
		t.Fatalf("unexpected list vulns: %+v", r.VulnerabilityCount)
	}
}
