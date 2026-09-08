package statestore

import (
	"context"
	"database/sql"
	"strings"
	"testing"

	"github.com/daimoniac/suppline/internal/types"
)

func TestNewSQLiteStoreRejectsLegacyVulnerabilitySchema(t *testing.T) {
	path := t.TempDir() + "/legacy.db"
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatalf("open legacy database: %v", err)
	}
	if _, err := db.Exec(`CREATE TABLE vulnerabilities (id INTEGER PRIMARY KEY)`); err != nil {
		t.Fatalf("create legacy table: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close legacy database: %v", err)
	}

	store, err := NewSQLiteStore(path)
	if store != nil {
		_ = store.Close()
		t.Fatal("expected legacy schema to be rejected")
	}
	if err == nil || !strings.Contains(err.Error(), "legacy vulnerabilities table detected") {
		t.Fatalf("unexpected legacy schema error: %v", err)
	}
}

func TestRecordScanDeduplicatesCVEMetadataAndPreservesFirstSeen(t *testing.T) {
	store, err := NewSQLiteStore(t.TempDir() + "/normalized.db")
	if err != nil {
		t.Fatalf("create store: %v", err)
	}
	defer store.Close()

	ctx := context.Background()
	record := &ScanRecord{
		Repository:   "example/app",
		Digest:       "sha256:normalized",
		Tag:          "1.0.0",
		PolicyPassed: true,
		SBOMAttested: true,
		VulnAttested: true,
		SCAIAttested: true,
		Vulnerabilities: []types.VulnerabilityRecord{{
			CVEID:            "CVE-2026-0001",
			Severity:         "HIGH",
			PackageName:      "openssl",
			InstalledVersion: "3.0.0",
			FixedVersion:     "3.0.1",
			Title:            "Original title",
			Description:      "Long metadata stored once",
			PrimaryURL:       "https://example.test/CVE-2026-0001",
		}},
	}
	if err := store.RecordScan(ctx, record); err != nil {
		t.Fatalf("record first scan: %v", err)
	}

	var firstSeen int64
	if err := store.db.QueryRowContext(ctx, `
		SELECT first_seen_at FROM cve_first_seen
		WHERE cve_id = ?
	`, "CVE-2026-0001").Scan(&firstSeen); err != nil {
		t.Fatalf("read first-seen time: %v", err)
	}

	record.Vulnerabilities[0].Severity = "CRITICAL"
	record.Vulnerabilities[0].Title = "Updated title"
	record.Vulnerabilities[0].Description = ""
	if err := store.RecordScan(ctx, record); err != nil {
		t.Fatalf("record second scan: %v", err)
	}

	var catalogCount, findingCount, firstSeenCount int
	if err := store.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM cve_catalog`).Scan(&catalogCount); err != nil {
		t.Fatalf("count catalog rows: %v", err)
	}
	if err := store.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM scan_findings`).Scan(&findingCount); err != nil {
		t.Fatalf("count finding rows: %v", err)
	}
	if err := store.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM cve_first_seen`).Scan(&firstSeenCount); err != nil {
		t.Fatalf("count first-seen rows: %v", err)
	}
	if catalogCount != 1 || findingCount != 2 || firstSeenCount != 1 {
		t.Fatalf("unexpected normalized row counts: catalog=%d findings=%d first_seen=%d",
			catalogCount, findingCount, firstSeenCount)
	}

	var severity, title, description string
	if err := store.db.QueryRowContext(ctx, `
		SELECT severity, title, description FROM cve_catalog WHERE cve_id = ?
	`, "CVE-2026-0001").Scan(&severity, &title, &description); err != nil {
		t.Fatalf("read catalog metadata: %v", err)
	}
	if severity != "CRITICAL" || title != "Updated title" || description != "Long metadata stored once" {
		t.Fatalf("unexpected catalog metadata: severity=%q title=%q description=%q",
			severity, title, description)
	}

	var preservedFirstSeen int64
	if err := store.db.QueryRowContext(ctx, `
		SELECT first_seen_at FROM cve_first_seen WHERE cve_id = ?
	`, "CVE-2026-0001").Scan(&preservedFirstSeen); err != nil {
		t.Fatalf("read preserved first-seen time: %v", err)
	}
	if preservedFirstSeen != firstSeen {
		t.Fatalf("first-seen changed from %d to %d", firstSeen, preservedFirstSeen)
	}
}

func TestGetUniqueVulnerabilityCountsUsesLatestScansOnly(t *testing.T) {
	store, err := NewSQLiteStore(t.TempDir() + "/unique-counts.db")
	if err != nil {
		t.Fatalf("create store: %v", err)
	}
	defer store.Close()

	ctx := context.Background()
	scan := func(repo, digest, tag string, vulns []types.VulnerabilityRecord) {
		t.Helper()
		if err := store.RecordScan(ctx, &ScanRecord{
			Repository:      repo,
			Digest:          digest,
			Tag:             tag,
			PolicyPassed:    true,
			Vulnerabilities: vulns,
		}); err != nil {
			t.Fatalf("RecordScan %s: %v", repo, err)
		}
	}

	shared := types.VulnerabilityRecord{CVEID: "CVE-2026-1001", Severity: "HIGH", PackageName: "openssl"}
	onlyA := types.VulnerabilityRecord{CVEID: "CVE-2026-1002", Severity: "LOW", PackageName: "musl"}
	onlyB := types.VulnerabilityRecord{CVEID: "CVE-2026-1003", Severity: "CRITICAL", PackageName: "glibc"}
	stale := types.VulnerabilityRecord{CVEID: "CVE-2026-1999", Severity: "MEDIUM", PackageName: "stale"}

	scan("example/a", "sha256:aaaa", "1.0", []types.VulnerabilityRecord{shared, onlyA, stale})
	scan("example/a", "sha256:aaaa", "1.0", []types.VulnerabilityRecord{shared, onlyA})
	scan("example/b", "sha256:bbbb", "1.0", []types.VulnerabilityRecord{shared, onlyB})

	got, err := store.GetUniqueVulnerabilityCounts(ctx)
	if err != nil {
		t.Fatalf("GetUniqueVulnerabilityCounts: %v", err)
	}
	want := map[string]int{"CRITICAL": 1, "HIGH": 1, "MEDIUM": 0, "LOW": 1}
	if got["CRITICAL"] != want["CRITICAL"] || got["HIGH"] != want["HIGH"] || got["MEDIUM"] != want["MEDIUM"] || got["LOW"] != want["LOW"] {
		t.Fatalf("unique counts = %#v, want %#v", got, want)
	}
}
