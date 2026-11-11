package vexaudit

import (
	"context"
	"database/sql"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/daimoniac/suppline/internal/policy"
	"github.com/daimoniac/suppline/internal/policy/catalog"
	"github.com/daimoniac/suppline/internal/statestore"
	"github.com/daimoniac/suppline/internal/types"
)

const testRepository = "registry.local/app"

type fakeCatalog struct {
	statements []types.VEXStatement
	policy     policy.PolicyConfig
}

func (f fakeCatalog) Repositories() []string { return []string{testRepository} }

func (f fakeCatalog) ResolvePolicy(string) (policy.PolicyConfig, error) { return f.policy, nil }

func (f fakeCatalog) ResolveEvidence(string) catalog.Evidence {
	return catalog.Evidence{VEXStatements: append([]types.VEXStatement(nil), f.statements...)}
}

func (f fakeCatalog) SyncVEX(string) []types.VEXStatement { return f.statements }

type fakeScans struct {
	records []*statestore.ScanRecord
	vulns   map[int64][]types.VulnerabilityRecord
}

func (f fakeScans) ListScans(context.Context, statestore.ScanFilter) ([]*statestore.ScanRecord, error) {
	return f.records, nil
}

func (f fakeScans) LoadVulnerabilitiesByScanIDs(context.Context, []int64) (map[int64][]types.VulnerabilityRecord, error) {
	return f.vulns, nil
}

func engineFor(cfg policy.PolicyConfig) (policy.PolicyEngine, error) {
	return policy.NewEngine(slog.New(slog.NewTextHandler(io.Discard, nil)), cfg)
}

func expiredAt(t time.Time) *int64 {
	unix := t.Add(-time.Hour).Unix()
	return &unix
}

// A LOW not_affected statement changes nothing under criticalCount == 0. A
// CRITICAL one decides the outcome, so removing it would fail the image.
func TestAuditFindsOnlyStatementsWithoutPolicyEffect(t *testing.T) {
	statements := []types.VEXStatement{
		{ID: "CVE-LOW", State: types.VEXStateNotAffected, Source: types.VEXSourceManual},
		{ID: "CVE-CRIT", State: types.VEXStateNotAffected, Source: types.VEXSourceManual},
		{ID: "CVE-AFFECTED", State: types.VEXStateAffected, Source: types.VEXSourceManual},
		{ID: "CVE-EXPIRED", State: types.VEXStateNotAffected, Source: types.VEXSourceAuto, ExpiresAt: expiredAt(time.Now())},
	}
	vulns := []types.VulnerabilityRecord{
		{CVEID: "CVE-LOW", Severity: "LOW", PackageName: "libc", InstalledVersion: "1", FixedVersion: "2"},
		{CVEID: "CVE-CRIT", Severity: "CRITICAL", PackageName: "openssl", InstalledVersion: "1", FixedVersion: "2"},
		{CVEID: "CVE-AFFECTED", Severity: "HIGH", PackageName: "zlib", InstalledVersion: "1"},
		{CVEID: "CVE-EXPIRED", Severity: "LOW", PackageName: "tar", InstalledVersion: "1"},
	}
	auditor := New(slog.New(slog.NewTextHandler(io.Discard, nil)),
		fakeCatalog{statements: statements, policy: policy.PolicyConfig{Expression: "criticalCount == 0"}},
		fakeScans{
			records: []*statestore.ScanRecord{{ID: 7, Repository: testRepository, Digest: "sha256:one", Tag: "v1", CreatedAt: time.Now().Unix(), PolicyStatus: "passed"}},
			vulns:   map[int64][]types.VulnerabilityRecord{7: vulns},
		},
		engineFor,
	)

	findings, err := auditor.Audit(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 {
		t.Fatalf("findings = %+v, want only CVE-LOW", findings)
	}
	got := findings[0]
	if got.CVEID != "CVE-LOW" || got.Repository != testRepository || got.Source != types.VEXSourceManual {
		t.Fatalf("finding = %+v", got)
	}
}

func TestAuditKeepsStatementThatDecidesHighCount(t *testing.T) {
	statements := []types.VEXStatement{
		{ID: "CVE-HIGH", State: types.VEXStateNotAffected, Source: types.VEXSourceManual},
		{ID: "CVE-LOW", State: types.VEXStateNotAffected, Source: types.VEXSourceAuto},
	}
	auditor := New(slog.New(slog.NewTextHandler(io.Discard, nil)),
		fakeCatalog{statements: statements, policy: policy.PolicyConfig{Expression: "highCount == 0"}},
		fakeScans{
			records: []*statestore.ScanRecord{{
				ID: 3, Repository: testRepository, Digest: "sha256:two", CreatedAt: time.Now().Unix(), PolicyStatus: "passed",
			}},
			vulns: map[int64][]types.VulnerabilityRecord{3: {
				{CVEID: "CVE-HIGH", Severity: "HIGH", PackageName: "openssl", InstalledVersion: "1", FixedVersion: "2"},
				{CVEID: "CVE-LOW", Severity: "LOW", PackageName: "libc", InstalledVersion: "1"},
			}},
		},
		engineFor,
	)
	findings, err := auditor.Audit(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || findings[0].CVEID != "CVE-LOW" || findings[0].Source != types.VEXSourceAuto {
		t.Fatalf("findings = %+v, want only CVE-LOW", findings)
	}
}

func TestAuditSkipsReleaseAgeGatedRepositories(t *testing.T) {
	statements := []types.VEXStatement{{ID: "CVE-LOW", State: types.VEXStateNotAffected, Source: types.VEXSourceManual}}
	auditor := New(slog.New(slog.NewTextHandler(io.Discard, nil)),
		fakeCatalog{statements: statements, policy: policy.PolicyConfig{Expression: "criticalCount == 0", MinimumReleaseAge: time.Hour}},
		fakeScans{
			records: []*statestore.ScanRecord{{ID: 7, Repository: testRepository, Digest: "sha256:one", CreatedAt: time.Now().Unix(), PolicyStatus: "passed"}},
			vulns:   map[int64][]types.VulnerabilityRecord{7: {{CVEID: "CVE-LOW", Severity: "LOW"}}},
		},
		engineFor,
	)
	findings, err := auditor.Audit(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Fatalf("release-age gated repository produced findings: %+v", findings)
	}
}

// The gate used in production ignores a critical finding until it has a fix.
// Reloading that finding must keep the severity recorded on the scan. A later
// scan of another image rewrites the shared CVE catalog, and trusting that
// rewrite makes a load-bearing not_affected statement look unused.
func TestAuditKeepsFixableCriticalAfterCatalogSeverityRewrite(t *testing.T) {
	store, err := statestore.NewSQLiteStore(t.TempDir() + "/vex-audit.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })

	ctx := context.Background()
	if err := store.RecordScan(ctx, &statestore.ScanRecord{
		Repository:   testRepository,
		Digest:       "sha256:app",
		Tag:          "v1",
		PolicyPassed: true,
		PolicyStatus: "passed",
		Vulnerabilities: []types.VulnerabilityRecord{
			{CVEID: "CVE-CRIT", Severity: "CRITICAL", PackageName: "stdlib", InstalledVersion: "1", FixedVersion: "2"},
			{CVEID: "CVE-LOW", Severity: "LOW", PackageName: "libc", InstalledVersion: "1"},
		},
	}); err != nil {
		t.Fatal(err)
	}
	// A later image rates the same CVE as HIGH and rewrites the shared catalog row.
	if err := store.RecordScan(ctx, &statestore.ScanRecord{
		Repository:   "registry.local/other",
		Digest:       "sha256:other",
		Tag:          "v1",
		PolicyPassed: true,
		PolicyStatus: "passed",
		Vulnerabilities: []types.VulnerabilityRecord{{
			CVEID: "CVE-CRIT", Severity: "HIGH", PackageName: "stdlib", InstalledVersion: "1", FixedVersion: "2",
		}},
	}); err != nil {
		t.Fatal(err)
	}

	statements := []types.VEXStatement{
		{ID: "CVE-CRIT", State: types.VEXStateNotAffected, Source: types.VEXSourceManual},
		{ID: "CVE-LOW", State: types.VEXStateNotAffected, Source: types.VEXSourceManual},
	}
	auditor := New(slog.New(slog.NewTextHandler(io.Discard, nil)),
		fakeCatalog{statements: statements, policy: policy.PolicyConfig{Expression: `vulnerabilities.filter(v, v.severity == "CRITICAL" && v.fixedVersion != "" && !v.exempted).size() == 0`}},
		store,
		engineFor,
	)
	findings, err := auditor.Audit(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || findings[0].CVEID != "CVE-LOW" {
		t.Fatalf("findings = %+v, want only CVE-LOW; removing CVE-CRIT fails the fixable-critical gate", findings)
	}
}

// Findings stored before per-scan severity have only the shared catalog value.
// That value may already have been rewritten, so those statements stay put.
func TestAuditKeepsStatementWhenFindingSeverityWasNotRecorded(t *testing.T) {
	path := t.TempDir() + "/vex-audit-legacy.db"
	store, err := statestore.NewSQLiteStore(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })

	ctx := context.Background()
	if err := store.RecordScan(ctx, &statestore.ScanRecord{
		Repository:   testRepository,
		Digest:       "sha256:app",
		Tag:          "v1",
		PolicyPassed: true,
		PolicyStatus: "passed",
		Vulnerabilities: []types.VulnerabilityRecord{{
			CVEID: "CVE-CRIT", Severity: "CRITICAL", PackageName: "stdlib", InstalledVersion: "1", FixedVersion: "2",
		}},
	}); err != nil {
		t.Fatal(err)
	}
	legacy, err := sql.Open("sqlite3", path+"?_foreign_keys=1&_busy_timeout=3000")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = legacy.Close() })
	if _, err := legacy.ExecContext(ctx, `UPDATE scan_findings SET severity = NULL`); err != nil {
		t.Fatal(err)
	}
	if _, err := legacy.ExecContext(ctx, `UPDATE cve_catalog SET severity = 'HIGH' WHERE cve_id = 'CVE-CRIT'`); err != nil {
		t.Fatal(err)
	}

	auditor := New(slog.New(slog.NewTextHandler(io.Discard, nil)),
		fakeCatalog{
			statements: []types.VEXStatement{{ID: "CVE-CRIT", State: types.VEXStateNotAffected, Source: types.VEXSourceManual}},
			policy:     policy.PolicyConfig{Expression: `vulnerabilities.filter(v, v.severity == "CRITICAL" && v.fixedVersion != "" && !v.exempted).size() == 0`},
		},
		store,
		engineFor,
	)
	findings, err := auditor.Audit(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Fatalf("findings = %+v, want none while the scan's own severity is missing", findings)
	}
}

func TestForgetDropsRemovedStatement(t *testing.T) {
	auditor := New(slog.New(slog.NewTextHandler(io.Discard, nil)), fakeCatalog{}, fakeScans{}, engineFor)
	auditor.findings = []Finding{
		{Repository: testRepository, CVEID: "CVE-1", Source: types.VEXSourceManual},
		{Repository: testRepository, CVEID: "CVE-2", Source: types.VEXSourceAuto},
	}
	auditor.Forget(testRepository, "CVE-1", types.VEXSourceManual)

	findings, computedAt := auditor.Snapshot()
	if len(findings) != 1 || findings[0].CVEID != "CVE-2" {
		t.Fatalf("findings = %+v", findings)
	}
	if !computedAt.IsZero() {
		t.Fatalf("computedAt = %v, want zero before any refresh", computedAt)
	}
}
