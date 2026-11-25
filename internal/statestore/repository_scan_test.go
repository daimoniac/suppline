package statestore

import (
	"context"
	"errors"
	"testing"

	"github.com/daimoniac/suppline/internal/types"
)

func TestGetLastRepositoryScan_IgnoresOtherRepository(t *testing.T) {
	raw, cleanup := createTestStore(t)
	defer cleanup()
	store, ok := raw.(*Store)
	if !ok {
		t.Fatal("expected *Store")
	}

	ctx := context.Background()
	digest := "sha256:shared"
	dockerRepo := "hostingmaloonde/rabbitmqoperator_cluster-operator"
	ghcrRepo := "hostingmaloonde/rabbitmq_cluster-operator"

	for _, repo := range []string{dockerRepo, ghcrRepo} {
		if err := store.RecordScan(ctx, &ScanRecord{
			Repository:   repo,
			Digest:       digest,
			Tag:          "2.19.2",
			PolicyPassed: true,
			PolicyStatus: "passed",
		}); err != nil {
			t.Fatalf("RecordScan %s: %v", repo, err)
		}
	}

	got, err := store.GetLastRepositoryScan(ctx, ghcrRepo, digest)
	if err != nil {
		t.Fatalf("GetLastRepositoryScan: %v", err)
	}
	if got.Repository != ghcrRepo {
		t.Fatalf("repository = %s, want %s", got.Repository, ghcrRepo)
	}

	_, err = store.GetLastRepositoryScan(ctx, "hostingmaloonde/missing", digest)
	if !errors.Is(err, ErrScanNotFound) {
		t.Fatalf("missing repository err = %v, want ErrScanNotFound", err)
	}
}

func TestGetLastRepositoryScanSummary_SkipsFindings(t *testing.T) {
	raw, cleanup := createTestStore(t)
	defer cleanup()
	store, ok := raw.(*Store)
	if !ok {
		t.Fatal("expected *Store")
	}

	ctx := context.Background()
	repo := "hostingmaloonde/supabase_postgres"
	digest := "sha256:summary"
	if err := store.RecordScan(ctx, &ScanRecord{
		Repository:        repo,
		Digest:            digest,
		Tag:               "15.8",
		CriticalVulnCount: 1,
		PolicyPassed:      false,
		PolicyStatus:      "failed",
		Vulnerabilities: []types.VulnerabilityRecord{{
			CVEID:       "CVE-2025-0001",
			Severity:    "CRITICAL",
			PackageName: "linux",
			Description: "long description",
		}},
	}); err != nil {
		t.Fatalf("RecordScan: %v", err)
	}

	full, err := store.GetLastRepositoryScan(ctx, repo, digest)
	if err != nil {
		t.Fatalf("GetLastRepositoryScan: %v", err)
	}
	if len(full.Vulnerabilities) != 1 {
		t.Fatalf("full scan findings = %d, want 1", len(full.Vulnerabilities))
	}

	got, err := store.GetLastRepositoryScanSummary(ctx, repo, digest)
	if err != nil {
		t.Fatalf("GetLastRepositoryScanSummary: %v", err)
	}
	if got.Vulnerabilities != nil {
		t.Fatalf("summary findings = %d, want none loaded", len(got.Vulnerabilities))
	}
	if got.ID != full.ID || got.CreatedAt != full.CreatedAt || got.CriticalVulnCount != 1 || got.PolicyStatus != "failed" {
		t.Fatalf("summary = %+v, want same scan as %+v without findings", got, full)
	}

	crossRepo, err := store.GetLastScanSummary(ctx, digest)
	if err != nil {
		t.Fatalf("GetLastScanSummary: %v", err)
	}
	if crossRepo.Vulnerabilities != nil || crossRepo.ID != full.ID {
		t.Fatalf("GetLastScanSummary = %+v, want scan %d without findings", crossRepo, full.ID)
	}

	_, err = store.GetLastRepositoryScanSummary(ctx, repo, "sha256:missing")
	if !errors.Is(err, ErrScanNotFound) {
		t.Fatalf("missing digest err = %v, want ErrScanNotFound", err)
	}
}
