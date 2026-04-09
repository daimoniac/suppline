package statestore

import (
	"context"
	"os"
	"testing"

	"github.com/daimoniac/suppline/internal/types"
)

func TestListRepositories_InUseFilterIncludesWhitelistedInBothModes(t *testing.T) {
	dbPath := "test_repositories_whitelist_filter_" + t.Name() + ".db"
	_ = os.Remove(dbPath)
	defer os.Remove(dbPath)

	store, err := NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("failed to create sqlite store: %v", err)
	}
	defer store.Close()

	ctx := context.Background()

	recordScan := func(repo, digest, tag string) {
		t.Helper()
		rec := &ScanRecord{
			Digest:               digest,
			Repository:           repo,
			Tag:                  tag,
			ScanDurationMs:       100,
			CriticalVulnCount:    0,
			HighVulnCount:        0,
			MediumVulnCount:      0,
			LowVulnCount:         0,
			PolicyPassed:         true,
			SBOMAttested:         false,
			VulnAttested:         false,
			SCAIAttested:         false,
			Vulnerabilities:      []types.VulnerabilityRecord{},
			AppliedVEXStatements: []types.AppliedVEXStatement{},
		}
		if err := store.RecordScan(ctx, rec); err != nil {
			t.Fatalf("failed to record scan for %s: %v", repo, err)
		}
	}

	// Both repositories are not runtime-used; one is explicitly whitelisted.
	whitelistedRepo := "example.com/whitelisted"
	normalRepo := "example.com/normal"
	recordScan(whitelistedRepo, "sha256:111", "1.0.0")
	recordScan(normalRepo, "sha256:222", "1.0.0")

	if err := store.AddRuntimeUnusedRepositoryWhitelist(ctx, whitelistedRepo); err != nil {
		t.Fatalf("failed to add whitelist entry: %v", err)
	}

	trueVal := true
	inUseResp, err := store.ListRepositories(ctx, RepositoryFilter{InUse: &trueVal, Limit: 100})
	if err != nil {
		t.Fatalf("failed to list repositories (in_use=true): %v", err)
	}
	if len(inUseResp.Repositories) != 1 {
		t.Fatalf("expected exactly 1 repository for in_use=true, got %d", len(inUseResp.Repositories))
	}
	if inUseResp.Repositories[0].Name != whitelistedRepo {
		t.Fatalf("expected whitelisted repository for in_use=true, got %s", inUseResp.Repositories[0].Name)
	}
	if !inUseResp.Repositories[0].Whitelisted {
		t.Fatalf("expected Whitelisted=true for %s", whitelistedRepo)
	}

	falseVal := false
	notInUseResp, err := store.ListRepositories(ctx, RepositoryFilter{InUse: &falseVal, Limit: 100})
	if err != nil {
		t.Fatalf("failed to list repositories (in_use=false): %v", err)
	}
	if len(notInUseResp.Repositories) != 2 {
		t.Fatalf("expected 2 repositories for in_use=false, got %d", len(notInUseResp.Repositories))
	}

	seen := map[string]RepositoryInfo{}
	for _, repo := range notInUseResp.Repositories {
		seen[repo.Name] = repo
	}

	if _, ok := seen[whitelistedRepo]; !ok {
		t.Fatalf("expected whitelisted repository in in_use=false list")
	}
	if _, ok := seen[normalRepo]; !ok {
		t.Fatalf("expected normal repository in in_use=false list")
	}
	if !seen[whitelistedRepo].Whitelisted {
		t.Fatalf("expected Whitelisted=true for %s in in_use=false list", whitelistedRepo)
	}
	if seen[normalRepo].Whitelisted {
		t.Fatalf("expected Whitelisted=false for %s", normalRepo)
	}

}
