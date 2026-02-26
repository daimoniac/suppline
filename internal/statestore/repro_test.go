package statestore

import (
	"context"
	"os"
	"testing"
)

func TestPolicyConsistencyReproStatus(t *testing.T) {
	dbPath := "repro_policy_consistency.db"
	os.Remove(dbPath)
	defer os.Remove(dbPath)

	store, err := NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("Failed to create SQLite store: %v", err)
	}
	defer store.Close()

	ctx := context.Background()
	digest := "sha256:2b02736448e5d6e080fc9e3963821c4c1e2461b3a1a0e588e7135e6712ac860c"
	repo := "hostingmaloonde/opensearchproject_opensearch-dashboards"

	// 1. Record a FAILED scan for Tag "3"
	scan1 := &ScanRecord{
		Digest:            digest,
		Repository:        repo,
		Tag:               "3",
		ScanDurationMs:    1000,
		CriticalVulnCount: 3,
		HighVulnCount:     30,
		MediumVulnCount:   20,
		LowVulnCount:      3,
		PolicyPassed:      false, // Fails
		CreatedAt:         1772092875,
	}
	if err := store.RecordScan(ctx, scan1); err != nil {
		t.Fatalf("Failed to record first scan: %v", err)
	}

	// 2. Record a PASSING scan for Tag "3.5.0" (same digest, later time)
	// In reality, this would happen if someone added tolerations and rescanned another tag of same digest.
	scan2 := &ScanRecord{
		Digest:            digest,
		Repository:        repo,
		Tag:               "3.5.0",
		ScanDurationMs:    1000,
		CriticalVulnCount: 3,
		HighVulnCount:     30,
		MediumVulnCount:   20,
		LowVulnCount:      3,
		PolicyPassed:      true, // Passes now!
		CreatedAt:         1772116127,
	}
	if err := store.RecordScan(ctx, scan2); err != nil {
		t.Fatalf("Failed to record second scan: %v", err)
	}

	// 3. Verify GetRepository state
	repoDetail, err := store.GetRepository(ctx, repo, RepositoryTagFilter{})
	if err != nil {
		t.Fatalf("Failed to get repository: %v", err)
	}

	foundTag3 := false
	foundTag350 := false
	for _, tag := range repoDetail.Tags {
		if tag.Name == "3" {
			foundTag3 = true
			if !tag.PolicyPassed {
				t.Errorf("Tag '3' should have PolicyPassed=true (it points to the latest scan), but got false")
			}
		}
		if tag.Name == "3.5.0" {
			foundTag350 = true
			if !tag.PolicyPassed {
				t.Errorf("Tag '3.5.0' should have PolicyPassed=true, but got false")
			}
		}
	}
	if !foundTag3 || !foundTag350 {
		t.Fatalf("Expected to find both tags, foundTag3: %v, foundTag350: %v", foundTag3, foundTag350)
	}

	// 4. Check GetFailedArtifacts - this should be EMPTY because the latest scan for this digest PASSED
	failedArtifacts, err := store.GetFailedArtifacts(ctx)
	if err != nil {
		t.Fatalf("Failed to get failed artifacts: %v", err)
	}
	if len(failedArtifacts) > 0 {
		for _, fa := range failedArtifacts {
			t.Errorf("Unexpected failed artifact: %s:%s (Digest: %s). Its latest scan should be the passing one.", fa.Repository, fa.Tag, fa.Digest)
		}
	}

	// 5. Check ListScans with policy_passed=false
	// This currently returns the OLD scan for tag "3", which is what causes the discrepancy in the UI
	// if the UI uses /scans?policy_passed=false to show "active" failures.
	falsePassed := false
	scans, err := store.ListScans(ctx, ScanFilter{PolicyPassed: &falsePassed})
	if err != nil {
		t.Fatalf("Failed to list scans: %v", err)
	}

	// If the user's report is correct, this will return 1 scan (the old one)
	t.Logf("Number of failed scans found: %d", len(scans))
	for _, s := range scans {
		t.Logf("Failed scan: ID %d, Repository %s, Tag %s, CreatedAt %d", s.ID, s.Repository, s.Tag, s.CreatedAt)
	}
}
