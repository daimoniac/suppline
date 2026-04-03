package observability

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/daimoniac/suppline/internal/statestore"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// mockStateStore only embeds StateStoreQuery since it includes StateStore
type mockStateStore struct {
	statestore.StateStoreQuery

	scans  []*statestore.ScanRecord
	counts map[string]int
}

func (m *mockStateStore) GetRuntimeUsageForScans(ctx context.Context, scans []statestore.RuntimeLookupInput) (map[string]statestore.RuntimeUsage, error) {
	usage := make(map[string]statestore.RuntimeUsage)
	runtimeByDigest := make(map[string]bool, len(m.scans))
	for _, s := range m.scans {
		runtimeByDigest[s.Digest] = s.RuntimeUsed
	}

	for _, scan := range scans {
		if runtimeByDigest[scan.Digest] {
			usage[scan.Digest] = statestore.RuntimeUsage{RuntimeUsed: true}
		}
	}

	return usage, nil
}

func (m *mockStateStore) GetFailedArtifacts(ctx context.Context) ([]*statestore.ScanRecord, error) {
	var failed []*statestore.ScanRecord
	for _, s := range m.scans {
		if !s.PolicyPassed {
			failed = append(failed, s)
		}
	}
	return failed, nil
}

func (m *mockStateStore) GetUniqueVulnerabilityCounts(ctx context.Context) (map[string]int, error) {
	return m.counts, nil
}

func TestDatabaseCollector(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	counts := map[string]int{
		"CRITICAL": 5,
		"HIGH":     10,
		"MEDIUM":   15,
		"LOW":      20,
	}

	scans := []*statestore.ScanRecord{
		{Digest: "abc", PolicyPassed: true, RuntimeUsed: true},
		{Digest: "def", PolicyPassed: false, RuntimeUsed: true},
		{Digest: "ghi", PolicyPassed: false, RuntimeUsed: false},
	}

	store := &mockStateStore{
		counts: counts,
		scans:  scans,
	}

	// NewDatabaseCollector takes statestore.StateStore
	collector := NewDatabaseCollector(store, logger)

	reg := prometheus.NewRegistry()
	reg.MustRegister(collector)

	// Use CollectAndCount
	count := testutil.CollectAndCount(collector)
	if count != 6 { // 2 policy failed source labels + 4 vuln severities
		t.Errorf("Expected 6 metrics, got %d", count)
	}

	// Verify specific values
	expectedVulnerabilities := `
		# HELP suppline_vulnerabilities_found Current number of vulnerabilities found by severity across all scanned artifacts
		# TYPE suppline_vulnerabilities_found gauge
		suppline_vulnerabilities_found{severity="CRITICAL"} 5
		suppline_vulnerabilities_found{severity="HIGH"} 10
		suppline_vulnerabilities_found{severity="LOW"} 20
		suppline_vulnerabilities_found{severity="MEDIUM"} 15
	`

	if err := testutil.GatherAndCompare(reg, strings.NewReader(expectedVulnerabilities), "suppline_vulnerabilities_found"); err != nil {
		t.Errorf("Unexpected vulnerability metrics: %v", err)
	}

	expectedPolicyFailed := `
		# HELP suppline_policy_failed_current Current number of artifacts that failed policy evaluation by source
		# TYPE suppline_policy_failed_current gauge
		suppline_policy_failed_current{source="registry"} 2
		suppline_policy_failed_current{source="runtime"} 1
	`

	if err := testutil.GatherAndCompare(reg, strings.NewReader(expectedPolicyFailed), "suppline_policy_failed_current"); err != nil {
		t.Errorf("Unexpected policy failed metrics: %v", err)
	}
}
