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
		{Digest: "abc", PolicyPassed: true},
		{Digest: "def", PolicyPassed: false},
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
	if count != 5 { // 1 policy failed + 4 vuln severities
		t.Errorf("Expected 5 metrics, got %d", count)
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
		# HELP suppline_policy_failed_total Current number of artifacts that failed policy evaluation
		# TYPE suppline_policy_failed_total gauge
		suppline_policy_failed_total 1
	`

	if err := testutil.GatherAndCompare(reg, strings.NewReader(expectedPolicyFailed), "suppline_policy_failed_total"); err != nil {
		t.Errorf("Unexpected policy failed metrics: %v", err)
	}
}
