package observability

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/daimoniac/suppline/internal/statestore"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// mockStateStore only embeds StateStoreQuery since it includes StateStore
type mockStateStore struct {
	statestore.StateStoreQuery

	scans     []*statestore.ScanRecord
	counts    map[string]int
	summaries []statestore.ClusterSummary
}

func (m *mockStateStore) ListClusterSummaries(ctx context.Context) ([]statestore.ClusterSummary, error) {
	return m.summaries, nil
}

func (m *mockStateStore) RecordClusterInventory(ctx context.Context, clusterName string, images []statestore.ClusterImageEntry, reportedAt time.Time) error {
	return nil
}

func (m *mockStateStore) ListClusterImages(ctx context.Context, clusterName string) ([]statestore.ClusterImageSummary, error) {
	return nil, nil
}

func (m *mockStateStore) DeleteClusterInventory(ctx context.Context, clusterName string) error {
	return nil
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
		{Digest: "abc", PolicyPassed: true, RuntimeUsed: true, PolicyStatus: "passed"},
		{Digest: "def", PolicyPassed: false, RuntimeUsed: true, PolicyStatus: "failed"},
		{Digest: "ghi", PolicyPassed: false, RuntimeUsed: false, PolicyStatus: "failed"},
		{Digest: "jkl", PolicyPassed: false, RuntimeUsed: false, PolicyStatus: "pending"},
	}

	ts1 := int64(1710000000)
	ts2 := int64(1710001234)

	store := &mockStateStore{
		counts: counts,
		scans:  scans,
		summaries: []statestore.ClusterSummary{
			{Name: "cluster-a", LastReported: &ts1, ImageCount: 3},
			{Name: "cluster-b", LastReported: &ts2, ImageCount: 1},
		},
	}

	// NewDatabaseCollector takes statestore.StateStore
	collector := NewDatabaseCollector(store, logger)

	reg := prometheus.NewRegistry()
	reg.MustRegister(collector)

	count := testutil.CollectAndCount(collector)
	if count != 10 { // 2 policy failed source labels + 2 policy pending source labels + 4 vuln severities + 2 cluster sync
		t.Errorf("Expected 10 metrics, got %d", count)
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

	expectedPolicyPending := `
		# HELP suppline_policy_pending_current Current number of artifacts with pending policy evaluation by source
		# TYPE suppline_policy_pending_current gauge
		suppline_policy_pending_current{source="registry"} 1
		suppline_policy_pending_current{source="runtime"} 0
	`

	if err := testutil.GatherAndCompare(reg, strings.NewReader(expectedPolicyPending), "suppline_policy_pending_current"); err != nil {
		t.Errorf("Unexpected policy pending metrics: %v", err)
	}

	expectedClusterSync := `
		# HELP suppline_cluster_last_sync_timestamp_seconds Unix timestamp of the last successful cluster inventory sync, labelled by cluster name
		# TYPE suppline_cluster_last_sync_timestamp_seconds gauge
		suppline_cluster_last_sync_timestamp_seconds{cluster="cluster-a"} 1.71e+09
		suppline_cluster_last_sync_timestamp_seconds{cluster="cluster-b"} 1.710001234e+09
	`

	if err := testutil.GatherAndCompare(reg, strings.NewReader(expectedClusterSync), "suppline_cluster_last_sync_timestamp_seconds"); err != nil {
		t.Errorf("Unexpected cluster sync metrics: %v", err)
	}
}
