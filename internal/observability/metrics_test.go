package observability

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestMetrics(t *testing.T) {
	// Get metrics instance
	m := GetMetrics()

	// Test that metrics are initialized
	if m.QueueDepth == nil {
		t.Error("QueueDepth metric not initialized")
	}
	if m.ScansTotal == nil {
		t.Error("ScansTotal metric not initialized")
	}
	if m.PolicyPassed == nil {
		t.Error("PolicyPassed metric not initialized")
	}

	// Test incrementing counters
	m.ScansTotal.Inc()
	if testutil.ToFloat64(m.ScansTotal) != 1 {
		t.Errorf("expected ScansTotal to be 1, got %f", testutil.ToFloat64(m.ScansTotal))
	}

	m.PolicyPassed.Inc()
	if testutil.ToFloat64(m.PolicyPassed) != 1 {
		t.Errorf("expected PolicyPassed to be 1, got %f", testutil.ToFloat64(m.PolicyPassed))
	}

	// Test gauge
	m.QueueDepth.Set(5)
	if testutil.ToFloat64(m.QueueDepth) != 5 {
		t.Errorf("expected QueueDepth to be 5, got %f", testutil.ToFloat64(m.QueueDepth))
	}

	// Test counter vec
	m.VulnerabilitiesFound.WithLabelValues("CRITICAL").Inc()
	m.VulnerabilitiesFound.WithLabelValues("HIGH").Add(3)

	criticalCount := testutil.ToFloat64(m.VulnerabilitiesFound.WithLabelValues("CRITICAL"))
	if criticalCount != 1 {
		t.Errorf("expected CRITICAL vulnerabilities to be 1, got %f", criticalCount)
	}

	highCount := testutil.ToFloat64(m.VulnerabilitiesFound.WithLabelValues("HIGH"))
	if highCount != 3 {
		t.Errorf("expected HIGH vulnerabilities to be 3, got %f", highCount)
	}
}

func TestMetricsSingleton(t *testing.T) {
	// Verify that GetMetrics returns the same instance
	m1 := GetMetrics()
	m2 := GetMetrics()

	if m1 != m2 {
		t.Error("GetMetrics should return the same instance")
	}
}

func TestHistogram(t *testing.T) {
	m := GetMetrics()

	// Observe some durations
	m.ScanDuration.Observe(1.5)
	m.ScanDuration.Observe(3.2)
	m.ScanDuration.Observe(10.7)

	// Verify histogram exists and can be observed
	// Note: We can't easily verify count with testutil for histograms
	// Just verify it doesn't panic
	if m.ScanDuration == nil {
		t.Error("ScanDuration histogram not initialized")
	}
}
