package observability

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestMetrics(t *testing.T) {
	m := GetMetrics()

	if m.QueueDepth == nil {
		t.Error("QueueDepth metric not initialized")
	}
	if m.ScansTotal == nil {
		t.Error("ScansTotal metric not initialized")
	}
	if m.PolicyPassed == nil {
		t.Error("PolicyPassed metric not initialized")
	}

	m.ScansTotal.Inc()
	if testutil.ToFloat64(m.ScansTotal) != 1 {
		t.Errorf("expected ScansTotal to be 1, got %f", testutil.ToFloat64(m.ScansTotal))
	}

	m.PolicyPassed.Inc()
	if testutil.ToFloat64(m.PolicyPassed) != 1 {
		t.Errorf("expected PolicyPassed to be 1, got %f", testutil.ToFloat64(m.PolicyPassed))
	}

	m.QueueDepth.Set(5)
	if testutil.ToFloat64(m.QueueDepth) != 5 {
		t.Errorf("expected QueueDepth to be 5, got %f", testutil.ToFloat64(m.QueueDepth))
	}
}

func TestMetricsSingleton(t *testing.T) {
	m1 := GetMetrics()
	m2 := GetMetrics()

	if m1 != m2 {
		t.Error("GetMetrics should return the same instance")
	}
}

func TestHistogram(t *testing.T) {
	m := GetMetrics()

	m.ScanDuration.Observe(1.5)
	m.ScanDuration.Observe(3.2)
	m.ScanDuration.Observe(10.7)

	if m.ScanDuration == nil {
		t.Error("ScanDuration histogram not initialized")
	}
}
