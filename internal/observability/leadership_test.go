package observability

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestStandbyComponentsCountAsHealthy(t *testing.T) {
	h := NewHealthChecker(slog.New(slog.NewTextHandler(io.Discard, nil)))
	h.RegisterComponent("database")
	h.RegisterComponent("worker")
	h.UpdateComponentHealth("database", StatusHealthy, "")
	h.UpdateComponentHealth("worker", StatusStandby, "waiting for leadership")
	h.SetRole(RoleStandby)

	health := h.GetHealth()
	if health.Status != StatusHealthy {
		t.Fatalf("overall status = %s, want healthy while a component stands by", health.Status)
	}
	if health.Role != RoleStandby {
		t.Fatalf("role = %q, want standby", health.Role)
	}

	h.UpdateComponentHealth("worker", StatusUnknown, "")
	if got := h.GetHealth().Status; got != StatusUnhealthy {
		t.Fatalf("overall status = %s, want unhealthy with an unknown component", got)
	}
}

// Not parallel: MarkLeader flips process-wide state.
func TestMetricsSwitchToFullRegistryOnLeadership(t *testing.T) {
	_ = GetMetrics() // registers the business metrics on the default registry

	scrape := func() string {
		rec := httptest.NewRecorder()
		metricsHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
		return rec.Body.String()
	}

	standby := scrape()
	if !strings.Contains(standby, "suppline_leader 0") {
		t.Fatalf("standby scrape lacks suppline_leader 0:\n%s", standby)
	}
	if strings.Contains(standby, "suppline_queue_depth") {
		t.Fatal("standby scrape exports business metrics")
	}
	if !strings.Contains(standby, "go_goroutines") {
		t.Fatal("standby scrape lacks Go runtime metrics")
	}

	MarkLeader()
	leader := scrape()
	if !strings.Contains(leader, "suppline_leader 1") || !strings.Contains(leader, "suppline_queue_depth") {
		t.Fatalf("leader scrape lacks suppline_leader 1 or business metrics:\n%s", leader)
	}
}

func TestReadyFailsWhileDraining(t *testing.T) {
	h := NewHealthChecker(slog.New(slog.NewTextHandler(io.Discard, nil)))
	h.RegisterComponent("database")
	h.UpdateComponentHealth("database", StatusHealthy, "")

	ready := func() int {
		rec := httptest.NewRecorder()
		h.ReadyHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/ready", nil))
		return rec.Code
	}
	if got := ready(); got != http.StatusOK {
		t.Fatalf("/ready = %d before draining, want 200", got)
	}
	h.SetDraining()
	if got := ready(); got != http.StatusServiceUnavailable {
		t.Fatalf("/ready = %d while draining, want 503", got)
	}
	if got := h.GetHealth().Status; got != StatusHealthy {
		t.Fatalf("/health status = %s while draining, want healthy (liveness must not fail)", got)
	}
}
