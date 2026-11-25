package observability

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
)

// Liveness must not depend on PostgreSQL or Trivy: restarting suppline does
// not bring a database back, it only adds restarts on top of the outage.
func TestLiveAnswersWhileUnhealthyAndDraining(t *testing.T) {
	h := NewHealthChecker(slog.New(slog.NewTextHandler(io.Discard, nil)))
	h.RegisterComponent("database")
	h.UpdateComponentHealth("database", StatusUnhealthy, "connection refused")
	h.SetDraining()

	rec := httptest.NewRecorder()
	h.LiveHandler()(rec, httptest.NewRequest(http.MethodGet, "/live", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("/live = %d, want 200 while the process runs", rec.Code)
	}

	rec = httptest.NewRecorder()
	h.HealthHandler()(rec, httptest.NewRequest(http.MethodGet, "/health", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("/health = %d, want 503 with the database down", rec.Code)
	}
}
