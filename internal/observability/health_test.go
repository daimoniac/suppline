package observability

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestHealthChecker(t *testing.T) {
	logger := NewLogger("info")
	hc := NewHealthChecker(logger)

	// Register components
	hc.RegisterComponent("database")
	hc.RegisterComponent("trivy")

	// Initially unknown
	health := hc.GetHealth()
	if health.Status != StatusUnhealthy {
		t.Errorf("expected unhealthy status with unknown components, got %v", health.Status)
	}

	// Update to healthy
	hc.UpdateComponentHealth("database", StatusHealthy, "")
	hc.UpdateComponentHealth("trivy", StatusHealthy, "")

	health = hc.GetHealth()
	if health.Status != StatusHealthy {
		t.Errorf("expected healthy status, got %v", health.Status)
	}

	// One component unhealthy
	hc.UpdateComponentHealth("database", StatusUnhealthy, "connection failed")

	health = hc.GetHealth()
	if health.Status != StatusUnhealthy {
		t.Errorf("expected unhealthy status, got %v", health.Status)
	}

	if health.Components["database"].Message != "connection failed" {
		t.Errorf("expected error message, got %v", health.Components["database"].Message)
	}
}

func TestHealthHandler(t *testing.T) {
	logger := NewLogger("info")
	hc := NewHealthChecker(logger)

	hc.RegisterComponent("test")
	hc.UpdateComponentHealth("test", StatusHealthy, "")

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()

	handler := hc.HealthHandler()
	handler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}

	// Test unhealthy
	hc.UpdateComponentHealth("test", StatusUnhealthy, "error")

	req = httptest.NewRequest(http.MethodGet, "/health", nil)
	w = httptest.NewRecorder()

	handler(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("expected status 503, got %d", w.Code)
	}
}

func TestCheckComponent(t *testing.T) {
	logger := NewLogger("info")
	hc := NewHealthChecker(logger)

	hc.RegisterComponent("test")

	// Successful check
	ctx := context.Background()
	hc.CheckComponent(ctx, "test", func(ctx context.Context) error {
		return nil
	})

	health := hc.GetHealth()
	if health.Components["test"].Status != StatusHealthy {
		t.Errorf("expected healthy status, got %v", health.Components["test"].Status)
	}

	// Failed check
	hc.CheckComponent(ctx, "test", func(ctx context.Context) error {
		return errors.New("check failed")
	})

	health = hc.GetHealth()
	if health.Components["test"].Status != StatusUnhealthy {
		t.Errorf("expected unhealthy status, got %v", health.Components["test"].Status)
	}
}

func TestPeriodicChecks(t *testing.T) {
	logger := NewLogger("info")
	hc := NewHealthChecker(logger)

	hc.RegisterComponent("test")

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	checkCount := 0
	checks := map[string]HealthCheckFunc{
		"test": func(ctx context.Context) error {
			checkCount++
			return nil
		},
	}

	go hc.StartPeriodicChecks(ctx, 20*time.Millisecond, checks)

	<-ctx.Done()

	if checkCount < 2 {
		t.Errorf("expected at least 2 checks, got %d", checkCount)
	}
}
