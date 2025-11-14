package observability

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"
)

func TestObservabilityServerIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	logger := NewLogger("info")
	healthChecker := NewHealthChecker(logger)

	healthChecker.RegisterComponent("test")
	healthChecker.UpdateComponentHealth("test", StatusHealthy, "")
	metricsPort := 19090
	healthPort := 18081

	server := NewServer(metricsPort, healthPort, logger, healthChecker)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start server
	go func() {
		_ = server.Start(ctx)
	}()

	// Wait for server to start
	time.Sleep(100 * time.Millisecond)

	// Test metrics endpoint
	t.Run("metrics endpoint", func(t *testing.T) {
		resp, err := http.Get(fmt.Sprintf("http://localhost:%d/metrics", metricsPort))
		if err != nil {
			t.Fatalf("failed to get metrics: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("expected status 200, got %d", resp.StatusCode)
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("failed to read response: %v", err)
		}

		// Check for some expected metrics
		bodyStr := string(body)
		if len(bodyStr) == 0 {
			t.Error("expected non-empty metrics response")
		}
	})

	// Test health endpoint
	t.Run("health endpoint", func(t *testing.T) {
		resp, err := http.Get(fmt.Sprintf("http://localhost:%d/health", healthPort))
		if err != nil {
			t.Fatalf("failed to get health: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("expected status 200, got %d", resp.StatusCode)
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("failed to read response: %v", err)
		}

		bodyStr := string(body)
		if len(bodyStr) == 0 {
			t.Error("expected non-empty health response")
		}
	})

	// Test ready endpoint
	t.Run("ready endpoint", func(t *testing.T) {
		resp, err := http.Get(fmt.Sprintf("http://localhost:%d/ready", healthPort))
		if err != nil {
			t.Fatalf("failed to get ready: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("expected status 200, got %d", resp.StatusCode)
		}
	})

	// Shutdown
	cancel()
	time.Sleep(100 * time.Millisecond)
}
