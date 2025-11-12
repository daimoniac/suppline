package observability

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"
)

// ComponentStatus represents the health status of a component
type ComponentStatus string

const (
	StatusHealthy   ComponentStatus = "healthy"
	StatusUnhealthy ComponentStatus = "unhealthy"
	StatusUnknown   ComponentStatus = "unknown"
)

// ComponentHealth represents the health of a single component
type ComponentHealth struct {
	Status  ComponentStatus `json:"status"`
	Message string          `json:"message,omitempty"`
	LastCheck time.Time     `json:"last_check"`
}

// HealthStatus represents the overall health status
type HealthStatus struct {
	Status     ComponentStatus            `json:"status"`
	Components map[string]ComponentHealth `json:"components"`
	Timestamp  time.Time                  `json:"timestamp"`
}

// HealthChecker provides health check functionality
type HealthChecker struct {
	mu         sync.RWMutex
	components map[string]ComponentHealth
	logger     *slog.Logger
}

// NewHealthChecker creates a new health checker
func NewHealthChecker(logger *slog.Logger) *HealthChecker {
	return &HealthChecker{
		components: make(map[string]ComponentHealth),
		logger:     logger,
	}
}

// RegisterComponent registers a component for health checking
func (h *HealthChecker) RegisterComponent(name string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.components[name] = ComponentHealth{
		Status:    StatusUnknown,
		LastCheck: time.Now(),
	}
}

// UpdateComponentHealth updates the health status of a component
func (h *HealthChecker) UpdateComponentHealth(name string, status ComponentStatus, message string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.components[name] = ComponentHealth{
		Status:    status,
		Message:   message,
		LastCheck: time.Now(),
	}
}

// GetHealth returns the current health status
func (h *HealthChecker) GetHealth() HealthStatus {
	h.mu.RLock()
	defer h.mu.RUnlock()

	// Copy components to avoid race conditions
	components := make(map[string]ComponentHealth)
	overallHealthy := true

	for name, health := range h.components {
		components[name] = health
		if health.Status != StatusHealthy {
			overallHealthy = false
		}
	}

	status := StatusHealthy
	if !overallHealthy {
		status = StatusUnhealthy
	}

	return HealthStatus{
		Status:     status,
		Components: components,
		Timestamp:  time.Now(),
	}
}

// HealthCheckFunc is a function that checks the health of a component
type HealthCheckFunc func(ctx context.Context) error

// CheckComponent runs a health check function and updates the component status
func (h *HealthChecker) CheckComponent(ctx context.Context, name string, checkFunc HealthCheckFunc) {
	err := checkFunc(ctx)
	if err != nil {
		h.UpdateComponentHealth(name, StatusUnhealthy, err.Error())
		h.logger.Warn("component health check failed",
			"component", name,
			"error", err.Error())
	} else {
		h.UpdateComponentHealth(name, StatusHealthy, "")
	}
}

// StartPeriodicChecks starts periodic health checks for registered components
func (h *HealthChecker) StartPeriodicChecks(ctx context.Context, interval time.Duration, checks map[string]HealthCheckFunc) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Run initial checks
	for name, checkFunc := range checks {
		h.CheckComponent(ctx, name, checkFunc)
	}

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			for name, checkFunc := range checks {
				h.CheckComponent(ctx, name, checkFunc)
			}
		}
	}
}

// HealthHandler returns an HTTP handler for the health endpoint
func (h *HealthChecker) HealthHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		health := h.GetHealth()

		w.Header().Set("Content-Type", "application/json")
		
		// Set HTTP status code based on health
		if health.Status == StatusHealthy {
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(http.StatusServiceUnavailable)
		}

		if err := json.NewEncoder(w).Encode(health); err != nil {
			h.logger.Error("failed to encode health response",
				"error", err.Error())
		}
	}
}

// ReadyHandler returns an HTTP handler for the readiness endpoint
func (h *HealthChecker) ReadyHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		health := h.GetHealth()

		w.Header().Set("Content-Type", "application/json")
		
		// Ready if all components are healthy
		if health.Status == StatusHealthy {
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, `{"status":"ready"}`)
		} else {
			w.WriteHeader(http.StatusServiceUnavailable)
			fmt.Fprintf(w, `{"status":"not_ready"}`)
		}
	}
}
