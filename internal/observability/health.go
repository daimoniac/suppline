package observability

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/daimoniac/suppline/internal/version"
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
	// StatusStandby marks a leader-only component on a standby instance. It
	// counts as healthy: a standby that waits for leadership is working.
	StatusStandby ComponentStatus = "standby"
)

// Roles an instance reports in /health.
const (
	RoleLeader  = "leader"
	RoleStandby = "standby"
)

// ComponentHealth represents the health of a single component
type ComponentHealth struct {
	Status    ComponentStatus `json:"status"`
	Message   string          `json:"message,omitempty"`
	LastCheck time.Time       `json:"last_check"`
}

// HealthStatus represents the overall health status
type HealthStatus struct {
	Status     ComponentStatus            `json:"status"`
	Role       string                     `json:"role,omitempty"`
	Version    string                     `json:"version"`
	Components map[string]ComponentHealth `json:"components"`
	Timestamp  time.Time                  `json:"timestamp"`
}

// HealthChecker provides health check functionality
type HealthChecker struct {
	mu         sync.RWMutex
	components map[string]ComponentHealth
	role       string
	draining   bool
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

// SetRole records whether this instance leads or stands by.
func (h *HealthChecker) SetRole(role string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.role = role
}

// SetDraining makes /ready fail so load balancers stop sending new
// requests while in-flight ones finish. /health is unaffected.
func (h *HealthChecker) SetDraining() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.draining = true
}

func (h *HealthChecker) isDraining() bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.draining
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
		if health.Status != StatusHealthy && health.Status != StatusStandby {
			overallHealthy = false
		}
	}

	status := StatusHealthy
	if !overallHealthy {
		status = StatusUnhealthy
	}

	return HealthStatus{
		Status:     status,
		Role:       h.role,
		Version:    version.Version,
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

		if h.isDraining() {
			w.WriteHeader(http.StatusServiceUnavailable)
			fmt.Fprintf(w, `{"status":"draining"}`)
			return
		}

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
