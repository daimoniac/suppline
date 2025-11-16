package observability

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/daimoniac/suppline/internal/errors"
)

// Server provides HTTP endpoints for metrics and health checks
type Server struct {
	metricsServer *http.Server
	healthServer  *http.Server
	logger        *slog.Logger
	healthChecker *HealthChecker
}

// NewServer creates a new observability server
func NewServer(metricsPort, healthPort int, logger *slog.Logger, healthChecker *HealthChecker) *Server {
	// Metrics server
	metricsMux := http.NewServeMux()
	metricsMux.Handle("/metrics", promhttp.Handler())
	
	metricsServer := &http.Server{
		Addr:         fmt.Sprintf(":%d", metricsPort),
		Handler:      metricsMux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  15 * time.Second,
	}

	// Health server
	healthMux := http.NewServeMux()
	healthMux.HandleFunc("/health", healthChecker.HealthHandler())
	healthMux.HandleFunc("/ready", healthChecker.ReadyHandler())
	
	healthServer := &http.Server{
		Addr:         fmt.Sprintf(":%d", healthPort),
		Handler:      healthMux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  15 * time.Second,
	}

	return &Server{
		metricsServer: metricsServer,
		healthServer:  healthServer,
		logger:        logger,
		healthChecker: healthChecker,
	}
}

// Start starts the observability servers
func (s *Server) Start(ctx context.Context) error {
	// Start metrics server
	go func() {
		s.logger.Info("starting metrics server",
			"addr", s.metricsServer.Addr)
		if err := s.metricsServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			s.logger.Error("metrics server error",
				"error", err.Error())
		}
	}()

	// Start health server
	go func() {
		s.logger.Info("starting health server",
			"addr", s.healthServer.Addr)
		if err := s.healthServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			s.logger.Error("health server error",
				"error", err.Error())
		}
	}()

	// Wait for context cancellation
	<-ctx.Done()

	// Shutdown servers gracefully
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	s.logger.Info("shutting down observability servers")

	if err := s.metricsServer.Shutdown(shutdownCtx); err != nil {
		s.logger.Error("metrics server shutdown error",
			"error", err.Error())
	}

	if err := s.healthServer.Shutdown(shutdownCtx); err != nil {
		s.logger.Error("health server shutdown error",
			"error", err.Error())
	}

	return nil
}

// Shutdown gracefully shuts down the observability servers
func (s *Server) Shutdown(ctx context.Context) error {
	s.logger.Info("shutting down observability servers")

	if err := s.metricsServer.Shutdown(ctx); err != nil {
		return errors.NewTransientf("metrics server shutdown: %w", err)
	}

	if err := s.healthServer.Shutdown(ctx); err != nil {
		return errors.NewTransientf("health server shutdown: %w", err)
	}

	return nil
}
