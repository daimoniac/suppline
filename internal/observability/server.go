package observability

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/daimoniac/suppline/internal/errors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Server serves /metrics, /health and /ready on the observability port.
type Server struct {
	server *http.Server
	logger *slog.Logger
}

// NewServer creates the observability server on port.
func NewServer(port int, logger *slog.Logger, healthChecker *HealthChecker) *Server {
	return &Server{
		server: &http.Server{
			Addr:         fmt.Sprintf(":%d", port),
			Handler:      newMux(healthChecker),
			ReadTimeout:  5 * time.Second,
			WriteTimeout: 10 * time.Second,
			IdleTimeout:  15 * time.Second,
		},
		logger: logger,
	}
}

func newMux(healthChecker *HealthChecker) *http.ServeMux {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	mux.HandleFunc("/health", healthChecker.HealthHandler())
	mux.HandleFunc("/ready", healthChecker.ReadyHandler())
	return mux
}

// Start serves until ctx is cancelled, then shuts down gracefully.
func (s *Server) Start(ctx context.Context) error {
	go func() {
		s.logger.Info("starting observability server", "addr", s.server.Addr)
		if err := s.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			s.logger.Error("observability server error", "error", err.Error())
		}
	}()

	<-ctx.Done()

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := s.Shutdown(shutdownCtx); err != nil {
		s.logger.Error("observability server shutdown error", "error", err.Error())
	}
	return nil
}

// Shutdown gracefully shuts down the observability server.
func (s *Server) Shutdown(ctx context.Context) error {
	s.logger.Info("shutting down observability server")
	if err := s.server.Shutdown(ctx); err != nil {
		return errors.NewTransientf("observability server shutdown: %w", err)
	}
	return nil
}
