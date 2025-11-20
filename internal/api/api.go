package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/daimoniac/suppline/internal/config"
	"github.com/daimoniac/suppline/internal/queue"
	"github.com/daimoniac/suppline/internal/statestore"
	httpSwagger "github.com/swaggo/http-swagger"
	
	_ "github.com/daimoniac/suppline/build/swagger" // Import generated docs
)

// @title suppline API
// @version 1.0
// @description REST API for querying container image scan results, managing CVE tolerations, and triggering security operations.
// @description
// @description ## Features
// @description - Query scan results and vulnerability data
// @description - List failed images and policy violations
// @description - Manage CVE tolerations
// @description - Trigger rescans and policy re-evaluations
// @description - Health checks and metrics

// @contact.name suppline
// @license.name Apache 2.0
// @license.url https://www.apache.org/licenses/LICENSE-2.0.html

// @host localhost:8080
// @BasePath /api/v1

// @securityDefinitions.apikey BearerAuth
// @in header
// @name Authorization
// @description Enter your API key (with or without "Bearer " prefix)

// APIServer provides HTTP API for querying scan results and triggering operations
type APIServer struct {
	config           *config.APIConfig
	attestationConfig *config.AttestationConfig
	stateStore       statestore.StateStoreQuery
	taskQueue        queue.TaskQueue
	regsyncPath      string
	router           *http.ServeMux
	server           *http.Server
	logger           *slog.Logger
}

// NewAPIServer creates a new API server instance
func NewAPIServer(cfg *config.APIConfig, attestationCfg *config.AttestationConfig, store statestore.StateStoreQuery, queue queue.TaskQueue, regsyncPath string, logger *slog.Logger) *APIServer {
	api := &APIServer{
		config:            cfg,
		attestationConfig: attestationCfg,
		stateStore:        store,
		taskQueue:         queue,
		regsyncPath:       regsyncPath,
		router:            http.NewServeMux(),
		logger:            logger,
	}

	api.setupRoutes()

	api.server = &http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.Port),
		Handler:      api.router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	return api
}

// setupRoutes configures all API routes
func (s *APIServer) setupRoutes() {
	// Query endpoints (GET)
	s.router.HandleFunc("/api/v1/scans", s.corsMiddleware(s.authMiddleware(s.handleListScans, false)))
	s.router.HandleFunc("/api/v1/scans/", s.corsMiddleware(s.authMiddleware(s.handleGetScan, false)))
	s.router.HandleFunc("/api/v1/vulnerabilities", s.corsMiddleware(s.authMiddleware(s.handleQueryVulnerabilities, false)))
	s.router.HandleFunc("/api/v1/tolerations", s.corsMiddleware(s.authMiddleware(s.handleListTolerations, false)))
	s.router.HandleFunc("/api/v1/images/failed", s.corsMiddleware(s.authMiddleware(s.handleListFailedImages, false)))

	// Action endpoints (POST)
	s.router.HandleFunc("/api/v1/scans/trigger", s.corsMiddleware(s.authMiddleware(s.handleTriggerScan, true)))
	s.router.HandleFunc("/api/v1/policy/reevaluate", s.corsMiddleware(s.authMiddleware(s.handleReevaluatePolicy, true)))

	// Health and metrics
	s.router.HandleFunc("/health", s.corsMiddleware(s.handleHealth))
	s.router.HandleFunc("/metrics", s.corsMiddleware(s.handleMetrics))

	// Integration endpoints
	s.router.HandleFunc("/api/v1/integration/publickey", s.corsMiddleware(s.handleGetPublicKey))
	s.router.HandleFunc("/api/v1/integration/kyverno/policy", s.corsMiddleware(s.handleGenerateKyvernoPolicy))

	// Swagger documentation
	s.router.HandleFunc("/swagger/", httpSwagger.WrapHandler)

	// Redirect root to swagger
	s.router.HandleFunc("/", s.handleRootRedirect)
}

// corsMiddleware adds CORS headers to allow cross-origin requests
func (s *APIServer) corsMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Set CORS headers
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		w.Header().Set("Access-Control-Max-Age", "3600")

		// Handle preflight OPTIONS request
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		// Call the next handler
		next(w, r)
	}
}

// authMiddleware provides optional API key authentication
// requireWrite indicates if this is a write operation that should be blocked in read-only mode
func (s *APIServer) authMiddleware(next http.HandlerFunc, requireWrite bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Check if write operation is allowed
		if requireWrite && s.config.ReadOnly {
			s.respondError(w, http.StatusForbidden, "API is in read-only mode")
			return
		}

		// If API key is configured, validate it
		if s.config.APIKey != "" {
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				s.respondError(w, http.StatusUnauthorized, "Authorization header required")
				return
			}

			// Extract token - accept both "Bearer <token>" and just "<token>"
			token := authHeader
			if strings.HasPrefix(authHeader, "Bearer ") {
				token = strings.TrimPrefix(authHeader, "Bearer ")
			}

			if token != s.config.APIKey {
				s.respondError(w, http.StatusUnauthorized, "Invalid API key")
				return
			}
		}

		// Authentication passed, call the handler
		next(w, r)
	}
}

// Start starts the API server
func (s *APIServer) Start(ctx context.Context) error {
	if !s.config.Enabled {
		s.logger.Info("API server is disabled")
		return nil
	}

	s.logger.Info("starting API server",
		"port", s.config.Port)

	// Start server in a goroutine
	go func() {
		if err := s.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			s.logger.Error("API server error",
				"error", err.Error())
		}
	}()

	// Wait for context cancellation
	<-ctx.Done()

	// Graceful shutdown
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	s.logger.Info("shutting down API server")
	return s.server.Shutdown(shutdownCtx)
}

// Shutdown gracefully shuts down the API server
func (s *APIServer) Shutdown(ctx context.Context) error {
	return s.server.Shutdown(ctx)
}

// respondJSON sends a JSON response
func (s *APIServer) respondJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		s.logger.Error("error encoding JSON response",
			"error", err.Error())
	}
}

// respondError sends an error response
func (s *APIServer) respondError(w http.ResponseWriter, status int, message string) {
	s.respondJSON(w, status, map[string]string{"error": message})
}

// parseQueryParam extracts a query parameter from the request
func parseQueryParam(r *http.Request, key string) string {
	return r.URL.Query().Get(key)
}

// parseQueryParamInt extracts an integer query parameter
func parseQueryParamInt(r *http.Request, key string, defaultValue int) int {
	value := r.URL.Query().Get(key)
	if value == "" {
		return defaultValue
	}
	var intValue int
	if _, err := fmt.Sscanf(value, "%d", &intValue); err == nil {
		return intValue
	}
	return defaultValue
}

// parseQueryParamBool extracts a boolean query parameter
func parseQueryParamBool(r *http.Request, key string) *bool {
	value := r.URL.Query().Get(key)
	if value == "" {
		return nil
	}
	boolValue := value == "true" || value == "1" || value == "yes"
	return &boolValue
}

// handleRootRedirect redirects / to /swagger/
func (s *APIServer) handleRootRedirect(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		s.respondError(w, http.StatusNotFound, "not found")
		return
	}
	http.Redirect(w, r, "/swagger/", http.StatusMovedPermanently)
}
