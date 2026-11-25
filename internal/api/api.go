package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	_ "github.com/daimoniac/suppline/build/swagger" // registers generated docs

	"github.com/daimoniac/suppline/internal/config"
	"github.com/daimoniac/suppline/internal/configedit"
	"github.com/daimoniac/suppline/internal/mirror"
	"github.com/daimoniac/suppline/internal/policy/catalog"
	"github.com/daimoniac/suppline/internal/queue"
	"github.com/daimoniac/suppline/internal/runway"
	"github.com/daimoniac/suppline/internal/scanenqueue"
	"github.com/daimoniac/suppline/internal/statestore"
	"github.com/daimoniac/suppline/internal/triage"
	"github.com/daimoniac/suppline/internal/vexaudit"
	httpSwagger "github.com/swaggo/http-swagger"

	uiassets "github.com/daimoniac/suppline/ui"
)

// @title suppline API
// @version 1.0
// @description REST API for querying container image scan results, managing VEX statements, and triggering security operations.
// @description
// @description ## Features
// @description - Query scan results and vulnerability data
// @description - List failed images and policy violations
// @description - Manage VEX statements and CVE exemptions
// @description - Trigger rescans and policy re-evaluations
// @description - Health checks and metrics

// @contact.name suppline
// @license.name Apache 2.0
// @license.url https://www.apache.org/licenses/LICENSE-2.0.html

// @BasePath /api/v1

// @securityDefinitions.apikey BearerAuth
// @in header
// @name Authorization
// @description Enter your API key (with or without "Bearer " prefix)

// APIServer provides HTTP API for querying scan results and triggering operations
type APIServer struct {
	config            *config.APIConfig
	attestationConfig *config.AttestationConfig
	stateStore        statestore.StateStoreQuery
	clusterInventory  statestore.ClusterInventoryStore
	taskQueue         queue.TaskQueue
	scanEnqueuer      *scanenqueue.Enqueuer
	currentConfig     config.Source
	policyCatalog     catalog.Catalog
	triageService     *triage.Service
	configEditor      *configedit.Editor
	vexAudit          *vexaudit.Auditor
	mirrorEnabled     bool
	mirrorActivity    *mirror.Activity
	malicious         MaliciousFeed
	maliciousInfo     MaliciousSettings
	heldDigests       HeldDigestLister
	digestResolver    DigestResolver
	scanWaiter        *ScanRequestWaiter
	oidc              *oidcVerifier
	router            *http.ServeMux
	ui                http.Handler
	server            *http.Server
	logger            *slog.Logger
}

// NewAPIServer creates a new API server instance
func NewAPIServer(cfg *config.APIConfig, attestationCfg *config.AttestationConfig, store statestore.StateStoreQuery, taskQueue queue.TaskQueue, regsyncConfig *config.RegsyncConfig, logger *slog.Logger) *APIServer {
	return NewAPIServerWithEnqueuer(
		cfg,
		attestationCfg,
		store,
		taskQueue,
		scanenqueue.New(taskQueue, store),
		regsyncConfig,
		logger,
	)
}

// NewAPIServerWithEnqueuer creates an API server with a shared scan enqueuer.
func NewAPIServerWithEnqueuer(cfg *config.APIConfig, attestationCfg *config.AttestationConfig, store statestore.StateStoreQuery, taskQueue queue.TaskQueue, scanEnqueuer *scanenqueue.Enqueuer, regsyncConfig *config.RegsyncConfig, logger *slog.Logger) *APIServer {
	running := catalog.NewConfigCatalog(regsyncConfig)
	return NewAPIServerWithCatalogAndEnqueuer(
		cfg, attestationCfg, store, taskQueue, scanEnqueuer,
		running.Current, running, logger,
	)
}

// NewAPIServerWithCatalogAndEnqueuer creates an API server using shared seams.
func NewAPIServerWithCatalogAndEnqueuer(cfg *config.APIConfig, attestationCfg *config.AttestationConfig, store statestore.StateStoreQuery, taskQueue queue.TaskQueue, scanEnqueuer *scanenqueue.Enqueuer, currentConfig config.Source, policyCatalog catalog.Catalog, logger *slog.Logger) *APIServer {
	var clusterInventoryStore statestore.ClusterInventoryStore
	if inventoryStore, ok := store.(statestore.ClusterInventoryStore); ok {
		clusterInventoryStore = inventoryStore
	}

	api := &APIServer{
		config:            cfg,
		attestationConfig: attestationCfg,
		stateStore:        store,
		clusterInventory:  clusterInventoryStore,
		taskQueue:         taskQueue,
		scanEnqueuer:      scanEnqueuer,
		currentConfig:     currentConfig,
		policyCatalog:     policyCatalog,
		router:            http.NewServeMux(),
		logger:            logger,
	}

	if cfg != nil && cfg.OIDC != nil {
		api.oidc = newOIDCVerifier(*cfg.OIDC, nil)
	}

	if cfg != nil && strings.TrimSpace(cfg.APIKey) == "" && logger != nil {
		logger.Warn("API authentication is disabled because SUPPLINE_API_KEY is empty")
	}

	api.setupRoutes()

	handler, err := api.rootHandler(uiassets.Files())
	if err != nil {
		// The UI's index.html is embedded at build time, so this only fails on a broken build.
		panic(fmt.Sprintf("api: build UI handler: %v", err))
	}

	api.server = &http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.Port),
		Handler:      handler,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	return api
}

// SetTriage connects the triage queue so the API can report it and enqueue work.
func (s *APIServer) SetTriage(svc *triage.Service) {
	if s == nil {
		return
	}
	s.triageService = svc
}

// SetConfigEditor enables the task endpoints that edit suppline.yml.
func (s *APIServer) SetConfigEditor(editor *configedit.Editor) {
	if s == nil {
		return
	}
	s.configEditor = editor
}

// SetVEXAudit connects the background audit of ineffective sync-entry VEX statements.
func (s *APIServer) SetVEXAudit(audit *vexaudit.Auditor) {
	if s == nil {
		return
	}
	s.vexAudit = audit
}

// SetMirror records whether the in-process mirror is enabled and which syncs are running.
func (s *APIServer) SetMirror(enabled bool, activity *mirror.Activity) {
	if s == nil {
		return
	}
	s.mirrorEnabled = enabled
	s.mirrorActivity = activity
}

// SetMalicious enables the malicious-packages view. A nil feed leaves it off.
func (s *APIServer) SetMalicious(feed MaliciousFeed, settings MaliciousSettings) {
	if s == nil {
		return
	}
	s.malicious = feed
	s.maliciousInfo = settings
}

// HeldDigestLister lists the digests the tag runway holds and rescans a
// released one at once.
type HeldDigestLister interface {
	Held() []runway.HeldDigest
	Release(ctx context.Context, repository, digest string) (bool, error)
}

// SetHeldDigests registers the tag runway for the Held section of the Mirror page.
func (s *APIServer) SetHeldDigests(held HeldDigestLister) {
	if s == nil {
		return
	}
	s.heldDigests = held
}

// setupRoutes configures all API routes
func (s *APIServer) setupRoutes() {
	// Query endpoints (GET)
	s.router.HandleFunc("/api/v1/scans", s.authMiddleware(s.handleListScans, false))
	s.router.HandleFunc("/api/v1/scans/", s.authMiddleware(s.handleGetScan, false))
	s.router.HandleFunc("/api/v1/vulnerabilities", s.authMiddleware(s.handleQueryVulnerabilities, false))
	s.router.HandleFunc("/api/v1/vulnerabilities/", s.authMiddleware(s.handleGetVulnerabilityDetails, false))
	s.router.HandleFunc("/api/v1/coverage", s.authMiddleware(s.handleGetCoverage, false))
	s.router.HandleFunc("/api/v1/cluster/instances", s.authMiddleware(s.handleListClusterInstances, false))
	s.router.HandleFunc("/api/v1/vex", s.authMiddleware(s.handleListVEX, false))
	s.router.HandleFunc("/api/v1/triage", s.authMiddleware(s.handleListTriage, false))
	s.router.HandleFunc("/api/v1/triage/statements", s.authMiddleware(s.handleListTriageStatements, false))
	s.router.HandleFunc("/api/v1/triage/repositories", s.authMiddleware(s.handleListTriageRepositories, false))
	s.router.HandleFunc("/api/v1/triage/status", s.authMiddleware(s.handleTriageStatus, false))
	s.router.HandleFunc("/api/v1/triage/run", s.authMiddleware(s.handleTriageRun, true))
	s.router.HandleFunc("/api/v1/triage/retry", s.authMiddleware(s.handleTriageRetry, true))
	s.router.HandleFunc("/api/v1/triage/accept", s.authMiddleware(s.handleTriageAccept, true))
	s.router.HandleFunc("/api/v1/triage/budget/reset", s.authMiddleware(s.handleTriageBudgetReset, true))
	s.router.HandleFunc("/api/v1/vex/inactive", s.authMiddleware(s.handleListInactiveVEX, false))
	s.router.HandleFunc("/api/v1/images/failed", s.authMiddleware(s.handleListFailedImages, false))
	s.router.HandleFunc("/api/v1/images/running-failures", s.authMiddleware(s.handleListRunningPolicyFailures, false))
	s.router.HandleFunc("/api/v1/policies", s.authMiddleware(s.handleListPolicies, false))
	s.router.HandleFunc("/api/v1/repositories", s.authMiddleware(s.handleListRepositories, false))
	s.router.HandleFunc("/api/v1/repositories/", s.authMiddleware(s.handleRepositoriesRouter, false))

	// Action endpoints (POST)
	s.router.HandleFunc("/api/v1/scans/trigger", s.authMiddleware(s.handleTriggerScan, true))
	// Scan requests are the only endpoints CI identities may call.
	s.router.HandleFunc("POST /api/v1/scan-requests", s.scanRequestAuth(s.handleCreateScanRequest, true))
	s.router.HandleFunc("GET /api/v1/scan-requests/", s.scanRequestAuth(s.handleGetScanRequest, false))
	s.router.HandleFunc("/api/v1/policy/reevaluate", s.authMiddleware(s.handleReevaluatePolicy, true))
	s.router.HandleFunc("/api/v1/webhook/cluster-inventory", s.handleClusterInventory)

	// Health and metrics
	s.router.HandleFunc("/health", s.handleHealth)

	// Task endpoints
	s.router.HandleFunc("/api/v1/tasks/config-edits", s.authMiddleware(s.handleConfigEditStatus, false))
	s.router.HandleFunc("/api/v1/tasks/semver-updates", s.authMiddleware(s.handleSemverUpdateTasks, true))
	s.router.HandleFunc("/api/v1/tasks/sync-removals", s.authMiddleware(s.handleRemoveSyncTargets, true))
	s.router.HandleFunc("/api/v1/tasks/vex-removals", s.authMiddleware(s.handleRemoveVEXStatements, true))
	s.router.HandleFunc("/api/v1/tasks/vex-expiry", s.authMiddleware(s.handleGetVEXExpiryTasks, true))
	s.router.HandleFunc("/api/v1/tasks/ineffective-vex", s.authMiddleware(s.handleGetIneffectiveVEX, true))
	s.router.HandleFunc("/api/v1/tasks/ineffective-vex-removals", s.authMiddleware(s.handleRemoveIneffectiveVEX, true))
	s.router.HandleFunc("/api/v1/tasks/runtime-unused-whitelist", s.authMiddleware(s.handleRuntimeUnusedWhitelistRouter, false))

	// Integration endpoints
	s.router.HandleFunc("/api/v1/integration/gitops", s.authMiddleware(s.handleGitopsStatus, false))
	s.router.HandleFunc("/api/v1/integration/kubernetes/clusters", s.handleListKubernetesClusters)
	s.router.HandleFunc("/api/v1/integration/kubernetes/clusters/", s.authMiddleware(s.handleKubernetesClustersRouter, false))
	s.router.HandleFunc("/api/v1/mirror", s.authMiddleware(s.handleGetMirror, false))
	s.router.HandleFunc("/api/v1/mirror/held", s.authMiddleware(s.handleListHeldDigests, false))
	s.router.HandleFunc("/api/v1/mirror/held/release", s.authMiddleware(s.handleReleaseCooldown, true))
	s.router.HandleFunc("/api/v1/mirror/", s.authMiddleware(s.handleMirrorSub, false))
	s.router.HandleFunc("/api/v1/malicious", s.authMiddleware(s.handleGetMalicious, false))

	s.router.HandleFunc("/api/v1/integration/publickey", s.handleGetPublicKey)
	s.router.HandleFunc("/api/v1/integration/kyverno/policy", s.handleGenerateKyvernoPolicy)

	// Swagger documentation
	s.router.HandleFunc("/swagger/", httpSwagger.WrapHandler)
	s.router.HandleFunc("/swagger", handleSwaggerRedirect)

	// Everything else is the embedded web UI.
	s.router.HandleFunc("/", s.handleUI)

	// Unknown API paths answer with a JSON 404 instead of the UI.
	s.router.HandleFunc("/api/", s.handleAPINotFound)
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

			// Accept both "Bearer <token>" and just "<token>".
			if !s.validAPIKey(bearerToken(r)) {
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

// parseImageUsageQuery maps in_use_mode to statestore.ImageUsage. Omitted or "all" means no filter.
func parseImageUsageQuery(r *http.Request) statestore.ImageUsage {
	mode := strings.ToLower(strings.TrimSpace(parseQueryParam(r, "in_use_mode")))
	switch mode {
	case "", "all":
		return statestore.ImageUsageAll
	case "in_use", "in-use":
		return statestore.ImageUsageInUse
	case "not_in_use", "not-in-use", "out":
		return statestore.ImageUsageNotInUse
	case "in_use_newer", "in-use-newer":
		return statestore.ImageUsageInUseOrNewerSemver
	default:
		return statestore.ImageUsageAll
	}
}

// handleAPINotFound answers unknown /api/ paths with a JSON 404.
func (s *APIServer) handleAPINotFound(w http.ResponseWriter, r *http.Request) {
	s.respondError(w, http.StatusNotFound, "not found")
}

// runningConfig returns the configuration snapshot for one request, or nil.
func (s *APIServer) runningConfig() *config.RegsyncConfig {
	if s.currentConfig == nil {
		return nil
	}
	return s.currentConfig()
}
