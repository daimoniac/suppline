package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/daimoniac/suppline/internal/config"
	"github.com/daimoniac/suppline/internal/integration"
	"github.com/daimoniac/suppline/internal/queue"
	"github.com/daimoniac/suppline/internal/statestore"
	"github.com/daimoniac/suppline/internal/types"
)

// handleGetScan retrieves a scan record with vulnerabilities for a specific digest
// @Summary Get scan by digest
// @Description Retrieve detailed scan information for a specific image digest
// @Tags Scans
// @Accept json
// @Produce json
// @Param digest path string true "Image digest (e.g., sha256:abc123...)"
// @Success 200 {object} statestore.ScanRecord
// @Failure 400 {object} map[string]string "Invalid digest format"
// @Failure 401 {object} map[string]string "Unauthorized"
// @Failure 404 {object} map[string]string "Scan not found"
// @Failure 500 {object} map[string]string "Internal server error"
// @Security BearerAuth
// @Router /scans/{digest} [get]
func (s *APIServer) handleGetScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	// Extract digest from URL path
	// Path format: /api/v1/scans/{digest}
	path := r.URL.Path
	prefix := "/api/v1/scans/"
	if !strings.HasPrefix(path, prefix) {
		s.respondError(w, http.StatusBadRequest, "Invalid path")
		return
	}

	digest := strings.TrimPrefix(path, prefix)
	if digest == "" {
		s.respondError(w, http.StatusBadRequest, "Digest is required")
		return
	}

	// Get scan record from state store
	record, err := s.stateStore.GetLastScan(r.Context(), digest)
	if err != nil {
		if errors.Is(err, statestore.ErrScanNotFound) {
			s.respondError(w, http.StatusNotFound, "Scan not found")
			return
		}
		s.respondError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to get scan: %v", err))
		return
	}

	// Convert to response DTO with ISO8601 timestamps
	response := toScanRecordResponse(record)
	s.respondJSON(w, http.StatusOK, response)
}

// handleListScans lists scan records with optional filters
// @Summary List scans
// @Description List all scans with optional filtering and pagination
// @Tags Scans
// @Accept json
// @Produce json
// @Param repository query string false "Filter by repository name"
// @Param policy_passed query boolean false "Filter by policy status"
// @Param limit query int false "Maximum number of results" default(100)
// @Param offset query int false "Pagination offset" default(0)
// @Success 200 {array} ScanRecordResponse
// @Failure 401 {object} map[string]string "Unauthorized"
// @Failure 500 {object} map[string]string "Internal server error"
// @Security BearerAuth
// @Router /scans [get]
func (s *APIServer) handleListScans(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	// Parse query parameters
	filter := statestore.ScanFilter{
		Repository:   parseQueryParam(r, "repository"),
		PolicyPassed: parseQueryParamBool(r, "policy_passed"),
		Limit:        parseQueryParamInt(r, "limit", 100),
		Offset:       parseQueryParamInt(r, "offset", 0),
	}

	// Get scans from state store
	records, err := s.stateStore.ListScans(r.Context(), filter)
	if err != nil {
		s.respondError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to list scans: %v", err))
		return
	}

	// Convert to response DTOs with ISO8601 timestamps
	responses := make([]*ScanRecordResponse, len(records))
	for i, record := range records {
		responses[i] = toScanRecordResponse(record)
	}

	// Stream JSON response to avoid buffering large payloads
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	encoder := json.NewEncoder(w)
	if err := encoder.Encode(responses); err != nil {
		s.logger.Error("error encoding JSON response",
			"error", err.Error())
	}
}

// handleQueryVulnerabilities searches vulnerabilities across all scans
// @Summary Query vulnerabilities
// @Description Search for vulnerabilities across all scans with filtering
// @Tags Vulnerabilities
// @Accept json
// @Produce json
// @Param cve_id query string false "Filter by CVE ID"
// @Param severity query string false "Filter by severity (CRITICAL, HIGH, MEDIUM, LOW)"
// @Param package_name query string false "Filter by package name"
// @Param repository query string false "Filter by repository"
// @Param limit query int false "Maximum number of results" default(100)
// @Success 200 {array} VulnerabilityRecordResponse
// @Failure 401 {object} map[string]string "Unauthorized"
// @Failure 500 {object} map[string]string "Internal server error"
// @Security BearerAuth
// @Router /vulnerabilities [get]
func (s *APIServer) handleQueryVulnerabilities(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	// Parse query parameters
	filter := statestore.VulnFilter{
		CVEID:       parseQueryParam(r, "cve_id"),
		Severity:    parseQueryParam(r, "severity"),
		PackageName: parseQueryParam(r, "package_name"),
		Repository:  parseQueryParam(r, "repository"),
		Limit:       parseQueryParamInt(r, "limit", 100),
	}

	// Query vulnerabilities from state store
	vulnerabilities, err := s.stateStore.QueryVulnerabilities(r.Context(), filter)
	if err != nil {
		s.respondError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to query vulnerabilities: %v", err))
		return
	}

	// Convert to response DTOs with ISO8601 timestamps
	responses := make([]VulnerabilityRecordResponse, len(vulnerabilities))
	for i, vuln := range vulnerabilities {
		responses[i] = toVulnerabilityRecordResponse(*vuln)
	}

	// Stream JSON response to avoid buffering large payloads
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	encoder := json.NewEncoder(w)
	if err := encoder.Encode(responses); err != nil {
		s.logger.Error("error encoding JSON response",
			"error", err.Error())
	}
}

// handleListTolerations lists tolerated CVEs with optional filters
// @Summary List tolerations
// @Description List all CVE tolerations with optional filtering. Returns one entry per unique repository + CVE ID combination.
// @Tags Tolerations
// @Accept json
// @Produce json
// @Param cve_id query string false "Filter by CVE ID"
// @Param repository query string false "Filter by repository name"
// @Param expired query boolean false "Filter by expiration status"
// @Param expiring_soon query boolean false "Show tolerations expiring within 7 days"
// @Param limit query int false "Maximum number of results" default(100)
// @Success 200 {array} types.TolerationInfo
// @Failure 401 {object} map[string]string "Unauthorized"
// @Failure 500 {object} map[string]string "Internal server error"
// @Security BearerAuth
// @Router /tolerations [get]
func (s *APIServer) handleListTolerations(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	// Parse query parameters
	filter := statestore.TolerationFilter{
		CVEID:        parseQueryParam(r, "cve_id"),
		Repository:   parseQueryParam(r, "repository"),
		Expired:      parseQueryParamBool(r, "expired"),
		ExpiringSoon: parseQueryParamBool(r, "expiring_soon"),
		Limit:        parseQueryParamInt(r, "limit", 100),
	}

	// List tolerations from state store
	tolerations, err := s.stateStore.ListTolerations(r.Context(), filter)
	if err != nil {
		s.respondError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to list tolerations: %v", err))
		return
	}

	// Convert to response DTOs with ISO8601 timestamps
	responses := make([]TolerationInfoResponse, len(tolerations))
	for i, toleration := range tolerations {
		responses[i] = toTolerationInfoResponse(*toleration)
	}

	// Stream JSON response to avoid buffering large payloads
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	encoder := json.NewEncoder(w)
	if err := encoder.Encode(responses); err != nil {
		s.logger.Error("error encoding JSON response",
			"error", err.Error())
	}
}

// handleListFailedImages lists all images that failed policy evaluation
// @Summary List failed images
// @Description List all images that failed policy evaluation
// @Tags Scans
// @Accept json
// @Produce json
// @Param limit query int false "Maximum number of results" default(100)
// @Success 200 {array} ScanRecordResponse
// @Failure 401 {object} map[string]string "Unauthorized"
// @Failure 500 {object} map[string]string "Internal server error"
// @Security BearerAuth
// @Router /images/failed [get]
func (s *APIServer) handleListFailedImages(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	// Parse optional limit parameter
	limit := parseQueryParamInt(r, "limit", 100)

	// List failed images using scan filter
	policyPassed := false
	filter := statestore.ScanFilter{
		PolicyPassed: &policyPassed,
		Limit:        limit,
	}

	records, err := s.stateStore.ListScans(r.Context(), filter)
	if err != nil {
		s.respondError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to list failed images: %v", err))
		return
	}

	// Convert to response DTOs with ISO8601 timestamps
	responses := make([]*ScanRecordResponse, len(records))
	for i, record := range records {
		responses[i] = toScanRecordResponse(record)
	}

	// Stream JSON response to avoid buffering large payloads
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	encoder := json.NewEncoder(w)
	if err := encoder.Encode(responses); err != nil {
		s.logger.Error("error encoding JSON response",
			"error", err.Error())
	}
}

// TriggerScanRequest represents the request body for triggering a scan
type TriggerScanRequest struct {
	Digest     string `json:"digest,omitempty"`
	Repository string `json:"repository,omitempty"`
}

// TriggerScanResponse represents the response for a triggered scan
type TriggerScanResponse struct {
	Queued int    `json:"queued"`
	TaskID string `json:"task_id,omitempty"`
}

// handleTriggerScan triggers a rescan of specific digest or repository
// @Summary Trigger rescan
// @Description Trigger a rescan of a specific image digest or all images in a repository
// @Tags Scans
// @Accept json
// @Produce json
// @Param request body TriggerScanRequest true "Trigger scan request (specify either digest or repository)"
// @Success 200 {object} TriggerScanResponse
// @Failure 400 {object} map[string]string "Invalid request"
// @Failure 401 {object} map[string]string "Unauthorized"
// @Failure 403 {object} map[string]string "API is in read-only mode"
// @Failure 404 {object} map[string]string "Digest or repository not found"
// @Failure 500 {object} map[string]string "Internal server error"
// @Security BearerAuth
// @Router /scans/trigger [post]
func (s *APIServer) handleTriggerScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	// Parse request body
	var req TriggerScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.respondError(w, http.StatusBadRequest, fmt.Sprintf("Invalid request body: %v", err))
		return
	}

	// Validate request - must have either digest or repository
	if req.Digest == "" && req.Repository == "" {
		s.respondError(w, http.StatusBadRequest, "Either digest or repository must be specified")
		return
	}

	// If both are specified, digest takes precedence
	if req.Digest != "" && req.Repository != "" {
		s.respondError(w, http.StatusBadRequest, "Cannot specify both digest and repository")
		return
	}

	ctx := r.Context()
	queuedCount := 0
	var taskID string

	if req.Digest != "" {
		// Trigger rescan for specific digest
		// Get the last scan record to retrieve repository and tag info
		lastScan, err := s.stateStore.GetLastScan(ctx, req.Digest)
		if err != nil {
			if errors.Is(err, statestore.ErrScanNotFound) {
				s.respondError(w, http.StatusNotFound, "Digest not found")
				return
			}
			s.respondError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to get scan: %v", err))
			return
		}

		// Load regsync config to get tolerations
		regsyncConfig, err := config.ParseRegsync(s.regsyncPath)
		if err != nil {
			s.respondError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to load regsync config: %v", err))
			return
		}

		// Get tolerations for this repository
		tolerations := regsyncConfig.GetTolerationsForTarget(lastScan.Repository)
		queueTolerations := make([]types.CVEToleration, len(tolerations))
		for i, t := range tolerations {
			queueTolerations[i] = types.CVEToleration{
				ID:        t.ID,
				Statement: t.Statement,
				ExpiresAt: t.ExpiresAt,
			}
		}

		// Create and enqueue task
		task := &queue.ScanTask{
			ID:          fmt.Sprintf("%s-%d", req.Digest, time.Now().Unix()),
			Repository:  lastScan.Repository,
			Digest:      req.Digest,
			Tag:         lastScan.Tag,
			EnqueuedAt:  time.Now(),
			Attempts:    0,
			IsRescan:    true,
			Tolerations: queueTolerations,
		}

		if err := s.taskQueue.Enqueue(ctx, task); err != nil {
			s.respondError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to enqueue task: %v", err))
			return
		}

		queuedCount = 1
		taskID = task.ID
		s.logger.Info("triggered rescan for digest",
			"digest", req.Digest,
			"task_id", taskID)

	} else if req.Repository != "" {
		// Trigger rescan for all images in repository
		// Query all scans for this repository
		filter := statestore.ScanFilter{
			Repository: req.Repository,
			Limit:      1000, // Reasonable limit
		}

		scans, err := s.stateStore.ListScans(ctx, filter)
		if err != nil {
			s.respondError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to list scans: %v", err))
			return
		}

		if len(scans) == 0 {
			s.respondError(w, http.StatusNotFound, "No scans found for repository")
			return
		}

		// Load regsync config to get tolerations
		regsyncConfig, err := config.ParseRegsync(s.regsyncPath)
		if err != nil {
			s.respondError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to load regsync config: %v", err))
			return
		}

		// Get tolerations for this repository
		tolerations := regsyncConfig.GetTolerationsForTarget(req.Repository)
		queueTolerations := make([]types.CVEToleration, len(tolerations))
		for i, t := range tolerations {
			queueTolerations[i] = types.CVEToleration{
				ID:        t.ID,
				Statement: t.Statement,
				ExpiresAt: t.ExpiresAt,
			}
		}

		// Enqueue tasks for all scans
		for _, scan := range scans {
			task := &queue.ScanTask{
				ID:          fmt.Sprintf("%s-%d", scan.Digest, time.Now().Unix()),
				Repository:  scan.Repository,
				Digest:      scan.Digest,
				Tag:         scan.Tag,
				EnqueuedAt:  time.Now(),
				Attempts:    0,
				IsRescan:    true,
				Tolerations: queueTolerations,
			}

			if err := s.taskQueue.Enqueue(ctx, task); err != nil {
				s.logger.Error("failed to enqueue task",
					"digest", scan.Digest,
					"error", err.Error())
				continue
			}

			queuedCount++
		}

		s.logger.Info("triggered rescan for repository",
			"repository", req.Repository,
			"image_count", queuedCount)
	}

	// Return response
	response := TriggerScanResponse{
		Queued: queuedCount,
		TaskID: taskID,
	}

	s.respondJSON(w, http.StatusOK, response)
}

// ReevaluatePolicyRequest represents the request body for policy re-evaluation
type ReevaluatePolicyRequest struct {
	Repository string `json:"repository,omitempty"`
}

// ReevaluatePolicyResponse represents the response for policy re-evaluation
type ReevaluatePolicyResponse struct {
	Queued     int    `json:"queued"`
	Repository string `json:"repository,omitempty"`
}

// handleReevaluatePolicy reloads suppline.yml and re-evaluates policy for all images
// @Summary Re-evaluate policy
// @Description Reload suppline.yml configuration and re-evaluate policy for all images or a specific repository
// @Tags Policy
// @Accept json
// @Produce json
// @Param request body ReevaluatePolicyRequest false "Optional repository filter"
// @Success 200 {object} ReevaluatePolicyResponse
// @Failure 400 {object} map[string]string "Invalid request"
// @Failure 401 {object} map[string]string "Unauthorized"
// @Failure 403 {object} map[string]string "API is in read-only mode"
// @Failure 404 {object} map[string]string "No scans found to re-evaluate"
// @Failure 500 {object} map[string]string "Internal server error"
// @Security BearerAuth
// @Router /policy/reevaluate [post]
func (s *APIServer) handleReevaluatePolicy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	// Parse request body (optional)
	var req ReevaluatePolicyRequest
	if r.Body != nil && r.Body != http.NoBody {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			// Empty body is acceptable, so only error on malformed JSON
			if err.Error() != "EOF" {
				s.respondError(w, http.StatusBadRequest, fmt.Sprintf("Invalid request body: %v", err))
				return
			}
		}
	}

	ctx := r.Context()

	// Reload regsync configuration
	regsyncConfig, err := config.ParseRegsync(s.regsyncPath)
	if err != nil {
		s.respondError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to reload regsync config: %v", err))
		return
	}

	s.logger.Info("reloaded regsync configuration",
		"path", s.regsyncPath)

	// Build scan filter
	filter := statestore.ScanFilter{
		Repository: req.Repository,
		Limit:      1000, // Reasonable limit per query
	}

	// Query scans to re-evaluate
	scans, err := s.stateStore.ListScans(ctx, filter)
	if err != nil {
		s.respondError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to list scans: %v", err))
		return
	}

	if len(scans) == 0 {
		s.respondError(w, http.StatusNotFound, "No scans found to re-evaluate")
		return
	}

	queuedCount := 0

	// Enqueue rescan tasks for all matching images with updated tolerations
	for _, scan := range scans {
		// Get updated tolerations for this repository
		tolerations := regsyncConfig.GetTolerationsForTarget(scan.Repository)
		queueTolerations := make([]types.CVEToleration, len(tolerations))
		for i, t := range tolerations {
			queueTolerations[i] = types.CVEToleration{
				ID:        t.ID,
				Statement: t.Statement,
				ExpiresAt: t.ExpiresAt,
			}
		}

		// Create rescan task with updated tolerations
		task := &queue.ScanTask{
			ID:          fmt.Sprintf("%s-%d", scan.Digest, time.Now().Unix()),
			Repository:  scan.Repository,
			Digest:      scan.Digest,
			Tag:         scan.Tag,
			EnqueuedAt:  time.Now(),
			Attempts:    0,
			IsRescan:    true,
			Tolerations: queueTolerations,
		}

		if err := s.taskQueue.Enqueue(ctx, task); err != nil {
			s.logger.Error("failed to enqueue task for policy re-evaluation",
				"digest", scan.Digest,
				"error", err.Error())
			continue
		}

		queuedCount++
	}

	s.logger.Info("queued images for policy re-evaluation",
		"image_count", queuedCount,
		"repository_filter", req.Repository)

	// Return response
	response := ReevaluatePolicyResponse{
		Queued:     queuedCount,
		Repository: req.Repository,
	}

	s.respondJSON(w, http.StatusOK, response)
}

// handleHealth provides health check endpoint
// @Summary Health check
// @Description Check the health status of the API server
// @Tags Health
// @Produce json
// @Success 200 {object} map[string]string
// @Router /health [get]
func (s *APIServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	// TODO: Implement in task 10 (observability)
	// For now, return basic health status
	s.respondJSON(w, http.StatusOK, map[string]string{
		"status": "healthy",
	})
}

// handleMetrics provides Prometheus metrics endpoint
// @Summary Prometheus metrics
// @Description Expose Prometheus-compatible metrics
// @Tags Health
// @Produce plain
// @Success 200 {string} string "Prometheus metrics"
// @Router /metrics [get]
func (s *APIServer) handleMetrics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	// TODO: Implement in task 10 (observability)
	// For now, return empty metrics
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("# Metrics endpoint - to be implemented\n"))
}

// handleGetPublicKey returns the cosign public key
// @Summary Get cosign public key
// @Description Retrieve the public key used for image signing and attestation verification
// @Tags Integration
// @Produce plain
// @Success 200 {string} string "PEM-encoded public key"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /integration/publickey [get]
func (s *APIServer) handleGetPublicKey(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	// Get public key from integration package
	publicKey, err := integration.GetPublicKeyFromConfig(*s.attestationConfig)
	if err != nil {
		s.logger.Error("failed to extract public key",
			"error", err.Error())
		s.respondError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to extract public key: %v", err))
		return
	}

	// Return the public key as plain text (PEM format)
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(publicKey))
}

// handleGenerateKyvernoPolicy generates a Kyverno ClusterPolicy YAML for SCAI attestation verification
// @Summary Generate Kyverno ClusterPolicy
// @Description Generate a Kyverno ClusterPolicy YAML for verifying SCAI attestations with the configured public key
// @Tags Integration
// @Produce plain
// @Success 200 {string} string "Kyverno ClusterPolicy YAML"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /integration/kyverno/policy [get]
func (s *APIServer) handleGenerateKyvernoPolicy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	// Get public key
	publicKey, err := integration.GetPublicKeyFromConfig(*s.attestationConfig)
	if err != nil {
		s.respondError(w, http.StatusInternalServerError, "Failed to get public key")
		return
	}

	// Generate policy
	policy, err := integration.GenerateKyvernoPolicy(publicKey)
	if err != nil {
		s.respondError(w, http.StatusInternalServerError, "Failed to generate policy")
		return
	}

	// Return YAML
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(policy))
}

// handleListRepositories lists all repositories with aggregated metadata
// @Summary List repositories
// @Description List all repositories with aggregated vulnerability and policy status
// @Tags Repositories
// @Accept json
// @Produce json
// @Param search query string false "Filter by repository name"
// @Param limit query int false "Maximum number of results" default(100)
// @Param offset query int false "Pagination offset" default(0)
// @Success 200 {object} RepositoriesListResponse "List of repositories with aggregated data"
// @Failure 401 {object} map[string]string "Unauthorized"
// @Failure 500 {object} map[string]string "Internal server error"
// @Security BearerAuth
// @Router /repositories [get]
func (s *APIServer) handleListRepositories(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	// Parse query parameters
	filter := statestore.RepositoryFilter{
		Search: parseQueryParam(r, "search"),
		Limit:  parseQueryParamInt(r, "limit", 100),
		Offset: parseQueryParamInt(r, "offset", 0),
	}

	// Get repositories from state store
	response, err := s.stateStore.ListRepositories(r.Context(), filter)
	if err != nil {
		s.respondError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to list repositories: %v", err))
		return
	}

	// Convert to response DTO with ISO8601 timestamps
	responseDTO := toRepositoriesListResponse(response)
	s.respondJSON(w, http.StatusOK, responseDTO)
}

// handleGetRepository retrieves a repository with all its tags
// @Summary Get repository details
// @Description Get a repository with all its tags and their scan results
// @Tags Repositories
// @Accept json
// @Produce json
// @Param name path string true "Repository name"
// @Param search query string false "Filter by tag name"
// @Param limit query int false "Maximum number of results" default(100)
// @Param offset query int false "Pagination offset" default(0)
// @Success 200 {object} statestore.RepositoryDetail
// @Failure 401 {object} map[string]string "Unauthorized"
// @Failure 404 {object} map[string]string "Repository not found"
// @Failure 500 {object} map[string]string "Internal server error"
// @Security BearerAuth
// @Router /repositories/{name} [get]
func (s *APIServer) handleGetRepository(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	// Extract repository name from URL path
	// Path format: /api/v1/repositories/{name}
	path := r.URL.Path
	prefix := "/api/v1/repositories/"
	if !strings.HasPrefix(path, prefix) {
		s.respondError(w, http.StatusBadRequest, "Invalid path")
		return
	}

	name := strings.TrimPrefix(path, prefix)
	if name == "" {
		s.respondError(w, http.StatusBadRequest, "Repository name is required")
		return
	}

	// Parse query parameters
	filter := statestore.RepositoryTagFilter{
		Search: parseQueryParam(r, "search"),
		Limit:  parseQueryParamInt(r, "limit", 100),
		Offset: parseQueryParamInt(r, "offset", 0),
	}

	// Get repository from state store
	detail, err := s.stateStore.GetRepository(r.Context(), name, filter)
	if err != nil {
		s.respondError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to get repository: %v", err))
		return
	}

	// Check if repository exists (has tags)
	if detail.Total == 0 {
		s.respondError(w, http.StatusNotFound, "Repository not found")
		return
	}

	// Convert to response DTO with ISO8601 timestamps
	responseDTO := toRepositoryDetailResponse(detail)
	s.respondJSON(w, http.StatusOK, responseDTO)
}

// handleRescanRepository triggers a rescan for all tags in a repository
// @Summary Rescan repository
// @Description Trigger a rescan for all tags in a repository
// @Tags Repositories
// @Accept json
// @Produce json
// @Param name path string true "Repository name"
// @Success 200 {object} TriggerScanResponse
// @Failure 401 {object} map[string]string "Unauthorized"
// @Failure 403 {object} map[string]string "API is in read-only mode"
// @Failure 404 {object} map[string]string "Repository not found"
// @Failure 500 {object} map[string]string "Internal server error"
// @Security BearerAuth
// @Router /repositories/{name}/rescan [post]
func (s *APIServer) handleRescanRepository(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	// Extract repository name from URL path
	// Path format: /api/v1/repositories/{name}/rescan
	path := r.URL.Path
	prefix := "/api/v1/repositories/"
	suffix := "/rescan"
	if !strings.HasPrefix(path, prefix) || !strings.HasSuffix(path, suffix) {
		s.respondError(w, http.StatusBadRequest, "Invalid path")
		return
	}

	name := strings.TrimPrefix(path, prefix)
	name = strings.TrimSuffix(name, suffix)
	if name == "" {
		s.respondError(w, http.StatusBadRequest, "Repository name is required")
		return
	}

	ctx := r.Context()

	// Query all scans for this repository
	filter := statestore.ScanFilter{
		Repository: name,
		Limit:      1000,
	}

	scans, err := s.stateStore.ListScans(ctx, filter)
	if err != nil {
		s.respondError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to list scans: %v", err))
		return
	}

	if len(scans) == 0 {
		s.respondError(w, http.StatusNotFound, "Repository not found")
		return
	}

	// Load regsync config to get tolerations
	regsyncConfig, err := config.ParseRegsync(s.regsyncPath)
	if err != nil {
		s.respondError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to load regsync config: %v", err))
		return
	}

	// Get tolerations for this repository
	tolerations := regsyncConfig.GetTolerationsForTarget(name)
	queueTolerations := make([]types.CVEToleration, len(tolerations))
	for i, t := range tolerations {
		queueTolerations[i] = types.CVEToleration{
			ID:        t.ID,
			Statement: t.Statement,
			ExpiresAt: t.ExpiresAt,
		}
	}

	// Enqueue tasks for all scans
	queuedCount := 0
	for _, scan := range scans {
		task := &queue.ScanTask{
			ID:          fmt.Sprintf("%s-%d", scan.Digest, time.Now().Unix()),
			Repository:  scan.Repository,
			Digest:      scan.Digest,
			Tag:         scan.Tag,
			EnqueuedAt:  time.Now(),
			Attempts:    0,
			IsRescan:    true,
			Tolerations: queueTolerations,
		}

		if err := s.taskQueue.Enqueue(ctx, task); err != nil {
			s.logger.Error("failed to enqueue task",
				"digest", scan.Digest,
				"error", err.Error())
			continue
		}

		queuedCount++
	}

	s.logger.Info("triggered rescan for repository",
		"repository", name,
		"image_count", queuedCount)

	// Return response
	response := TriggerScanResponse{
		Queued: queuedCount,
	}

	s.respondJSON(w, http.StatusOK, response)
}

// handleRepositoriesRouter routes requests to the appropriate handler based on method and path
func (s *APIServer) handleRepositoriesRouter(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path

	// Check if this is a rescan request
	if strings.Contains(path, "/rescan") {
		if r.Method == http.MethodPost {
			// Check if it's a tag rescan or repository rescan
			if strings.Contains(path, "/tags/") {
				s.handleRescanTag(w, r)
			} else {
				s.handleRescanRepository(w, r)
			}
			return
		}
		s.respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	// Otherwise, it's a GET request for repository detail
	if r.Method == http.MethodGet {
		s.handleGetRepository(w, r)
		return
	}

	s.respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
}

// handleRescanTag triggers a rescan for a specific tag
// @Summary Rescan tag
// @Description Trigger a rescan for a specific tag in a repository
// @Tags Repositories
// @Accept json
// @Produce json
// @Param name path string true "Repository name"
// @Param tag path string true "Tag name"
// @Success 200 {object} TriggerScanResponse
// @Failure 401 {object} map[string]string "Unauthorized"
// @Failure 403 {object} map[string]string "API is in read-only mode"
// @Failure 404 {object} map[string]string "Tag not found"
// @Failure 500 {object} map[string]string "Internal server error"
// @Security BearerAuth
// @Router /repositories/{name}/tags/{tag}/rescan [post]
func (s *APIServer) handleRescanTag(w http.ResponseWriter, r *http.Request) {
	// Extract repository name and tag from URL path
	// Path format: /api/v1/repositories/{name}/tags/{tag}/rescan
	path := r.URL.Path
	prefix := "/api/v1/repositories/"
	suffix := "/rescan"
	if !strings.HasPrefix(path, prefix) || !strings.HasSuffix(path, suffix) {
		s.respondError(w, http.StatusBadRequest, "Invalid path")
		return
	}

	// Remove prefix and suffix
	middle := strings.TrimPrefix(path, prefix)
	middle = strings.TrimSuffix(middle, suffix)

	// Split by /tags/
	parts := strings.Split(middle, "/tags/")
	if len(parts) != 2 {
		s.respondError(w, http.StatusBadRequest, "Invalid path format")
		return
	}

	name := parts[0]
	tag := parts[1]

	if name == "" || tag == "" {
		s.respondError(w, http.StatusBadRequest, "Repository name and tag are required")
		return
	}

	ctx := r.Context()

	// Get repository detail to find the digest for this tag
	detail, err := s.stateStore.GetRepository(ctx, name, statestore.RepositoryTagFilter{
		Search: tag,
		Limit:  1,
	})
	if err != nil {
		s.respondError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to get repository: %v", err))
		return
	}

	if len(detail.Tags) == 0 {
		s.respondError(w, http.StatusNotFound, "Tag not found")
		return
	}

	digest := detail.Tags[0].Digest

	// Get the last scan record to retrieve repository and tag info
	lastScan, err := s.stateStore.GetLastScan(ctx, digest)
	if err != nil {
		if errors.Is(err, statestore.ErrScanNotFound) {
			s.respondError(w, http.StatusNotFound, "Tag not found")
			return
		}
		s.respondError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to get scan: %v", err))
		return
	}

	// Load regsync config to get tolerations
	regsyncConfig, err := config.ParseRegsync(s.regsyncPath)
	if err != nil {
		s.respondError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to load regsync config: %v", err))
		return
	}

	// Get tolerations for this repository
	tolerations := regsyncConfig.GetTolerationsForTarget(lastScan.Repository)
	queueTolerations := make([]types.CVEToleration, len(tolerations))
	for i, t := range tolerations {
		queueTolerations[i] = types.CVEToleration{
			ID:        t.ID,
			Statement: t.Statement,
			ExpiresAt: t.ExpiresAt,
		}
	}

	// Create and enqueue task
	task := &queue.ScanTask{
		ID:          fmt.Sprintf("%s-%d", digest, time.Now().Unix()),
		Repository:  lastScan.Repository,
		Digest:      digest,
		Tag:         lastScan.Tag,
		EnqueuedAt:  time.Now(),
		Attempts:    0,
		IsRescan:    true,
		Tolerations: queueTolerations,
	}

	if err := s.taskQueue.Enqueue(ctx, task); err != nil {
		s.respondError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to enqueue task: %v", err))
		return
	}

	s.logger.Info("triggered rescan for tag",
		"repository", name,
		"tag", tag,
		"digest", digest)

	// Return response
	response := TriggerScanResponse{
		Queued: 1,
		TaskID: task.ID,
	}

	s.respondJSON(w, http.StatusOK, response)
}
