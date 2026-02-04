package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

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

	// Enrich with current tolerations from config instead of stale DB values
	s.enrichScanRecord(record)

	s.respondJSON(w, http.StatusOK, record)
}

// handleListScans lists scan records with optional filters
// @Summary List scans
// @Description List all scans with optional filtering and pagination
// @Tags Scans
// @Accept json
// @Produce json
// @Param repository query string false "Filter by repository name"
// @Param policy_passed query boolean false "Filter by policy status"
// @Param max_age query int false "Maximum age of scans in seconds (e.g., 86400 for last 24 hours)"
// @Param sort_by query string false "Sort order: age_desc (default)" Enums(age_desc)
// @Param limit query int false "Maximum number of results" default(100)
// @Param offset query int false "Pagination offset" default(0)
// @Success 200 {array} statestore.ScanRecord
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
		MaxAge:       parseQueryParamInt(r, "max_age", 0),
		SortBy:       parseQueryParam(r, "sort_by"),
		Limit:        parseQueryParamInt(r, "limit", 100),
		Offset:       parseQueryParamInt(r, "offset", 0),
	}

	// Get scans from state store
	records, err := s.stateStore.ListScans(r.Context(), filter)
	if err != nil {
		s.respondError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to list scans: %v", err))
		return
	}

	// Enrich each record with current tolerations from config
	for _, record := range records {
		s.enrichScanRecord(record)
	}

	// Stream JSON response to avoid buffering large payloads
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	encoder := json.NewEncoder(w)
	if err := encoder.Encode(records); err != nil {
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
// @Success 200 {array} types.VulnerabilityRecord
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

	// Stream JSON response to avoid buffering large payloads
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	encoder := json.NewEncoder(w)
	if err := encoder.Encode(vulnerabilities); err != nil {
		s.logger.Error("error encoding JSON response",
			"error", err.Error())
	}
}

// handleListUnappliedTolerations lists tolerations defined in config but not applied to any digests
// @Summary List unapplied tolerations
// @Description List all CVE tolerations defined in configuration that have never been applied to any digest. Returns CVE IDs grouped by repository.
// @Tags Tolerations
// @Accept json
// @Produce json
// @Success 200 {array} types.TolerationSummary
// @Failure 401 {object} map[string]string "Unauthorized"
// @Failure 500 {object} map[string]string "Internal server error"
// @Security BearerAuth
// @Router /tolerations/unapplied [get]
func (s *APIServer) handleListUnappliedTolerations(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	if s.regsyncConfig == nil {
		s.respondJSON(w, http.StatusOK, []types.TolerationSummary{})
		return
	}

	ctx := r.Context()

	// Collect all defined CVE IDs from configuration per repository
	repoTolerations := make(map[string]map[string]*types.TolerationSummary)

	// Get all target repositories from config
	repositories := s.regsyncConfig.GetTargetRepositories()

	for _, repo := range repositories {
		// Get tolerations for this repository
		configTolerations := s.regsyncConfig.GetTolerationsForTarget(repo)

		for _, toleration := range configTolerations {
			if _, exists := repoTolerations[repo]; !exists {
				repoTolerations[repo] = make(map[string]*types.TolerationSummary)
			}
			if _, exists := repoTolerations[repo][toleration.ID]; !exists {
				repoTolerations[repo][toleration.ID] = &types.TolerationSummary{
					CVEID:     toleration.ID,
					Statement: toleration.Statement,
					ExpiresAt: toleration.ExpiresAt,
					Repositories: []types.RepositoryTolInfo{
						{Repository: repo, ToleratedAt: 0},
					},
				}
			}
		}
	}

	// Flatten to get all unique CVE IDs
	definedCVEIDs := make(map[string]bool)
	for _, cveMap := range repoTolerations {
		for cveID := range cveMap {
			definedCVEIDs[cveID] = true
		}
	}

	// Convert to slice for query
	cveIDSlice := make([]string, 0, len(definedCVEIDs))
	for cveID := range definedCVEIDs {
		cveIDSlice = append(cveIDSlice, cveID)
	}

	// Query state store to find which CVE IDs have been applied
	appliedCVEs, err := s.stateStore.GetAppliedCVEIDs(ctx, cveIDSlice)
	if err != nil {
		s.respondError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to get applied CVE IDs: %v", err))
		return
	}

	// Build set of applied CVE IDs for quick lookup
	appliedSet := make(map[string]bool)
	for _, cveID := range appliedCVEs {
		appliedSet[cveID] = true
	}

	// Filter to only include unapplied tolerations and group by CVE ID
	grouped := make(map[string]*types.TolerationSummary)
	for repo, cveMap := range repoTolerations {
		for cveID, summary := range cveMap {
			// Skip if this CVE has been applied
			if appliedSet[cveID] {
				continue
			}

			// Add to grouped result
			if existing, exists := grouped[cveID]; exists {
				// Add repository to existing entry
				existing.Repositories = append(existing.Repositories, types.RepositoryTolInfo{
					Repository:  repo,
					ToleratedAt: 0,
				})
			} else {
				// Create new entry
				grouped[cveID] = &types.TolerationSummary{
					CVEID:     summary.CVEID,
					Statement: summary.Statement,
					ExpiresAt: summary.ExpiresAt,
					Repositories: []types.RepositoryTolInfo{
						{Repository: repo, ToleratedAt: 0},
					},
				}
			}
		}
	}

	// Convert map to slice
	result := make([]*types.TolerationSummary, 0, len(grouped))
	for _, summary := range grouped {
		result = append(result, summary)
	}

	// Stream JSON response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	encoder := json.NewEncoder(w)
	if err := encoder.Encode(result); err != nil {
		s.logger.Error("error encoding JSON response",
			"error", err.Error())
	}
}

// handleListTolerations lists tolerated CVEs with optional filters
// @Summary List tolerations
// @Description List all CVE tolerations as defined in the configuration file. Groups by CVE ID with repositories array.
// @Tags Tolerations
// @Accept json
// @Produce json
// @Param cve_id query string false "Filter by CVE ID"
// @Param repository query string false "Filter by repository name"
// @Success 200 {array} types.TolerationSummary
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
	cveIDFilter := parseQueryParam(r, "cve_id")
	repositoryFilter := parseQueryParam(r, "repository")

	// Get all configured tolerations from config
	tolerations := s.getConfiguredTolerations(cveIDFilter, repositoryFilter)

	// Get historical application timestamps from state store
	s.enrichWithHistoricalTimestamps(r.Context(), tolerations)

	// Group tolerations by CVE ID
	grouped := s.groupTolerationsByCVE(tolerations)

	// Stream JSON response to avoid buffering large payloads
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	encoder := json.NewEncoder(w)
	if err := encoder.Encode(grouped); err != nil {
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
// @Success 200 {array} statestore.ScanRecord
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

	// Stream JSON response to avoid buffering large payloads
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	encoder := json.NewEncoder(w)
	if err := encoder.Encode(records); err != nil {
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
		// Get tolerations for this repository from in-memory config
		tolerations := s.regsyncConfig.GetTolerationsForTarget(lastScan.Repository)
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

		// Get tolerations for this repository from in-memory config
		tolerations := s.regsyncConfig.GetTolerationsForTarget(req.Repository)
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

	s.logger.Info("reprocessing scans with current regsync configuration")

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
		// Get updated tolerations for this repository from in-memory config
		tolerations := s.regsyncConfig.GetTolerationsForTarget(scan.Repository)
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
// @Param max_age query int false "Maximum age of last scan in seconds (e.g., 86400 for last 24 hours)"
// @Param sort_by query string false "Sort order: age_desc (default), age_asc, name_asc, name_desc, status_asc, status_desc" Enums(age_desc,age_asc,name_asc,name_desc,status_asc,status_desc)
// @Param limit query int false "Maximum number of results" default(100)
// @Param offset query int false "Pagination offset" default(0)
// @Success 200 {object} map[string]interface{} "List of repositories with aggregated data"
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
		MaxAge: parseQueryParamInt(r, "max_age", 0),
		SortBy: parseQueryParam(r, "sort_by"),
		Limit:  parseQueryParamInt(r, "limit", 100),
		Offset: parseQueryParamInt(r, "offset", 0),
	}

	// Get repositories from state store
	response, err := s.stateStore.ListRepositories(r.Context(), filter)
	if err != nil {
		s.respondError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to list repositories: %v", err))
		return
	}

	s.respondJSON(w, http.StatusOK, response)
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

	s.respondJSON(w, http.StatusOK, detail)
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

	// Get tolerations for this repository from in-memory config
	tolerations := s.regsyncConfig.GetTolerationsForTarget(name)
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

	// Get tolerations for this repository from in-memory config
	tolerations := s.regsyncConfig.GetTolerationsForTarget(lastScan.Repository)
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

// enrichScanRecord updates a scan record's tolerated CVEs with current config values
// Preserves ToleratedAt timestamps while using current Statement and ExpiresAt from config
func (s *APIServer) enrichScanRecord(record *statestore.ScanRecord) {
	if record == nil || s.regsyncConfig == nil {
		return
	}

	// Build map of historically tolerated CVEs (cveID -> toleratedAt timestamp)
	historicalMap := make(map[string]int64)
	for _, stored := range record.ToleratedCVEs {
		historicalMap[stored.CVEID] = stored.ToleratedAt
	}

	// Get current config and rebuild toleration list
	configTolerations := s.regsyncConfig.GetTolerationsForTarget(record.Repository)
	record.ToleratedCVEs = make([]types.ToleratedCVE, 0, len(historicalMap))

	for _, configTol := range configTolerations {
		if toleratedAt, wasHistoricallyTolerated := historicalMap[configTol.ID]; wasHistoricallyTolerated {
			record.ToleratedCVEs = append(record.ToleratedCVEs, types.ToleratedCVE{
				CVEID:       configTol.ID,
				Statement:   configTol.Statement, // Current from config
				ToleratedAt: toleratedAt,         // Historical timestamp (audit trail)
				ExpiresAt:   configTol.ExpiresAt, // Current from config
			})
		}
	}
}

// getConfiguredTolerations returns all tolerations from config file
// Returns all configured tolerations for each target repository, optionally filtered by CVE ID and/or repository
func (s *APIServer) getConfiguredTolerations(cveIDFilter, repositoryFilter string) []*types.TolerationInfo {
	if s.regsyncConfig == nil {
		return []*types.TolerationInfo{}
	}

	tolerationMap := make(map[string]*types.TolerationInfo)

	// Get all target repositories from config
	repositories := s.regsyncConfig.GetTargetRepositories()

	for _, repo := range repositories {
		// Apply repository filter if specified
		if repositoryFilter != "" && repo != repositoryFilter {
			continue
		}

		// Get tolerations for this repository
		configTolerations := s.regsyncConfig.GetTolerationsForTarget(repo)

		for i := range configTolerations {
			// Apply CVE ID filter if specified
			if cveIDFilter != "" && configTolerations[i].ID != cveIDFilter {
				continue
			}

			key := repo + ":" + configTolerations[i].ID

			// Only add if not already present (avoid duplicates from overlapping defaults and sync-specific)
			if _, exists := tolerationMap[key]; !exists {
				tolerationMap[key] = &types.TolerationInfo{
					CVEID:       configTolerations[i].ID,
					Statement:   configTolerations[i].Statement,
					ToleratedAt: 0, // Will be enriched with historical data if available
					ExpiresAt:   configTolerations[i].ExpiresAt,
					Repository:  repo,
				}
			}
		}
	}

	// Convert map to slice
	result := make([]*types.TolerationInfo, 0, len(tolerationMap))
	for _, info := range tolerationMap {
		result = append(result, info)
	}

	return result
}

// enrichWithHistoricalTimestamps updates tolerations with earliest ToleratedAt timestamps from scan history
// Only updates ToleratedAt if the toleration was actually applied in a past scan
func (s *APIServer) enrichWithHistoricalTimestamps(ctx context.Context, tolerations []*types.TolerationInfo) {
	if s.stateStore == nil || len(tolerations) == 0 {
		return
	}

	// Query historical tolerations from state store to get ToleratedAt timestamps
	filter := statestore.TolerationFilter{
		Limit: 0, // No limit, get all historical records
	}

	historicalTolerations, err := s.stateStore.ListTolerations(ctx, filter)
	if err != nil {
		s.logger.Error("failed to get historical tolerations",
			"error", err.Error())
		return
	}

	// Build a map of historical timestamps: "repo:cveid" -> earliest ToleratedAt
	historicalMap := make(map[string]int64)
	for _, hist := range historicalTolerations {
		key := hist.Repository + ":" + hist.CVEID
		if existing, found := historicalMap[key]; !found || hist.ToleratedAt < existing {
			historicalMap[key] = hist.ToleratedAt
		}
	}

	// Update tolerations with historical timestamps
	for _, tol := range tolerations {
		key := tol.Repository + ":" + tol.CVEID
		if toleratedAt, found := historicalMap[key]; found {
			tol.ToleratedAt = toleratedAt
		}
	}
}

// groupTolerationsByCVE groups tolerations by CVE ID, collecting repositories into an array
func (s *APIServer) groupTolerationsByCVE(tolerations []*types.TolerationInfo) []*types.TolerationSummary {
	// Group by CVE ID
	grouped := make(map[string]*types.TolerationSummary)

	for _, tol := range tolerations {
		summary, exists := grouped[tol.CVEID]
		if !exists {
			summary = &types.TolerationSummary{
				CVEID:        tol.CVEID,
				Statement:    tol.Statement,
				ExpiresAt:    tol.ExpiresAt,
				Repositories: make([]types.RepositoryTolInfo, 0),
			}
			grouped[tol.CVEID] = summary
		}

		// Add repository info
		summary.Repositories = append(summary.Repositories, types.RepositoryTolInfo{
			Repository:  tol.Repository,
			ToleratedAt: tol.ToleratedAt,
		})
	}

	// Convert map to slice
	result := make([]*types.TolerationSummary, 0, len(grouped))
	for _, summary := range grouped {
		result = append(result, summary)
	}

	return result
}
