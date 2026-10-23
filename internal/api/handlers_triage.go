package api

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/daimoniac/suppline/internal/statestore"
	"github.com/daimoniac/suppline/internal/types"
	"github.com/daimoniac/suppline/internal/worker"
)

// TriageRunResponse is one stored triage decision.
type TriageRunResponse struct {
	ID            int64           `json:"ID"`
	Repository    string          `json:"Repository"`
	CVEID         string          `json:"CVEID"`
	Verdict       string          `json:"Verdict"`
	Justification string          `json:"Justification,omitempty"`
	Confidence    float64         `json:"Confidence"`
	Evidence      json.RawMessage `json:"Evidence,omitempty"`
	Reasoning     string          `json:"Reasoning,omitempty"`
	Model         string          `json:"Model,omitempty"`
	RepoSHAs      json.RawMessage `json:"RepoSHAs,omitempty"`
	Tokens        int             `json:"Tokens"`
	Status        string          `json:"Status"`
	CommitSHA     string          `json:"CommitSHA,omitempty"`
	CreatedAt     int64           `json:"CreatedAt"`
	Superseded    bool            `json:"Superseded"`
}

// handleListTriage lists automated triage decisions.
// @Summary List triage runs
// @Description List automated VEX triage decisions. Filter by repository, CVE, or status.
// @Tags Triage
// @Produce json
// @Param repository query string false "Repository name"
// @Param cve query string false "CVE ID"
// @Param status query string false "dry_run, committed, written, push_failed, rejected_by_guardrail, or error"
// @Success 200 {array} TriageRunResponse
// @Failure 401 {object} map[string]string "Unauthorized"
// @Failure 500 {object} map[string]string "Internal server error"
// @Security BearerAuth
// @Router /triage [get]
func (s *APIServer) handleListTriage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	store, ok := s.stateStore.(statestore.TriageStore)
	if !ok {
		s.respondError(w, http.StatusNotImplemented, "triage store is not available")
		return
	}
	runs, err := store.ListTriageRuns(r.Context(), statestore.TriageFilter{
		Repository: r.URL.Query().Get("repository"),
		CVEID:      r.URL.Query().Get("cve"),
		Status:     r.URL.Query().Get("status"),
		Limit:      parseQueryParamInt(r, "limit", 200),
	})
	if err != nil {
		s.respondError(w, http.StatusInternalServerError, "Failed to list triage runs")
		s.logger.Error("list triage runs", "error", err)
		return
	}
	latest := map[string]int64{}
	for _, run := range runs {
		key := run.Repository + "\n" + run.CVEID
		if _, ok := latest[key]; !ok {
			latest[key] = run.ID
		}
	}
	response := make([]TriageRunResponse, 0, len(runs))
	for _, run := range runs {
		item := TriageRunResponse{
			ID:            run.ID,
			Repository:    run.Repository,
			CVEID:         run.CVEID,
			Verdict:       run.Verdict,
			Justification: run.Justification,
			Confidence:    run.Confidence,
			Reasoning:     run.Reasoning,
			Model:         run.Model,
			Tokens:        run.Tokens,
			Status:        run.Status,
			CommitSHA:     run.CommitSHA,
			CreatedAt:     run.CreatedAt.Unix(),
			Superseded:    latest[run.Repository+"\n"+run.CVEID] != run.ID,
		}
		if run.EvidenceJSON != "" {
			item.Evidence = json.RawMessage(run.EvidenceJSON)
		}
		if run.RepoSHAsJSON != "" {
			item.RepoSHAs = json.RawMessage(run.RepoSHAsJSON)
		}
		response = append(response, item)
	}
	s.respondJSON(w, http.StatusOK, response)
}

// TriageStatusResponse describes whether triage can accept work.
type TriageStatusResponse struct {
	Enabled   bool                   `json:"Enabled"`
	Mode      string                 `json:"Mode,omitempty"`
	OnlyInUse bool                   `json:"OnlyInUse"`
	Pending   int                    `json:"Pending"`
	Active    []TriageActiveResponse `json:"Active"`
}

// TriageActiveResponse is one job waiting or in flight.
type TriageActiveResponse struct {
	Repository string `json:"Repository"`
	CVEID      string `json:"CVEID"`
	Image      string `json:"Image,omitempty"`
}

// TriageRunRequest selects the failed images to queue.
type TriageRunRequest struct {
	Images []TriageRunImage `json:"Images"`
}

// TriageRunImage is one scan the UI is showing.
type TriageRunImage struct {
	Repository string `json:"Repository"`
	Digest     string `json:"Digest"`
	Tag        string `json:"Tag"`
}

// TriageRunResult is how many findings were queued.
type TriageRunResult struct {
	Queued int `json:"Queued"`
}

// GitopsRepoResponse is one configured gitops checkout.
type GitopsRepoResponse struct {
	Name            string   `json:"Name"`
	URL             string   `json:"URL"`
	Branch          string   `json:"Branch,omitempty"`
	Roles           []string `json:"Roles"`
	Cloned          bool     `json:"Cloned"`
	HeadSHA         string   `json:"HeadSHA,omitempty"`
	HeadAt          int64    `json:"HeadAt,omitempty"`
	LastSupplineSHA string   `json:"LastSupplineSHA,omitempty"`
	LastSupplineAt  int64    `json:"LastSupplineAt,omitempty"`
}

// handleTriageStatus reports whether x-triage is accepting work.
// @Summary Triage status
// @Description Reports whether triage is enabled, its mode, and how many jobs are waiting.
// @Tags Triage
// @Produce json
// @Success 200 {object} TriageStatusResponse
// @Security BearerAuth
// @Router /triage/status [get]
func (s *APIServer) handleTriageStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	response := TriageStatusResponse{OnlyInUse: true, Active: []TriageActiveResponse{}}
	if s.triageService != nil {
		response.Enabled = s.triageService.Enabled()
		response.Mode = s.triageService.Mode()
		response.OnlyInUse = s.triageService.OnlyInUse()
		response.Pending = s.triageService.Pending()
		for _, job := range s.triageService.Active() {
			response.Active = append(response.Active, TriageActiveResponse{
				Repository: job.Repository,
				CVEID:      job.CVEID,
				Image:      job.Image,
			})
		}
	}
	s.respondJSON(w, http.StatusOK, response)
}

// handleTriageRun queues triage for the failed images in the request.
// @Summary Queue triage
// @Description Queue triage for the listed policy-failed images. Cached decisions are run again.
// @Tags Triage
// @Accept json
// @Produce json
// @Param request body TriageRunRequest true "Images to triage"
// @Success 200 {object} TriageRunResult
// @Failure 400 {object} map[string]string "Invalid request"
// @Failure 409 {object} map[string]string "Triage is not enabled"
// @Security BearerAuth
// @Router /triage/run [post]
func (s *APIServer) handleTriageRun(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	if s.triageService == nil || !s.triageService.Enabled() {
		s.respondError(w, http.StatusConflict, "triage is not enabled")
		return
	}
	var body TriageRunRequest
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	if err := decoder.Decode(&body); err != nil {
		s.respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	if len(body.Images) == 0 || len(body.Images) > 500 {
		s.respondError(w, http.StatusBadRequest, "Images must contain between 1 and 500 entries")
		return
	}
	records, err := s.stateStore.ListScans(r.Context(), statestore.ScanFilter{PolicyStatus: "failed"})
	if err != nil {
		s.respondError(w, http.StatusInternalServerError, "Failed to list policy failures")
		s.logger.Error("triage run list scans", "error", err)
		return
	}
	byKey := make(map[string]*statestore.ScanRecord, len(records))
	for _, record := range records {
		byKey[triageImageKey(record.Repository, record.Digest, record.Tag)] = record
	}
	queued := 0
	for _, image := range body.Images {
		record := byKey[triageImageKey(image.Repository, image.Digest, image.Tag)]
		if record == nil {
			continue
		}
		queued += s.triageService.QueuePolicyFailure(r.Context(), noticeFromScan(record))
	}
	s.respondJSON(w, http.StatusOK, TriageRunResult{Queued: queued})
}

// handleGitopsStatus lists configured gitops checkouts and the last suppline commit.
// @Summary Gitops repositories
// @Description Local checkout HEAD and the last commit written by triage.
// @Tags Integration
// @Produce json
// @Success 200 {array} GitopsRepoResponse
// @Security BearerAuth
// @Router /integration/gitops [get]
func (s *APIServer) handleGitopsStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	if s.triageService == nil {
		s.respondJSON(w, http.StatusOK, []GitopsRepoResponse{})
		return
	}
	repos, err := s.triageService.GitopsStatus(r.Context())
	if err != nil {
		s.respondError(w, http.StatusInternalServerError, "Failed to read gitops checkouts")
		s.logger.Error("gitops status", "error", err)
		return
	}
	response := make([]GitopsRepoResponse, 0, len(repos))
	for _, repo := range repos {
		item := GitopsRepoResponse{
			Name:            repo.Name,
			URL:             repo.URL,
			Branch:          repo.Branch,
			Roles:           repo.Roles,
			Cloned:          repo.Cloned,
			HeadSHA:         repo.HeadSHA,
			LastSupplineSHA: repo.LastSupplineSHA,
		}
		if !repo.HeadAt.IsZero() {
			item.HeadAt = repo.HeadAt.Unix()
		}
		if !repo.LastSupplineAt.IsZero() {
			item.LastSupplineAt = repo.LastSupplineAt.Unix()
		}
		response = append(response, item)
	}
	s.respondJSON(w, http.StatusOK, response)
}

// TriageAcceptRequest is a human override of one triage decision.
type TriageAcceptRequest struct {
	Repository    string `json:"Repository"`
	CVEID         string `json:"CVEID"`
	State         string `json:"State"`
	Justification string `json:"Justification,omitempty"`
	Detail        string `json:"Detail,omitempty"`
	ExpiresAt     int64  `json:"ExpiresAt,omitempty"`
}

// TriageAcceptResult is the commit created for a hand-written x-vex statement.
type TriageAcceptResult struct {
	CommitSHA string `json:"CommitSHA,omitempty"`
}

// handleTriageAccept writes the edited decision into x-vex.
// @Summary Accept a triage decision into x-vex
// @Description Writes a hand-written x-vex statement. It overrides x-vex-auto for the same id.
// @Tags Triage
// @Accept json
// @Produce json
// @Param request body TriageAcceptRequest true "Statement to write"
// @Success 200 {object} TriageAcceptResult
// @Failure 400 {object} map[string]string "Invalid request"
// @Failure 409 {object} map[string]string "Triage is not enabled"
// @Security BearerAuth
// @Router /triage/accept [post]
func (s *APIServer) handleTriageAccept(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	if s.triageService == nil || !s.triageService.Enabled() {
		s.respondError(w, http.StatusConflict, "triage is not enabled")
		return
	}
	var body TriageAcceptRequest
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	if err := decoder.Decode(&body); err != nil {
		s.respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	statement := types.VEXStatement{
		ID:            strings.TrimSpace(body.CVEID),
		State:         types.VEXAnalysisState(strings.TrimSpace(body.State)),
		Justification: types.VEXJustification(strings.TrimSpace(body.Justification)),
		Detail:        strings.TrimSpace(body.Detail),
	}
	if body.ExpiresAt > 0 {
		expires := body.ExpiresAt
		statement.ExpiresAt = &expires
	}
	commit, err := s.triageService.PromoteManual(r.Context(), body.Repository, statement)
	if err != nil {
		s.respondError(w, http.StatusBadRequest, err.Error())
		s.logger.Error("accept triage into x-vex", "repository", body.Repository, "cve", body.CVEID, "error", err)
		return
	}
	s.respondJSON(w, http.StatusOK, TriageAcceptResult{CommitSHA: commit})
}

func triageImageKey(repository, digest, tag string) string {
	return strings.TrimSpace(repository) + "\n" + strings.TrimSpace(digest) + "\n" + strings.TrimSpace(tag)
}

func noticeFromScan(record *statestore.ScanRecord) worker.PolicyFailureNotice {
	vulns := make([]types.Vulnerability, 0, len(record.Vulnerabilities))
	for _, vuln := range record.Vulnerabilities {
		vulns = append(vulns, types.Vulnerability{
			ID:           vuln.CVEID,
			Severity:     vuln.Severity,
			PackageName:  vuln.PackageName,
			Version:      vuln.InstalledVersion,
			FixedVersion: vuln.FixedVersion,
			Title:        vuln.Title,
			Description:  vuln.Description,
			PrimaryURL:   vuln.PrimaryURL,
		})
	}
	return worker.PolicyFailureNotice{
		Repository:      record.Repository,
		Digest:          record.Digest,
		Tag:             record.Tag,
		Findings:        record.PolicyFailureFindings,
		Vulnerabilities: vulns,
	}
}
