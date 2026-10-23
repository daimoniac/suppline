package api

import (
	"encoding/json"
	"net/http"

	"github.com/daimoniac/suppline/internal/statestore"
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
