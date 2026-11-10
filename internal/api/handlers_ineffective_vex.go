package api

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/daimoniac/suppline/internal/policy/catalog"
	"github.com/daimoniac/suppline/internal/triage/yamledit"
	"github.com/daimoniac/suppline/internal/types"
)

// IneffectiveVEXStatement is a sync-entry VEX statement that no current policy
// decision depends on.
type IneffectiveVEXStatement struct {
	Repository    string `json:"repository"`
	CVEID         string `json:"cve_id"`
	Source        string `json:"source"`
	State         string `json:"state"`
	Justification string `json:"justification,omitempty"`
	Detail        string `json:"detail,omitempty"`
	ExpiresAt     *int64 `json:"expires_at,omitempty"`
}

// IneffectiveVEXResponse is returned by GET /api/v1/tasks/ineffective-vex.
type IneffectiveVEXResponse struct {
	Statements []IneffectiveVEXStatement `json:"statements"`
	// ComputedAt is the Unix time of the last finished audit; 0 when none has finished.
	ComputedAt int64 `json:"computed_at"`
}

// IneffectiveVEXRef names one statement to remove from a sync entry.
type IneffectiveVEXRef struct {
	Repository string `json:"repository"`
	CVEID      string `json:"cve_id"`
	Source     string `json:"source"`
}

// IneffectiveVEXRemovalRequest is the body of POST /api/v1/tasks/ineffective-vex-removals.
type IneffectiveVEXRemovalRequest struct {
	Statements []IneffectiveVEXRef `json:"statements"`
}

// handleGetIneffectiveVEX lists sync-entry VEX statements with no policy effect.
//
// @Summary     Get ineffective VEX statements
// @Description Lists sync-entry not_affected statements whose removal leaves the pass/fail result of every latest scan unchanged. Results come from a background audit that runs hourly.
// @Tags        Tasks
// @Produce     json
// @Success     200  {object}  IneffectiveVEXResponse
// @Failure     401  {object}  map[string]string  "Unauthorized"
// @Security    BearerAuth
// @Router      /tasks/ineffective-vex [get]
func (s *APIServer) handleGetIneffectiveVEX(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	resp := IneffectiveVEXResponse{Statements: []IneffectiveVEXStatement{}}
	if s.vexAudit != nil {
		findings, computedAt := s.vexAudit.Snapshot()
		for _, finding := range findings {
			resp.Statements = append(resp.Statements, IneffectiveVEXStatement{
				Repository:    finding.Repository,
				CVEID:         finding.CVEID,
				Source:        finding.Source,
				State:         finding.State,
				Justification: finding.Justification,
				Detail:        finding.Detail,
				ExpiresAt:     finding.ExpiresAt,
			})
		}
		if !computedAt.IsZero() {
			resp.ComputedAt = computedAt.Unix()
		}
	}
	s.respondJSON(w, http.StatusOK, resp)
}

// handleRemoveIneffectiveVEX deletes the given statements from their sync entries.
//
// @Summary     Remove ineffective VEX statements
// @Description Deletes each statement from the sync entry of its repository only, leaving defaults and other repositories untouched. Commits the config repository when one is configured.
// @Tags        Tasks
// @Accept      json
// @Produce     json
// @Param       request  body      IneffectiveVEXRemovalRequest  true  "Statements to remove"
// @Success     200      {object}  ConfigEditResult
// @Failure     400      {object}  map[string]string
// @Failure     409      {object}  map[string]string
// @Security    BearerAuth
// @Router      /tasks/ineffective-vex-removals [post]
func (s *APIServer) handleRemoveIneffectiveVEX(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	var req IneffectiveVEXRemovalRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	refs := make([]IneffectiveVEXRef, 0, len(req.Statements))
	for _, statement := range req.Statements {
		ref := IneffectiveVEXRef{
			Repository: strings.TrimSpace(statement.Repository),
			CVEID:      strings.TrimSpace(statement.CVEID),
			Source:     strings.TrimSpace(statement.Source),
		}
		if ref.Repository == "" || ref.CVEID == "" {
			s.respondError(w, http.StatusBadRequest, "each statement needs a repository and cve_id")
			return
		}
		if ref.Source != types.VEXSourceManual && ref.Source != types.VEXSourceAuto {
			s.respondError(w, http.StatusBadRequest, "source must be x-vex or x-vex-auto")
			return
		}
		refs = append(refs, ref)
	}
	if len(refs) == 0 {
		s.respondError(w, http.StatusBadRequest, "no statements to remove")
		return
	}

	yamlRefs := make([]yamledit.SyncVEXRef, 0, len(refs))
	catRefs := make([]catalog.EntryVEXRef, 0, len(refs))
	for _, ref := range refs {
		yamlRefs = append(yamlRefs, yamledit.SyncVEXRef{Repository: ref.Repository, ID: ref.CVEID, Source: ref.Source})
		catRefs = append(catRefs, catalog.EntryVEXRef{Repository: ref.Repository, ID: ref.CVEID, Source: ref.Source})
	}
	s.applyConfigEdit(w, r, "chore(config): remove VEX statements without policy effect [skip ci]", func(current []byte) ([]byte, int, error) {
		return yamledit.RemoveSyncVEXStatements(current, yamlRefs)
	}, func(cat *catalog.ConfigCatalog) (int, error) {
		return cat.RemoveEntryVEX(catRefs)
	}, func() {
		if s.vexAudit == nil {
			return
		}
		for _, ref := range refs {
			s.vexAudit.Forget(ref.Repository, ref.CVEID, ref.Source)
		}
	})
}
