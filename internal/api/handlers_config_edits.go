package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/daimoniac/suppline/internal/gitops"
	"github.com/daimoniac/suppline/internal/policy/catalog"
	"github.com/daimoniac/suppline/internal/statestore"
	"github.com/daimoniac/suppline/internal/triage/yamledit"
)

// ConfigEditStatus is returned by GET /api/v1/tasks/config-edits.
type ConfigEditStatus struct {
	Available bool   `json:"available"`
	Mode      string `json:"mode"`
	Detail    string `json:"detail,omitempty"`
}

// ConfigEditResult is returned after a config edit is written.
type ConfigEditResult struct {
	Mode    string `json:"mode"`
	Commit  string `json:"commit,omitempty"`
	Updated int    `json:"updated"`
}

type semverApplyRequest struct {
	Updates []semverApplyUpdate `json:"updates"`
}

type semverApplyUpdate struct {
	Target string   `json:"target"`
	Ranges []string `json:"ranges"`
}

type syncRemovalRequest struct {
	Targets []string `json:"targets"`
}

type vexRemovalRequest struct {
	IDs []string `json:"ids"`
}

// handleConfigEditStatus reports whether tasks can edit suppline.yaml directly.
//
// @Summary     Config edit availability
// @Description Reports whether semver, sync, and VEX task fixes can update suppline.yaml, either by committing the configured config repository or by writing the local file.
// @Tags        Tasks
// @Produce     json
// @Success     200  {object}  ConfigEditStatus
// @Security    BearerAuth
// @Router      /tasks/config-edits [get]
func (s *APIServer) handleConfigEditStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	s.respondJSON(w, http.StatusOK, s.configEditStatus())
}

func (s *APIServer) configEditStatus() ConfigEditStatus {
	if s.config != nil && s.config.ReadOnly {
		return ConfigEditStatus{Mode: "unavailable", Detail: "API is in read-only mode."}
	}
	if s.triageService == nil {
		return ConfigEditStatus{Mode: "unavailable", Detail: "Config editing is unavailable."}
	}
	mode, err := s.triageService.ConfigWriteMode()
	if err != nil {
		return ConfigEditStatus{Mode: "unavailable", Detail: err.Error()}
	}
	switch mode {
	case "git":
		return ConfigEditStatus{Available: true, Mode: mode, Detail: "Changes are committed to the configured config repository."}
	case "local":
		return ConfigEditStatus{Available: true, Mode: mode, Detail: "Changes are written to the local suppline config file."}
	default:
		return ConfigEditStatus{Mode: "unavailable", Detail: "Config editing is unavailable."}
	}
}

func (s *APIServer) handleSemverUpdateTasks(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.handleGetSemverUpdateTasks(w, r)
	case http.MethodPost:
		s.handleApplySemverUpdates(w, r)
	default:
		s.respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
	}
}

// handleApplySemverUpdates writes suggested semver ranges into suppline.yaml.
//
// @Summary     Apply semver range updates
// @Description Replaces tags.semverRange on the matching sync entries and commits the config repository when one is configured.
// @Tags        Tasks
// @Accept      json
// @Produce     json
// @Param       request  body      semverApplyRequest  true  "Ranges to write"
// @Success     200      {object}  ConfigEditResult
// @Failure     400      {object}  map[string]string
// @Failure     409      {object}  map[string]string
// @Security    BearerAuth
// @Router      /tasks/semver-updates [post]
func (s *APIServer) handleApplySemverUpdates(w http.ResponseWriter, r *http.Request) {
	var req semverApplyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	updates := make([]yamledit.SemverRangeUpdate, 0, len(req.Updates))
	for _, update := range req.Updates {
		updates = append(updates, yamledit.SemverRangeUpdate{Target: strings.TrimSpace(update.Target), Ranges: update.Ranges})
	}
	s.applyConfigEdit(w, r, "chore(config): update semver ranges [skip ci]", func(current []byte) ([]byte, int, error) {
		return yamledit.SetSemverRanges(current, updates)
	}, func(cat *catalog.ConfigCatalog) (int, error) {
		total := 0
		for _, update := range updates {
			n, err := cat.SetSemverRanges(update.Target, update.Ranges)
			if err != nil {
				return total, err
			}
			total += n
		}
		return total, nil
	}, nil)
}

// handleRemoveSyncTargets deletes unused sync entries from suppline.yaml.
//
// @Summary     Remove unused sync repositories
// @Description Deletes sync entries for the given targets and commits the config repository when one is configured.
// @Tags        Tasks
// @Accept      json
// @Produce     json
// @Param       request  body      syncRemovalRequest  true  "Targets to remove"
// @Success     200      {object}  ConfigEditResult
// @Failure     400      {object}  map[string]string
// @Failure     409      {object}  map[string]string
// @Security    BearerAuth
// @Router      /tasks/sync-removals [post]
func (s *APIServer) handleRemoveSyncTargets(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	var req syncRemovalRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	targets := trimStrings(req.Targets)
	s.applyConfigEdit(w, r, "chore(config): remove unused sync repositories [skip ci]", func(current []byte) ([]byte, int, error) {
		return yamledit.RemoveSyncTargets(current, targets)
	}, func(cat *catalog.ConfigCatalog) (int, error) {
		return cat.RemoveSyncTargets(targets)
	}, func() {
		s.cleanupRemovedRepositories(r.Context(), targets)
	})
}

// handleRemoveVEXStatements deletes unused VEX statements from suppline.yaml.
//
// @Summary     Remove unused VEX statements
// @Description Deletes x-vex and x-vex-auto statements with the given ids and commits the config repository when one is configured.
// @Tags        Tasks
// @Accept      json
// @Produce     json
// @Param       request  body      vexRemovalRequest  true  "Statement ids to remove"
// @Success     200      {object}  ConfigEditResult
// @Failure     400      {object}  map[string]string
// @Failure     409      {object}  map[string]string
// @Security    BearerAuth
// @Router      /tasks/vex-removals [post]
func (s *APIServer) handleRemoveVEXStatements(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	var req vexRemovalRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	ids := trimStrings(req.IDs)
	s.applyConfigEdit(w, r, "chore(config): remove unused VEX statements [skip ci]", func(current []byte) ([]byte, int, error) {
		return yamledit.RemoveVEXStatements(current, ids)
	}, func(cat *catalog.ConfigCatalog) (int, error) {
		return cat.RemoveVEXIDs(ids)
	}, nil)
}

func (s *APIServer) applyConfigEdit(
	w http.ResponseWriter,
	r *http.Request,
	message string,
	mutate func([]byte) ([]byte, int, error),
	applyMemory func(*catalog.ConfigCatalog) (int, error),
	after func(),
) {
	if s.triageService == nil {
		s.respondError(w, http.StatusConflict, "Config editing is unavailable.")
		return
	}
	mode, err := s.triageService.ConfigWriteMode()
	if err != nil {
		s.respondError(w, http.StatusConflict, err.Error())
		return
	}
	cat, ok := s.policyCatalog.(*catalog.ConfigCatalog)
	if !ok || cat == nil {
		s.respondError(w, http.StatusConflict, "Running configuration cannot be updated.")
		return
	}
	updated := 0
	commit, err := s.triageService.CommitConfig(r.Context(), message, func(current []byte) ([]byte, error) {
		next, n, editErr := mutate(current)
		updated = n
		return next, editErr
	})
	if err != nil {
		s.respondError(w, editStatus(err), err.Error())
		return
	}
	if _, err := applyMemory(cat); err != nil {
		s.logger.Error("config was written but the running configuration was not refreshed", "error", err)
		s.respondError(w, http.StatusInternalServerError, fmt.Sprintf("config was written but the running configuration could not be refreshed: %v", err))
		return
	}
	if after != nil {
		after()
	}
	s.logger.Info("applied config edit", "mode", mode, "updated", updated, "commit", commit)
	s.respondJSON(w, http.StatusOK, ConfigEditResult{Mode: mode, Commit: commit, Updated: updated})
}

func (s *APIServer) cleanupRemovedRepositories(ctx context.Context, repositories []string) {
	cleaner, ok := s.stateStore.(statestore.StateStoreCleanup)
	if !ok {
		return
	}
	for _, repository := range repositories {
		if err := cleaner.CleanupRepository(ctx, repository); err != nil {
			s.logger.Error("failed to remove state for deleted sync target", "repository", repository, "error", err)
		}
	}
}

func editStatus(err error) int {
	if errors.Is(err, yamledit.ErrNoMatch) {
		return http.StatusBadRequest
	}
	var push *gitops.PushError
	if errors.As(err, &push) {
		return http.StatusBadGateway
	}
	if strings.Contains(err.Error(), "must not be empty") || strings.Contains(err.Error(), "needs a target") || strings.Contains(err.Error(), "no semver") || strings.Contains(err.Error(), "no sync") || strings.Contains(err.Error(), "no VEX") || strings.Contains(err.Error(), "parse suppline") {
		return http.StatusBadRequest
	}
	return http.StatusInternalServerError
}

func trimStrings(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		out = append(out, value)
	}
	return out
}
