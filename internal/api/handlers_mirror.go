package api

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/daimoniac/suppline/internal/statestore"
)

// MirrorSyncResponse is one configured sync on the mirror page.
type MirrorSyncResponse struct {
	Key              string
	Source           string
	Target           string
	Type             string
	Schedule         string
	Status           string
	FinishedAt       *int64
	Error            string
	ImageCount       int
	TagDeletionCount int
}

// MirrorOverviewResponse is the mirror page summary.
type MirrorOverviewResponse struct {
	Syncs            []MirrorSyncResponse
	HubDeletionCount int
	HubError         string
}

// handleGetMirror lists sync health for the in-process mirror.
// @Summary List mirror syncs
// @Description Sync health, image counts, and Docker Hub cleanup status
// @Tags Mirror
// @Produce json
// @Success 200 {object} MirrorOverviewResponse
// @Failure 401 {object} map[string]string "Unauthorized"
// @Failure 500 {object} map[string]string "Internal server error"
// @Security BearerAuth
// @Router /mirror [get]
func (s *APIServer) handleGetMirror(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	store, ok := s.stateStore.(statestore.MirrorStore)
	if !ok {
		s.respondJSON(w, http.StatusOK, MirrorOverviewResponse{Syncs: []MirrorSyncResponse{}})
		return
	}
	syncs, err := store.ListMirrorSyncs(r.Context())
	if err != nil {
		s.logger.Error("list mirror syncs", "error", err.Error())
		s.respondError(w, http.StatusInternalServerError, "Failed to list mirror syncs")
		return
	}
	hubError, err := store.MirrorHubError(r.Context())
	if err != nil {
		s.logger.Error("read mirror hub error", "error", err.Error())
		s.respondError(w, http.StatusInternalServerError, "Failed to read hub cleanup status")
		return
	}
	_, hubCount, err := store.ListMirrorHubDeletions(r.Context(), 1, 0)
	if err != nil {
		s.logger.Error("count hub deletions", "error", err.Error())
		s.respondError(w, http.StatusInternalServerError, "Failed to list hub deletions")
		return
	}
	out := make([]MirrorSyncResponse, 0, len(syncs))
	for _, sync := range syncs {
		status := sync.Status
		errMsg := sync.Error
		if s.mirrorActivity != nil && s.mirrorActivity.Running(sync.Key) {
			status = "running"
			errMsg = ""
		}
		if status == "" {
			status = "never"
		}
		out = append(out, MirrorSyncResponse{
			Key:              sync.Key,
			Source:           sync.Source,
			Target:           sync.Target,
			Type:             sync.Type,
			Schedule:         sync.Schedule,
			Status:           status,
			FinishedAt:       sync.FinishedAt,
			Error:            errMsg,
			ImageCount:       sync.ImageCount,
			TagDeletionCount: sync.TagDeletionCount,
		})
	}
	s.respondJSON(w, http.StatusOK, MirrorOverviewResponse{
		Syncs:            out,
		HubDeletionCount: hubCount,
		HubError:         hubError,
	})
}

func (s *APIServer) handleMirrorSub(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/mirror/")
	if path == "hub-deletions" {
		s.handleListMirrorHubDeletions(w, r)
		return
	}
	parts := strings.Split(path, "/")
	if len(parts) != 3 || parts[0] != "syncs" {
		http.NotFound(w, r)
		return
	}
	switch parts[2] {
	case "images":
		s.handleListMirrorImages(w, r, parts[1])
	case "deletions":
		s.handleListMirrorTagDeletions(w, r, parts[1])
	default:
		http.NotFound(w, r)
	}
}

// handleListMirrorImages lists tags currently mirrored for one sync.
// @Summary List mirrored images
// @Description Current wanted tags for one sync
// @Tags Mirror
// @Produce json
// @Param key path string true "Sync key"
// @Param limit query int false "Page size" default(25)
// @Param offset query int false "Offset" default(0)
// @Success 200 {array} statestore.MirrorImage
// @Failure 401 {object} map[string]string "Unauthorized"
// @Failure 500 {object} map[string]string "Internal server error"
// @Security BearerAuth
// @Router /mirror/syncs/{key}/images [get]
func (s *APIServer) handleListMirrorImages(w http.ResponseWriter, r *http.Request, key string) {
	s.listMirrorPage(w, r, func(limit, offset int) (any, int, error) {
		store, ok := s.stateStore.(statestore.MirrorStore)
		if !ok {
			return []statestore.MirrorImage{}, 0, nil
		}
		return store.ListMirrorImages(r.Context(), key, limit, offset)
	})
}

// handleListMirrorTagDeletions lists tags cleanup removed for one sync.
// @Summary List mirror tag deletions
// @Description Tags removed by cleanup for one sync
// @Tags Mirror
// @Produce json
// @Param key path string true "Sync key"
// @Param limit query int false "Page size" default(25)
// @Param offset query int false "Offset" default(0)
// @Success 200 {array} statestore.MirrorDeletion
// @Failure 401 {object} map[string]string "Unauthorized"
// @Failure 500 {object} map[string]string "Internal server error"
// @Security BearerAuth
// @Router /mirror/syncs/{key}/deletions [get]
func (s *APIServer) handleListMirrorTagDeletions(w http.ResponseWriter, r *http.Request, key string) {
	s.listMirrorPage(w, r, func(limit, offset int) (any, int, error) {
		store, ok := s.stateStore.(statestore.MirrorStore)
		if !ok {
			return []statestore.MirrorDeletion{}, 0, nil
		}
		return store.ListMirrorTagDeletions(r.Context(), key, limit, offset)
	})
}

// handleListMirrorHubDeletions lists Docker Hub repositories removed by cleanup.
// @Summary List hub repository deletions
// @Description Docker Hub repositories removed by cleanupRepos
// @Tags Mirror
// @Produce json
// @Param limit query int false "Page size" default(25)
// @Param offset query int false "Offset" default(0)
// @Success 200 {array} statestore.MirrorDeletion
// @Failure 401 {object} map[string]string "Unauthorized"
// @Failure 500 {object} map[string]string "Internal server error"
// @Security BearerAuth
// @Router /mirror/hub-deletions [get]
func (s *APIServer) handleListMirrorHubDeletions(w http.ResponseWriter, r *http.Request) {
	s.listMirrorPage(w, r, func(limit, offset int) (any, int, error) {
		store, ok := s.stateStore.(statestore.MirrorStore)
		if !ok {
			return []statestore.MirrorDeletion{}, 0, nil
		}
		return store.ListMirrorHubDeletions(r.Context(), limit, offset)
	})
}

func (s *APIServer) listMirrorPage(w http.ResponseWriter, r *http.Request, load func(limit, offset int) (any, int, error)) {
	limit := parseQueryParamInt(r, "limit", 25)
	offset := parseQueryParamInt(r, "offset", 0)
	if limit < 1 {
		limit = 25
	}
	if limit > 100 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}
	items, total, err := load(limit, offset)
	if err != nil {
		s.logger.Error("list mirror records", "error", err.Error())
		s.respondError(w, http.StatusInternalServerError, "Failed to list mirror records")
		return
	}
	w.Header().Set("X-Total-Count", strconv.Itoa(total))
	s.respondJSON(w, http.StatusOK, items)
}
