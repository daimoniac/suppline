package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/daimoniac/suppline/internal/config"
	"github.com/daimoniac/suppline/internal/policy/catalog"
	"github.com/daimoniac/suppline/internal/statestore"
	"github.com/daimoniac/suppline/internal/triage/yamledit"
)

// HeldDigestResponse is one Held digest on the Mirror page.
type HeldDigestResponse struct {
	Repository string
	Digest     string
	Source     string
	Tags       []string
	// FirstSeen is when suppline first saw the digest upstream (Unix seconds).
	FirstSeen int64
	// CooldownSeconds is the repository's cooldown. Zero means the digest
	// only waits for a passing attestation.
	CooldownSeconds int64
	// RemainingSeconds is the cooldown left, zero once it is over or released.
	RemainingSeconds int64
	Released         bool
	// PolicyStatus is the latest scan's policy status, empty before the first scan.
	PolicyStatus string
	PolicyReason string
	ScannedAt    int64
}

type cooldownReleaseRequest struct {
	Repository string `json:"repository"`
	Digest     string `json:"digest"`
	Reason     string `json:"reason"`
	Author     string `json:"author,omitempty"`
}

// handleListHeldDigests lists the digests the tag runway holds.
// @Summary List held digests
// @Description Digests the tag runway holds off a tag: in their cooldown, waiting for a passing attestation, or failing policy
// @Tags Mirror
// @Produce json
// @Success 200 {array} HeldDigestResponse
// @Failure 401 {object} map[string]string "Unauthorized"
// @Security BearerAuth
// @Router /mirror/held [get]
func (s *APIServer) handleListHeldDigests(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	out := []HeldDigestResponse{}
	if s.heldDigests == nil {
		s.respondJSON(w, http.StatusOK, out)
		return
	}
	now := time.Now()
	for _, held := range s.heldDigests.Held() {
		item := HeldDigestResponse{
			Repository:      held.Repository,
			Digest:          held.Digest,
			Source:          held.Source,
			Tags:            held.Tags,
			FirstSeen:       held.FirstSeen.Unix(),
			CooldownSeconds: int64(held.Cooldown.Seconds()),
			Released:        held.Released,
		}
		if !held.Released && held.Cooldown > 0 {
			item.RemainingSeconds = int64(max(held.FirstSeen.Add(held.Cooldown).Sub(now), 0).Seconds())
		}
		rec, err := s.stateStore.GetLastRepositoryScanSummary(r.Context(), held.Repository, held.Digest)
		switch {
		case err == nil && rec != nil:
			item.PolicyStatus = rec.PolicyStatus
			item.PolicyReason = rec.PolicyReason
			item.ScannedAt = rec.CreatedAt
		case err != nil && !errors.Is(err, statestore.ErrScanNotFound):
			s.logger.Warn("read scan of held digest", "repository", held.Repository, "digest", held.Digest, "error", err.Error())
		}
		out = append(out, item)
	}
	s.respondJSON(w, http.StatusOK, out)
}

// handleReleaseCooldown records a Cooldown release for one Held digest.
// @Summary Release a held digest from its cooldown
// @Description Writes x-cooldown-release on the repository's sync entries. The release skips the rest of the cooldown only; the digest still needs a passing scan and attestation before its tag moves.
// @Tags Mirror
// @Accept json
// @Produce json
// @Param request body cooldownReleaseRequest true "Digest to release"
// @Success 200 {object} ConfigEditResult
// @Failure 400 {object} map[string]string
// @Failure 409 {object} map[string]string
// @Security BearerAuth
// @Router /mirror/held/release [post]
func (s *APIServer) handleReleaseCooldown(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	var req cooldownReleaseRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	repository := strings.TrimSpace(req.Repository)
	release := config.CooldownRelease{
		Digest: strings.TrimSpace(req.Digest),
		Reason: strings.TrimSpace(req.Reason),
		Author: strings.TrimSpace(req.Author),
		At:     time.Now().UTC().Format(time.RFC3339),
	}
	if repository == "" || !strings.HasPrefix(release.Digest, "sha256:") {
		s.respondError(w, http.StatusBadRequest, "repository and a sha256 digest are required")
		return
	}
	if release.Reason == "" {
		s.respondError(w, http.StatusBadRequest, "a reason is required")
		return
	}
	s.applyConfigEdit(w, r, "chore(config): release "+release.Digest+" from cooldown [skip ci]", func(current []byte) ([]byte, int, error) {
		next, err := yamledit.AddCooldownRelease(current, repository, release)
		return next, 1, err
	}, func(cat *catalog.ConfigCatalog) (int, error) {
		return cat.AddCooldownRelease(repository, release)
	}, func() int {
		s.rescanReleased(r.Context(), repository, release.Digest)
		return 0
	})
}

// rescanReleased asks the runway to rescan a released digest now. The config
// edit only requeues a repository's current images, and a Held digest is not
// one of them. A failure is logged: the next mirror pass rescans it as well.
func (s *APIServer) rescanReleased(ctx context.Context, repository, digest string) {
	if s.heldDigests == nil {
		return
	}
	held, err := s.heldDigests.Release(ctx, repository, digest)
	if err != nil {
		s.logger.Warn("cannot queue rescan of released digest; next mirror pass rescans it",
			"repository", repository, "digest", digest, "error", err.Error())
		return
	}
	if !held {
		s.logger.Info("released digest is not held", "repository", repository, "digest", digest)
	}
}
