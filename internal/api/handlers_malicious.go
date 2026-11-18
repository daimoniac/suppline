package api

import (
	"context"
	"net/http"

	"github.com/daimoniac/suppline/internal/malicious"
	"github.com/daimoniac/suppline/internal/statestore"
	"github.com/daimoniac/suppline/internal/types"
)

// MaliciousFeed reports the state of the malicious-packages feed.
type MaliciousFeed interface {
	Overview() malicious.Overview
}

// MaliciousSettings is the static part of x-malicious-packages shown in the UI.
type MaliciousSettings struct {
	Block   bool
	RepoURL string
	Ref     string
}

type maliciousImageStore interface {
	ListMaliciousImages(ctx context.Context) ([]statestore.MaliciousImage, statestore.MaliciousCoverage, error)
}

// MaliciousFeedResponse is the state of the malicious-packages feed.
type MaliciousFeedResponse struct {
	Status              string // ok, unavailable or stale
	Commit              string
	SyncedAt            *int64 // Unix seconds of the last successful sync
	LastAttemptAt       *int64 // Unix seconds of the last sync attempt
	LastDurationMs      int64
	LastError           string
	SyncIntervalSeconds int64
	StaleAfterSeconds   int64
	RepoURL             string
	Ref                 string
	Block               bool
	Ecosystems          []string
	Entries             int
	Packages            map[string]int // indexed packages per ecosystem
}

// MaliciousImageResponse is a current image with malicious findings.
type MaliciousImageResponse struct {
	Repository   string
	Digest       string
	Tags         []string
	ScannedAt    int64
	PolicyPassed bool
	PolicyStatus string
	RuntimeUsed  bool
	Runtime      statestore.RuntimeInventory
	CheckStatus  string
	Findings     []types.MaliciousFinding
	// FalsePositives are the repository's false_positive statements for
	// malicious advisories, so the UI can show and edit them.
	FalsePositives []MaliciousStatement
}

// MaliciousStatement is a false_positive VEX statement for a MAL advisory.
type MaliciousStatement struct {
	ID        string
	Detail    string
	ExpiresAt *int64
}

// MaliciousOverviewResponse is the malicious-packages page.
type MaliciousOverviewResponse struct {
	Enabled  bool
	Feed     *MaliciousFeedResponse
	Coverage statestore.MaliciousCoverage
	Images   []MaliciousImageResponse
}

// handleGetMalicious reports the malicious-packages feed and affected images.
// @Summary Malicious-package detection overview
// @Description Feed sync state, check coverage of current images, and every current image whose latest scan found malicious packages (in-use images first)
// @Tags Malicious
// @Produce json
// @Success 200 {object} MaliciousOverviewResponse
// @Failure 401 {object} map[string]string "Unauthorized"
// @Failure 500 {object} map[string]string "Internal server error"
// @Security BearerAuth
// @Router /malicious [get]
func (s *APIServer) handleGetMalicious(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	out := MaliciousOverviewResponse{Enabled: s.malicious != nil, Images: []MaliciousImageResponse{}}
	if s.malicious != nil {
		out.Feed = maliciousFeedResponse(s.malicious.Overview(), s.maliciousInfo)
	}
	if store, ok := s.stateStore.(maliciousImageStore); ok {
		images, coverage, err := store.ListMaliciousImages(r.Context())
		if err != nil {
			s.logger.Error("list malicious images", "error", err.Error())
			s.respondError(w, http.StatusInternalServerError, "Failed to list malicious images")
			return
		}
		out.Coverage = coverage
		for _, image := range images {
			findings := image.Check.Findings
			if findings == nil {
				findings = []types.MaliciousFinding{}
			}
			out.Images = append(out.Images, MaliciousImageResponse{
				Repository:     image.Repository,
				Digest:         image.Digest,
				Tags:           image.Tags,
				ScannedAt:      image.ScannedAt,
				PolicyPassed:   image.PolicyPassed,
				PolicyStatus:   image.PolicyStatus,
				RuntimeUsed:    image.RuntimeUsed,
				Runtime:        image.Runtime,
				CheckStatus:    image.Check.Status,
				Findings:       findings,
				FalsePositives: s.maliciousStatements(image.Repository),
			})
		}
	}
	s.respondJSON(w, http.StatusOK, out)
}

func maliciousFeedResponse(overview malicious.Overview, settings MaliciousSettings) *MaliciousFeedResponse {
	feed := &MaliciousFeedResponse{
		Status:              string(overview.Status),
		Commit:              overview.Commit,
		LastDurationMs:      overview.LastDuration.Milliseconds(),
		LastError:           overview.LastError,
		SyncIntervalSeconds: int64(overview.SyncInterval.Seconds()),
		StaleAfterSeconds:   int64(overview.StaleAfter.Seconds()),
		RepoURL:             settings.RepoURL,
		Ref:                 settings.Ref,
		Block:               settings.Block,
		Ecosystems:          overview.Ecosystems,
		Entries:             overview.Entries,
		Packages:            overview.Packages,
	}
	if !overview.SyncedAt.IsZero() {
		at := overview.SyncedAt.Unix()
		feed.SyncedAt = &at
	}
	if !overview.LastAttemptAt.IsZero() {
		at := overview.LastAttemptAt.Unix()
		feed.LastAttemptAt = &at
	}
	return feed
}

func (s *APIServer) maliciousStatements(repository string) []MaliciousStatement {
	out := []MaliciousStatement{}
	if s.policyCatalog == nil {
		return out
	}
	for _, statement := range s.policyCatalog.ResolveEvidence(repository).VEXStatements {
		if !types.IsMaliciousID(statement.ID) || statement.State != types.VEXStateFalsePositive {
			continue
		}
		out = append(out, MaliciousStatement{ID: statement.ID, Detail: statement.Detail, ExpiresAt: statement.ExpiresAt})
	}
	return out
}
