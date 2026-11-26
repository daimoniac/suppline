package api

import (
	"context"
	"net/http"

	"github.com/daimoniac/suppline/internal/kev"
	"github.com/daimoniac/suppline/internal/statestore"
	"github.com/daimoniac/suppline/internal/types"
)

// KEVFeed gives the API the CISA KEV catalog.
type KEVFeed interface {
	Snapshot() kev.Snapshot
}

type kevImageStore interface {
	ListKEVImages(ctx context.Context, kevIDs []string) ([]statestore.KEVImage, error)
}

// SetKEV enables the KEV overview, the kev filter on vulnerabilities and KEV
// details on findings. nil leaves them off.
func (s *APIServer) SetKEV(feed KEVFeed) {
	s.kev = feed
}

func (s *APIServer) kevSnapshot() kev.Snapshot {
	if s.kev == nil {
		return kev.Snapshot{Status: kev.StatusDisabled}
	}
	return s.kev.Snapshot()
}

// kevInfo returns cve's catalog entry, or nil when it is not listed.
func kevInfo(catalog *kev.Catalog, cve string) *types.KEVInfo {
	entry, ok := catalog.Lookup(cve)
	if !ok {
		return nil
	}
	return &types.KEVInfo{DateAdded: entry.DateAdded, DueDate: entry.DueDate, Ransomware: entry.Ransomware}
}

// KEVOverviewResponse is the CISA KEV feed and the current images it affects.
type KEVOverviewResponse struct {
	Enabled        bool
	Status         string // ok, stale, unavailable or disabled
	CatalogVersion string
	SyncedAt       *int64 // Unix seconds of the last successful sync
	Entries        int    // CVEs in the catalog
	// Images counts current images with at least one KEV finding that no VEX
	// statement exempts. InUseImages of them run in a cluster; PassingImages
	// passed policy anyway.
	Images        int
	InUseImages   int
	PassingImages int
	// CVEs counts distinct unexempted KEV CVEs across those images.
	CVEs int
}

// handleGetKEV reports the CISA KEV feed and how many current images have
// unexempted known-exploited findings.
// @Summary CISA KEV overview
// @Description Feed state, and how many current images have a CVE from the CISA Known Exploited Vulnerabilities catalog that no VEX statement exempts
// @Tags Vulnerabilities
// @Produce json
// @Success 200 {object} KEVOverviewResponse
// @Failure 401 {object} map[string]string "Unauthorized"
// @Failure 500 {object} map[string]string "Internal server error"
// @Security BearerAuth
// @Router /kev [get]
func (s *APIServer) handleGetKEV(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	snapshot := s.kevSnapshot()
	out := KEVOverviewResponse{
		Enabled: s.kev != nil,
		Status:  string(snapshot.Status),
		Entries: snapshot.Catalog.Len(),
	}
	if snapshot.Catalog != nil {
		out.CatalogVersion = snapshot.Catalog.Version
		synced := snapshot.SyncedAt.Unix()
		out.SyncedAt = &synced
	}
	store, ok := s.stateStore.(kevImageStore)
	if !ok || snapshot.Catalog == nil {
		s.respondJSON(w, http.StatusOK, out)
		return
	}
	images, err := store.ListKEVImages(r.Context(), snapshot.Catalog.IDs())
	if err != nil {
		s.logger.Error("list KEV images", "error", err.Error())
		s.respondStoreError(w, err, "Failed to list images with known-exploited vulnerabilities")
		return
	}
	cves := map[string]struct{}{}
	for _, image := range images {
		out.Images++
		if image.RuntimeUsed {
			out.InUseImages++
		}
		if image.PolicyPassed {
			out.PassingImages++
		}
		for _, cve := range image.CVEs {
			cves[cve] = struct{}{}
		}
	}
	out.CVEs = len(cves)
	s.respondJSON(w, http.StatusOK, out)
}
