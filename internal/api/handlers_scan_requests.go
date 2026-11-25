package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/daimoniac/suppline/internal/config"
	"github.com/daimoniac/suppline/internal/scanenqueue"
	"github.com/daimoniac/suppline/internal/statestore"
	"github.com/daimoniac/suppline/internal/tagselect"
	"github.com/daimoniac/suppline/internal/types"
)

// maxScanRequestWait caps how long one request may wait for a verdict.
// Clients behind proxies with short read timeouts wait in shorter slices.
const maxScanRequestWait = 10 * time.Minute

var digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// DigestResolver resolves a tag of a repository to its digest.
type DigestResolver interface {
	GetDigest(ctx context.Context, repo, tag string) (string, error)
}

// SetScanRequests enables the scan-request endpoints. resolver looks up the
// digest a pushed tag names; waiter hears about finished scans.
func (s *APIServer) SetScanRequests(resolver DigestResolver, waiter *ScanRequestWaiter) {
	if s == nil {
		return
	}
	s.digestResolver = resolver
	s.scanWaiter = waiter
	if waiter != nil && s.server != nil {
		s.server.RegisterOnShutdown(waiter.Close)
	}
}

// ScanRequestBody asks for a scan of one image of an in-place repository.
type ScanRequestBody struct {
	// Image is repository:tag, optionally followed by @sha256:<digest>.
	Image string `json:"image" example:"registry.gitlab.com/group/app:sha1a2b3c4d"`
}

// ScanRequestResult answers a scan request: the verdict once the scan is
// done, or where to poll while it is still queued.
type ScanRequestResult struct {
	Repository string `json:"repository"`
	Tag        string `json:"tag,omitempty"`
	Digest     string `json:"digest"`
	// State is "done" when a scan finished, "error" when it could not be
	// scanned, and "queued" while it is still waiting or running.
	State   string       `json:"state" enums:"done,error,queued"`
	Verdict *ScanVerdict `json:"verdict,omitempty"`
	Error   string       `json:"error,omitempty"`
	// After is the scan id a poll must wait past.
	After int64 `json:"after"`
	// Poll is the path to poll while State is "queued".
	Poll string `json:"poll,omitempty"`
	// URL is the scan's page in the web UI, relative to the server.
	URL string `json:"url,omitempty"`
}

// ScanVerdict is the outcome of one scan.
type ScanVerdict struct {
	ScanID int64 `json:"scanId"`
	// Status is the policy status: passed, failed or pending.
	Status    string                       `json:"status"`
	Reason    string                       `json:"reason,omitempty"`
	Findings  []types.PolicyFailureFinding `json:"findings,omitempty"`
	Attested  ScanAttestations             `json:"attested"`
	Counts    ScanCounts                   `json:"counts"`
	Malicious *types.MaliciousCheck        `json:"malicious,omitempty"`
	ScannedAt int64                        `json:"scannedAt"`
}

// ScanAttestations lists the attestations a scan published.
type ScanAttestations struct {
	SCAI bool `json:"scai"`
	SBOM bool `json:"sbom"`
	Vuln bool `json:"vuln"`
	VEX  bool `json:"vex"`
}

// ScanCounts are the vulnerability counts as found, exempted ones included.
// The verdict's status and reason already account for VEX exemptions.
type ScanCounts struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
}

// handleCreateScanRequest scans one image of an in-place repository now
// @Summary Request a scan
// @Description Queues an urgent scan of an image in an in-place repository, typically right after CI pushed it, and waits up to `wait` for the verdict. The scan attests the image where it lives. Returns 200 with the verdict when the scan finished in time, or 202 with a poll path.
// @Tags Scans
// @Accept json
// @Produce json
// @Param request body ScanRequestBody true "Image to scan"
// @Param wait query string false "How long to wait for the verdict, e.g. 55s (max 10m, default 0)"
// @Success 200 {object} ScanRequestResult
// @Success 202 {object} ScanRequestResult
// @Failure 400 {object} map[string]string "Invalid request"
// @Failure 401 {object} map[string]string "Unauthorized"
// @Failure 403 {object} map[string]string "Caller may not request scans of this repository"
// @Failure 404 {object} map[string]string "Repository not configured or tag not found"
// @Failure 409 {object} map[string]string "Tag names another digest"
// @Failure 422 {object} map[string]string "Repository is mirrored, or its tag filters drop the tag"
// @Security BearerAuth
// @Router /scan-requests [post]
func (s *APIServer) handleCreateScanRequest(w http.ResponseWriter, r *http.Request) {
	if s.scanWaiter == nil || s.digestResolver == nil {
		s.respondError(w, http.StatusServiceUnavailable, "scan requests are not enabled")
		return
	}
	wait, err := parseWait(r)
	if err != nil {
		s.respondError(w, http.StatusBadRequest, err.Error())
		return
	}
	var body ScanRequestBody
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&body); err != nil {
		s.respondError(w, http.StatusBadRequest, fmt.Sprintf("invalid request body: %v", err))
		return
	}
	repository, tag, digest, err := parseImageReference(body.Image)
	if err != nil {
		s.respondError(w, http.StatusBadRequest, err.Error())
		return
	}
	if tag == "" {
		s.respondError(w, http.StatusBadRequest, "image must name a tag, e.g. repository:tag")
		return
	}
	entry, status, message := s.inPlaceEntryFor(r, repository)
	if status != 0 {
		s.respondError(w, status, message)
		return
	}
	allowed, err := tagselect.Allowed(entry, tag)
	if err != nil {
		s.respondStoreError(w, err, fmt.Sprintf("tag filters: %v", err))
		return
	}
	if !allowed {
		s.respondError(w, http.StatusUnprocessableEntity, fmt.Sprintf("the tag filters of %s drop tag %s", repository, tag))
		return
	}

	resolved, err := s.digestResolver.GetDigest(r.Context(), repository, tag)
	if err != nil {
		s.respondError(w, http.StatusNotFound, fmt.Sprintf("resolve %s:%s: %v", repository, tag, err))
		return
	}
	if digest != "" && digest != resolved {
		s.respondError(w, http.StatusConflict, fmt.Sprintf("%s:%s names %s, not %s", repository, tag, resolved, digest))
		return
	}
	digest = resolved

	after, err := s.latestScanID(r.Context(), repository, digest)
	if err != nil {
		s.respondStoreError(w, err, err.Error())
		return
	}
	finish := s.scanWaiter.watch(repository, digest)
	s.scanWaiter.request(repository, digest)
	if _, err := s.scanEnqueuer.EnqueueScanRequest(r.Context(), scanenqueue.Image{
		Repository: repository,
		Digest:     digest,
		Tag:        tag,
	}); err != nil {
		s.respondStoreError(w, err, fmt.Sprintf("queue scan: %v", err))
		return
	}
	s.logger.Info("scan requested", "repository", repository, "tag", tag, "digest", digest, "caller", callerFrom(r.Context()).subject)

	result := s.awaitScan(w, r, repository, tag, digest, after, wait, finish)
	s.respondScanResult(w, result)
}

// handleGetScanRequest polls a scan request
// @Summary Poll a scan request
// @Description Waits up to `wait` for a scan of the digest newer than `after` and returns its verdict. Returns 202 while the scan is still queued or running.
// @Tags Scans
// @Produce json
// @Param digest path string true "Image digest (sha256:...)"
// @Param repository query string true "In-place repository"
// @Param after query int false "Scan id the result must be newer than"
// @Param wait query string false "How long to wait, e.g. 55s (max 10m, default 0)"
// @Success 200 {object} ScanRequestResult
// @Success 202 {object} ScanRequestResult
// @Failure 400 {object} map[string]string "Invalid request"
// @Failure 401 {object} map[string]string "Unauthorized"
// @Failure 403 {object} map[string]string "Caller may not read scans of this repository"
// @Failure 404 {object} map[string]string "Repository not configured, or no scan requested"
// @Security BearerAuth
// @Router /scan-requests/{digest} [get]
func (s *APIServer) handleGetScanRequest(w http.ResponseWriter, r *http.Request) {
	if s.scanWaiter == nil {
		s.respondError(w, http.StatusServiceUnavailable, "scan requests are not enabled")
		return
	}
	digest := strings.TrimPrefix(r.URL.Path, "/api/v1/scan-requests/")
	if !digestPattern.MatchString(digest) {
		s.respondError(w, http.StatusBadRequest, "path must end in a sha256 digest")
		return
	}
	repository := strings.TrimSpace(r.URL.Query().Get("repository"))
	if repository == "" {
		s.respondError(w, http.StatusBadRequest, "repository is required")
		return
	}
	after, err := strconv.ParseInt(r.URL.Query().Get("after"), 10, 64)
	if err != nil && r.URL.Query().Get("after") != "" {
		s.respondError(w, http.StatusBadRequest, "after must be a scan id")
		return
	}
	wait, err := parseWait(r)
	if err != nil {
		s.respondError(w, http.StatusBadRequest, err.Error())
		return
	}
	if _, status, message := s.inPlaceEntryFor(r, repository); status != 0 {
		s.respondError(w, status, message)
		return
	}
	finish := s.scanWaiter.watch(repository, digest)
	if record, err := s.newerScan(r.Context(), repository, digest, after); err == nil && record == nil && !s.scanPending(r.Context(), repository, digest) {
		if _, failed := s.scanWaiter.outstanding(repository, digest); failed != nil {
			s.respondScanResult(w, ScanRequestResult{Repository: repository, Digest: digest, After: after, State: "error", Error: failed.Error()})
			return
		}
		s.respondError(w, http.StatusNotFound, fmt.Sprintf("no scan of %s@%s newer than %d is queued", repository, digest, after))
		return
	}
	s.respondScanResult(w, s.awaitScan(w, r, repository, r.URL.Query().Get("tag"), digest, after, wait, finish))
}

// inPlaceEntryFor finds the in-place entry of repository and checks the
// caller may request its scans. A non-zero status is the error to answer.
func (s *APIServer) inPlaceEntryFor(r *http.Request, repository string) (config.SyncEntry, int, string) {
	cfg := s.runningConfig()
	if cfg == nil {
		return config.SyncEntry{}, http.StatusServiceUnavailable, "configuration is not loaded"
	}
	entry, ok := cfg.InPlaceEntryFor(repository)
	if !ok {
		if slices.Contains(cfg.GetTargetRepositories(), repository) {
			return config.SyncEntry{}, http.StatusUnprocessableEntity, fmt.Sprintf("%s is a mirrored repository; scan requests are only for in-place repositories", repository)
		}
		return config.SyncEntry{}, http.StatusNotFound, fmt.Sprintf("%s is not an in-place repository", repository)
	}
	caller := callerFrom(r.Context())
	if !caller.admin && !slices.Contains(entry.ScanRequesters, caller.subject) {
		return config.SyncEntry{}, http.StatusForbidden, fmt.Sprintf("%q may not request scans of %s", caller.subject, repository)
	}
	return entry, 0, ""
}

// awaitScan waits until a scan of repository@digest newer than after is
// persisted, a requested scan fails without one, wait runs out, or the
// client or server goes away.
func (s *APIServer) awaitScan(w http.ResponseWriter, r *http.Request, repository, tag, digest string, after int64, wait time.Duration, finish *scanFinish) ScanRequestResult {
	result := ScanRequestResult{Repository: repository, Tag: tag, Digest: digest, After: after}
	if wait > 0 {
		// The server's write timeout is shorter than a scan.
		_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(wait + 30*time.Second))
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	for {
		record, err := s.newerScan(r.Context(), repository, digest, after)
		if err != nil {
			result.State = "error"
			result.Error = err.Error()
			return result
		}
		if record != nil {
			return s.withVerdict(result, record)
		}
		select {
		case <-finish.done:
			if finish.err != nil && !s.scanPending(r.Context(), repository, digest) {
				// Several failure paths persist no scan record; look once
				// more in case this one did.
				if record, err := s.newerScan(r.Context(), repository, digest, after); err == nil && record != nil {
					return s.withVerdict(result, record)
				}
				result.State = "error"
				result.Error = finish.err.Error()
				return result
			}
			finish = s.scanWaiter.watch(repository, digest)
		case <-timer.C:
			return s.queuedResult(result)
		case <-r.Context().Done():
			return s.queuedResult(result)
		case <-s.scanWaiter.closed:
			return s.queuedResult(result)
		}
	}
}

// scanPending reports whether a scan of repository@digest is queued or a
// requested one has not finished yet.
func (s *APIServer) scanPending(ctx context.Context, repository, digest string) bool {
	if requested, _ := s.scanWaiter.outstanding(repository, digest); requested {
		return true
	}
	if s.taskQueue == nil {
		return false
	}
	pending, err := s.taskQueue.HasPendingTask(ctx, repository, digest)
	return err == nil && pending
}

func (s *APIServer) queuedResult(result ScanRequestResult) ScanRequestResult {
	if _, failed := s.scanWaiter.outstanding(result.Repository, result.Digest); failed != nil {
		result.State = "error"
		result.Error = failed.Error()
		return result
	}
	result.State = "queued"
	query := url.Values{}
	query.Set("repository", result.Repository)
	query.Set("after", strconv.FormatInt(result.After, 10))
	if result.Tag != "" {
		query.Set("tag", result.Tag)
	}
	result.Poll = s.config.BasePath + "/api/v1/scan-requests/" + result.Digest + "?" + query.Encode()
	return result
}

func (s *APIServer) withVerdict(result ScanRequestResult, record *statestore.ScanRecord) ScanRequestResult {
	result.State = "done"
	if record.ErrorMessage != "" {
		result.State = "error"
		result.Error = record.ErrorMessage
	}
	if result.Tag == "" {
		result.Tag = record.Tag
	}
	result.URL = s.config.BasePath + "/scans/" + record.Digest
	result.Verdict = &ScanVerdict{
		ScanID:   record.ID,
		Status:   record.PolicyStatus,
		Reason:   record.PolicyReason,
		Findings: record.PolicyFailureFindings,
		Attested: ScanAttestations{
			SCAI: record.SCAIAttested,
			SBOM: record.SBOMAttested,
			Vuln: record.VulnAttested,
			VEX:  record.VEXAttested,
		},
		Counts: ScanCounts{
			Critical: record.CriticalVulnCount,
			High:     record.HighVulnCount,
			Medium:   record.MediumVulnCount,
			Low:      record.LowVulnCount,
		},
		Malicious: record.Malicious,
		ScannedAt: record.CreatedAt,
	}
	return result
}

func (s *APIServer) respondScanResult(w http.ResponseWriter, result ScanRequestResult) {
	status := http.StatusOK
	if result.State == "queued" {
		status = http.StatusAccepted
	}
	s.respondJSON(w, status, result)
}

// latestScanID is the id of the newest scan of repository@digest, or 0.
func (s *APIServer) latestScanID(ctx context.Context, repository, digest string) (int64, error) {
	record, err := s.stateStore.GetLastRepositoryScan(ctx, repository, digest)
	if errors.Is(err, statestore.ErrScanNotFound) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("read last scan: %w", err)
	}
	return record.ID, nil
}

// newerScan returns the newest scan of repository@digest when its id is
// greater than after, or nil.
func (s *APIServer) newerScan(ctx context.Context, repository, digest string, after int64) (*statestore.ScanRecord, error) {
	record, err := s.stateStore.GetLastRepositoryScan(ctx, repository, digest)
	if errors.Is(err, statestore.ErrScanNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read last scan: %w", err)
	}
	if record.ID <= after {
		return nil, nil
	}
	return record, nil
}

func parseWait(r *http.Request) (time.Duration, error) {
	value := strings.TrimSpace(r.URL.Query().Get("wait"))
	if value == "" {
		return 0, nil
	}
	wait, err := time.ParseDuration(value)
	if err != nil || wait < 0 {
		return 0, fmt.Errorf("wait must be a duration such as 55s")
	}
	return min(wait, maxScanRequestWait), nil
}

// parseImageReference splits repository[:tag][@sha256:digest]. The repository
// is kept as written, because in-place entries are matched by their exact name.
func parseImageReference(image string) (repository, tag, digest string, err error) {
	image = strings.TrimSpace(image)
	if image == "" {
		return "", "", "", fmt.Errorf("image is required")
	}
	if at := strings.Index(image, "@"); at >= 0 {
		digest = image[at+1:]
		image = image[:at]
		if !digestPattern.MatchString(digest) {
			return "", "", "", fmt.Errorf("digest %q is not a sha256 digest", digest)
		}
	}
	if colon := strings.LastIndex(image, ":"); colon > strings.LastIndex(image, "/") {
		tag = image[colon+1:]
		image = image[:colon]
		if tag == "" {
			return "", "", "", fmt.Errorf("tag must not be empty")
		}
	}
	if image == "" {
		return "", "", "", fmt.Errorf("image needs a repository")
	}
	return image, tag, digest, nil
}
