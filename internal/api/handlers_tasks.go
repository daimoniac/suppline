package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"

	semver "github.com/Masterminds/semver/v3"
	"github.com/daimoniac/suppline/internal/semverutil"
	"github.com/daimoniac/suppline/internal/statestore"
)

// SemverUpdateEntry describes the state of a single sync entry with semverRange.
type SemverUpdateEntry struct {
	Source             string   `json:"source"`
	Target             string   `json:"target"`
	CurrentRanges      []string `json:"current_ranges"`
	RuntimeVersions    []string `json:"runtime_versions"`
	OutOfRangeVersions []string `json:"out_of_range_versions"`
	SuggestedRanges    []string `json:"suggested_ranges,omitempty"`
	// Status is one of "current", "out_of_bounds", "tighten", or "no_runtime_data".
	Status string `json:"status"`
}

// SemverUpdateTasksResponse is returned by GET /api/v1/tasks/semver-updates.
type SemverUpdateTasksResponse struct {
	Entries       []SemverUpdateEntry `json:"entries"`
	AIAgentPrompt string              `json:"ai_agent_prompt"`
	NoRuntimeData bool                `json:"no_runtime_data"`
}

// VEXExpiryTaskEntry is one repository's VEX statement that is expired or
// near expiry, with the facts that decide what can be done about it.
type VEXExpiryTaskEntry struct {
	CVEID string `json:"cve_id"`
	// Repository is the repository this statement belongs to.
	Repository string `json:"repository"`
	// Repositories holds Repository alone. Kept for older clients.
	Repositories  []string `json:"repositories"`
	ExpiresAt     int64    `json:"expires_at"`
	State         string   `json:"state"`
	Justification string   `json:"justification,omitempty"`
	Detail        string   `json:"detail,omitempty"`
	// Status is one of "expired" or "expiring_soon".
	Status string `json:"status"`
	// Source is "vex" (hand-written) or "vex-auto" (written by triage).
	Source string `json:"source"`
	// Editable is true when the statement is the one sync-entry copy for this
	// id, so it can be extended or removed on its own. It is false for a
	// defaults.vex statement or an id stored on more than one entry.
	Editable bool `json:"editable"`
	// InScans is true when a current scan of the repository still reports the CVE.
	InScans bool `json:"in_scans"`
	// AffectedTags are the scanned tags that still report the CVE.
	AffectedTags []string `json:"affected_tags,omitempty"`
	// FixedTag is the newest scanned tag that no longer reports the CVE, set
	// only when it is newer than every tag that still does.
	FixedTag string `json:"fixed_tag,omitempty"`
	// KEV is true when triage refuses to exempt the CVE because it is in the
	// CISA KEV catalog, so a re-triage cannot renew the statement.
	KEV bool `json:"kev,omitempty"`
	// LastRun is the latest triage run for this repository and CVE.
	LastRun *TriageRunResponse `json:"last_run,omitempty"`
}

// VEXExpiryTasksResponse is returned by GET /api/v1/tasks/vex-expiry.
type VEXExpiryTasksResponse struct {
	Entries       []VEXExpiryTaskEntry `json:"entries"`
	AIAgentPrompt string               `json:"ai_agent_prompt"`
	// TriageEnabled says whether a re-triage can be queued.
	TriageEnabled bool `json:"triage_enabled"`
}

type RuntimeUnusedWhitelistResponse struct {
	Repositories []string `json:"repositories"`
}

type RuntimeUnusedWhitelistRequest struct {
	Repository string `json:"repository"`
}

// internalSemverEntry carries both the public data and the original sync index
// so that the yaml.Node updater can map suggestions back to the right YAML node.
type internalSemverEntry struct {
	SemverUpdateEntry
	syncIndex int
}

// handleGetSemverUpdateTasks returns semver range update suggestions.
//
// @Summary     Get semver range update tasks
// @Description For each sync entry in suppline.yml with a semverRange, compares
// @Description the configured constraint against versions actively running in
// @Description Kubernetes clusters (via clusterstate-agent) and suggests updates.
// @Tags        Tasks
// @Produce     json
// @Success     200  {object}  SemverUpdateTasksResponse
// @Failure     401  {object}  map[string]string  "Unauthorized"
// @Failure     500  {object}  map[string]string  "Internal server error"
// @Security    BearerAuth
// @Router      /tasks/semver-updates [get]
func (s *APIServer) handleGetSemverUpdateTasks(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	ctx := r.Context()

	// Collect sync entries that have a semverRange configured.
	var candidates []internalSemverEntry
	running := s.runningConfig()
	_ = running.ForEachActive(func(i int) error {
		entry := running.Sync[i]
		if entry.Tags == nil || len(entry.Tags.SemverRange) == 0 {
			return nil
		}
		candidates = append(candidates, internalSemverEntry{
			syncIndex: i,
			SemverUpdateEntry: SemverUpdateEntry{
				Source:             entry.Source,
				Target:             entry.Target,
				CurrentRanges:      entry.Tags.SemverRange,
				RuntimeVersions:    []string{},
				OutOfRangeVersions: []string{},
			},
		})
		return nil
	})

	if len(candidates) == 0 {
		s.respondJSON(w, http.StatusOK, SemverUpdateTasksResponse{
			Entries:       []SemverUpdateEntry{},
			AIAgentPrompt: "",
			NoRuntimeData: false,
		})
		return
	}

	// Gather runtime images from every known cluster.
	noRuntimeData := true
	if s.clusterInventory != nil {
		clusters, err := s.clusterInventory.ListClusterSummaries(ctx)
		if err != nil {
			s.logger.Error("failed to list cluster summaries", "error", err)
			s.respondError(w, http.StatusInternalServerError, "Failed to list cluster summaries")
			return
		}

		if len(clusters) > 0 {
			noRuntimeData = false

			// Build: normalized imageRef -> deduplicated set of semver tags
			imageTagMap := make(map[string]map[string]struct{})
			for _, cluster := range clusters {
				images, err := s.clusterInventory.ListClusterImages(ctx, cluster.Name)
				if err != nil {
					s.logger.Warn("failed to list cluster images", "cluster", cluster.Name, "error", err)
					continue
				}
				for _, img := range images {
					if img.Tag == "" || img.Tag == "latest" {
						continue
					}
					if _, ok := semverutil.ParseVersion(img.Tag); !ok {
						continue // not a semver tag
					}

					normalizedRef := statestore.NormalizeRepositoryRef(img.ImageRef)
					if normalizedRef == "" {
						continue
					}

					if _, ok := imageTagMap[normalizedRef]; !ok {
						imageTagMap[normalizedRef] = make(map[string]struct{})
					}
					imageTagMap[normalizedRef][img.Tag] = struct{}{}
				}
			}

			// Match runtime images to sync entries using canonical repository references.
			for i := range candidates {
				c := &candidates[i]
				normalizedTarget := statestore.NormalizeRepositoryRef(c.Target)
				if normalizedTarget == "" {
					continue
				}

				tagSet, ok := imageTagMap[normalizedTarget]
				if !ok {
					continue
				}

				for tag := range tagSet {
					c.RuntimeVersions = append(c.RuntimeVersions, tag)
				}
				sort.Slice(c.RuntimeVersions, func(a, b int) bool {
					va, okA := semverutil.ParseVersion(c.RuntimeVersions[a])
					vb, okB := semverutil.ParseVersion(c.RuntimeVersions[b])
					if !okA || !okB {
						return c.RuntimeVersions[a] < c.RuntimeVersions[b]
					}
					return semverutil.Compare(va, vb) < 0
				})
			}
		}
	}

	// Evaluate each candidate against its constraint.
	for i := range candidates {
		c := &candidates[i]

		if len(c.RuntimeVersions) == 0 {
			c.Status = "no_runtime_data"
			continue
		}

		// Join multiple range strings with || so a runtime version only needs
		// to satisfy one configured range.
		constraintStr := strings.Join(c.CurrentRanges, " || ")
		constraint, err := semverutil.NewConstraint(constraintStr)
		if err != nil {
			s.logger.Warn("failed to parse semver constraint", "constraint", constraintStr, "error", err)
			c.Status = "no_runtime_data"
			continue
		}

		var outOfRangeTags []string
		var allTags []string
		for _, tag := range c.RuntimeVersions {
			v, ok := semverutil.ParseVersion(tag)
			if !ok {
				continue
			}
			allTags = append(allTags, tag)
			if !semverutil.Satisfies(constraint, v) {
				outOfRangeTags = append(outOfRangeTags, tag)
				c.OutOfRangeVersions = append(c.OutOfRangeVersions, tag)
			}
		}

		if len(allTags) == 0 {
			c.Status = "no_runtime_data"
			continue
		}

		// RuntimeVersions is already sorted by ParseVersion order.
		minTag := allTags[0]
		minVer, _ := semverutil.ParseVersion(minTag)

		suggestedLower := suggestedLowerBound(minVer, minTag, c.CurrentRanges)
		suggestedRange := formatSuggestedLowerOnlyRange(suggestedLower, strings.Join(c.CurrentRanges, " "))
		tightenRanges, hasTighteningSuggestion := suggestedRangesForTighten(c.CurrentRanges, allTags)

		if len(outOfRangeTags) == 0 {
			c.Status = "current"
			if hasTighteningSuggestion {
				c.Status = "tighten"
				c.SuggestedRanges = tightenRanges
			}
			continue
		}

		c.Status = "out_of_bounds"
		c.SuggestedRanges = []string{suggestedRange}
	}

	// Build the public-facing entry list.
	publicEntries := make([]SemverUpdateEntry, len(candidates))
	for i, c := range candidates {
		publicEntries[i] = c.SemverUpdateEntry
	}

	aiAgentPrompt := buildSemverUpdatePrompt(candidates)

	s.respondJSON(w, http.StatusOK, SemverUpdateTasksResponse{
		Entries:       publicEntries,
		AIAgentPrompt: aiAgentPrompt,
		NoRuntimeData: noRuntimeData,
	})
}

// handleGetVEXExpiryTasks returns VEX statements that are expired or expiring soon.
//
// @Summary     Get VEX expiry tasks
// @Description Lists configured VEX statements that are already expired or will
// @Description expire within the next 7 days.
// @Tags        Tasks
// @Produce     json
// @Success     200  {object}  VEXExpiryTasksResponse
// @Failure     401  {object}  map[string]string  "Unauthorized"
// @Security    BearerAuth
// @Router      /tasks/vex-expiry [get]
func (s *APIServer) handleGetVEXExpiryTasks(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	expiringSoon := true
	expired := true
	vexInfos := s.getConfiguredVEXStatements("", "", &expiringSoon, &expired)

	now := time.Now().Unix()
	entries := make([]VEXExpiryTaskEntry, 0, len(vexInfos))
	for _, info := range vexInfos {
		if info == nil || info.ExpiresAt == nil || *info.ExpiresAt == 0 {
			continue
		}
		status := "expiring_soon"
		if *info.ExpiresAt <= now {
			status = "expired"
		}
		entries = append(entries, VEXExpiryTaskEntry{
			CVEID:         info.CVEID,
			Repository:    info.Repository,
			Repositories:  []string{info.Repository},
			ExpiresAt:     *info.ExpiresAt,
			State:         string(info.State),
			Justification: string(info.Justification),
			Detail:        info.Detail,
			Status:        status,
			Source:        info.Source,
		})
	}
	s.addVEXExpiryFacts(r.Context(), entries)

	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Status != entries[j].Status {
			return entries[i].Status == "expired"
		}
		if entries[i].ExpiresAt != entries[j].ExpiresAt {
			return entries[i].ExpiresAt < entries[j].ExpiresAt
		}
		if entries[i].CVEID != entries[j].CVEID {
			return entries[i].CVEID < entries[j].CVEID
		}
		return entries[i].Repository < entries[j].Repository
	})

	s.respondJSON(w, http.StatusOK, VEXExpiryTasksResponse{
		Entries:       entries,
		AIAgentPrompt: buildVEXExpiryPrompt(entries),
		TriageEnabled: s.triageService != nil && s.triageService.Enabled(),
	})
}

func (s *APIServer) handleRuntimeUnusedWhitelistRouter(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.handleGetRuntimeUnusedWhitelist(w, r)
		return
	case http.MethodPost:
		if s.config.ReadOnly {
			s.respondError(w, http.StatusForbidden, "API is in read-only mode")
			return
		}
		s.handleAddRuntimeUnusedWhitelist(w, r)
		return
	case http.MethodDelete:
		if s.config.ReadOnly {
			s.respondError(w, http.StatusForbidden, "API is in read-only mode")
			return
		}
		s.handleRemoveRuntimeUnusedWhitelist(w, r)
		return
	default:
		s.respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
	}
}

func (s *APIServer) handleGetRuntimeUnusedWhitelist(w http.ResponseWriter, r *http.Request) {
	entries, err := s.stateStore.ListRuntimeUnusedRepositoryWhitelist(r.Context())
	if err != nil {
		s.respondError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to list runtime-unused whitelist: %v", err))
		return
	}

	repositories := make([]string, 0, len(entries))
	for _, entry := range entries {
		repositories = append(repositories, entry.Repository)
	}

	s.respondJSON(w, http.StatusOK, RuntimeUnusedWhitelistResponse{Repositories: repositories})
}

func (s *APIServer) handleAddRuntimeUnusedWhitelist(w http.ResponseWriter, r *http.Request) {
	var req RuntimeUnusedWhitelistRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.respondError(w, http.StatusBadRequest, fmt.Sprintf("Invalid request body: %v", err))
		return
	}

	repository := strings.TrimSpace(req.Repository)
	if repository == "" {
		s.respondError(w, http.StatusBadRequest, "repository is required")
		return
	}

	if err := s.stateStore.AddRuntimeUnusedRepositoryWhitelist(r.Context(), repository); err != nil {
		s.respondError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to add runtime-unused whitelist entry: %v", err))
		return
	}

	s.respondJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *APIServer) handleRemoveRuntimeUnusedWhitelist(w http.ResponseWriter, r *http.Request) {
	var req RuntimeUnusedWhitelistRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.respondError(w, http.StatusBadRequest, fmt.Sprintf("Invalid request body: %v", err))
		return
	}

	repository := strings.TrimSpace(req.Repository)
	if repository == "" {
		s.respondError(w, http.StatusBadRequest, "repository is required")
		return
	}

	if err := s.stateStore.RemoveRuntimeUnusedRepositoryWhitelist(r.Context(), repository); err != nil {
		s.respondError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to remove runtime-unused whitelist entry: %v", err))
		return
	}

	s.respondJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

var lowerOnlyRangeRe = regexp.MustCompile(`^>=\s*(\S+)\s*$`)
var exactVersionRangeRe = regexp.MustCompile(`^\s*v?\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?\s*$`)
var vPrefixRangeRe = regexp.MustCompile(`^(>=|<=|>|<|=|~|\^)?\s*v\d`)

// sameSemverLowerOnlyRange returns true when current is already a single
// lower-bound-only range (>=x.y.z) equivalent to proposedLower.
func sameSemverLowerOnlyRange(current []string, proposedLower string) bool {
	if len(current) != 1 {
		return false
	}
	m := lowerOnlyRangeRe.FindStringSubmatch(strings.TrimSpace(current[0]))
	if m == nil {
		return false
	}
	currentLower, ok := semverutil.ParseVersion(m[1])
	if !ok {
		return false
	}
	proposed, ok := semverutil.ParseVersion(proposedLower)
	if !ok {
		return false
	}
	return semverutil.Compare(currentLower, proposed) == 0
}

func suggestedLowerBound(minVer *semver.Version, originalTag string, currentRanges []string) string {
	if rangesIncludePrereleaseMarker(currentRanges) {
		// Keep prerelease inclusion semantics when existing constraints use -0.
		return fmt.Sprintf("%d.%d.%d-0", minVer.Major(), minVer.Minor(), minVer.Patch())
	}

	// Prefer the tag's own version text so Bitnami-style "-rN" revisions are
	// preserved (ParseVersion canonicalizes them to ".N" for comparison only).
	// A distribution prefix such as "alpine-" is dropped: ">=alpine-v19.5.3"
	// is not a valid constraint.
	if originalTag != "" {
		lower := stripLeadingV(semverutil.VersionText(originalTag))
		if _, err := semverutil.NewConstraint(">=" + lower); err == nil {
			return lower
		}
	}
	return fmt.Sprintf("%d.%d.%d", minVer.Major(), minVer.Minor(), minVer.Patch())
}

func stripLeadingV(tag string) string {
	if len(tag) > 0 && (tag[0] == 'v' || tag[0] == 'V') {
		return tag[1:]
	}
	return tag
}

func rangesIncludePrereleaseMarker(ranges []string) bool {
	for _, r := range ranges {
		if strings.Contains(r, "-0") {
			return true
		}
	}
	return false
}

func suggestedRangesForTighten(currentRanges []string, runtimeTags []string) ([]string, bool) {
	suggested := make([]string, 0, len(currentRanges))
	changed := false

	type taggedVersion struct {
		tag string
		ver *semver.Version
	}
	runtime := make([]taggedVersion, 0, len(runtimeTags))
	for _, tag := range runtimeTags {
		v, ok := semverutil.ParseVersion(tag)
		if !ok {
			continue
		}
		runtime = append(runtime, taggedVersion{tag: tag, ver: v})
	}
	if len(runtime) == 0 {
		return nil, false
	}
	sort.Slice(runtime, func(i, j int) bool { return semverutil.Compare(runtime[i].ver, runtime[j].ver) < 0 })
	runtimeFloor := runtime[0].ver

	for _, current := range currentRanges {
		constraint, err := semverutil.NewConstraint(current)
		if err != nil {
			suggested = append(suggested, current)
			continue
		}

		matching := make([]taggedVersion, 0, len(runtime))
		for _, tv := range runtime {
			if semverutil.Satisfies(constraint, tv.ver) {
				matching = append(matching, tv)
			}
		}

		if len(matching) == 0 {
			if rangeStrictlyBelowVersion(current, runtimeFloor) {
				changed = true
				continue
			}
			suggested = append(suggested, current)
			continue
		}

		sort.Slice(matching, func(i, j int) bool { return semverutil.Compare(matching[i].ver, matching[j].ver) < 0 })
		trimmedCurrent := strings.TrimSpace(current)
		if exactVersionRangeRe.MatchString(trimmedCurrent) {
			suggested = append(suggested, trimmedCurrent)
			continue
		}

		lower := suggestedLowerBound(matching[0].ver, matching[0].tag, []string{current})
		next := formatSuggestedLowerOnlyRange(lower, current)
		upperBounds := extractUpperBounds(current)
		if len(upperBounds) == 0 && sameSemverLowerOnlyRange([]string{current}, lower) {
			suggested = append(suggested, trimmedCurrent)
			continue
		}
		if len(upperBounds) > 0 {
			next = fmt.Sprintf("%s %s", next, strings.Join(upperBounds, " "))
		}
		suggested = append(suggested, next)

		if normalizeConstraint(current) != normalizeConstraint(next) {
			changed = true
		}
	}

	return suggested, changed
}

func formatSuggestedLowerOnlyRange(lower string, currentRange string) string {
	if rangeUsesVPrefix(currentRange) {
		return fmt.Sprintf(">=v%s", lower)
	}
	return fmt.Sprintf(">=%s", lower)
}

func rangeUsesVPrefix(r string) bool {
	return vPrefixRangeRe.MatchString(strings.TrimSpace(r))
}

func extractUpperBounds(r string) []string {
	fields := strings.Fields(r)
	upper := make([]string, 0, len(fields))
	for _, field := range fields {
		if strings.HasPrefix(field, "<") {
			upper = append(upper, field)
		}
	}
	return upper
}

func normalizeConstraint(r string) string {
	return strings.Join(strings.Fields(strings.TrimSpace(r)), " ")
}

func rangeStrictlyBelowVersion(r string, floor *semver.Version) bool {
	for _, upper := range extractUpperBounds(r) {
		inclusive := strings.HasPrefix(upper, "<=")
		verStr := strings.TrimLeft(upper, "<=>")
		v, ok := semverutil.ParseVersion(verStr)
		if !ok {
			continue
		}

		if inclusive {
			if semverutil.Compare(v, floor) < 0 {
				return true
			}
			continue
		}

		if semverutil.Compare(v, floor) <= 0 {
			return true
		}
	}

	fields := strings.Fields(strings.TrimSpace(r))
	for _, field := range fields {
		token := strings.TrimSpace(field)
		if token == "" {
			continue
		}

		if strings.HasPrefix(token, "~") {
			if upper, ok := inferredUpperBoundForTilde(strings.TrimPrefix(token, "~")); ok {
				if semverutil.Compare(upper, floor) <= 0 {
					return true
				}
			}
		}

		if strings.HasPrefix(token, "^") {
			if upper, ok := inferredUpperBoundForCaret(strings.TrimPrefix(token, "^")); ok {
				if semverutil.Compare(upper, floor) <= 0 {
					return true
				}
			}
		}

		if exactVersionRangeRe.MatchString(token) {
			if v, ok := semverutil.ParseVersion(token); ok && semverutil.Compare(v, floor) < 0 {
				return true
			}
		}
	}

	return false
}

func inferredUpperBoundForTilde(raw string) (*semver.Version, bool) {
	v, ok := semverutil.ParseVersion(raw)
	if !ok {
		return nil, false
	}
	upper, ok := semverutil.ParseVersion(fmt.Sprintf("%d.%d.0", v.Major(), v.Minor()+1))
	if !ok {
		return nil, false
	}
	return upper, true
}

func inferredUpperBoundForCaret(raw string) (*semver.Version, bool) {
	v, ok := semverutil.ParseVersion(raw)
	if !ok {
		return nil, false
	}

	major := v.Major()
	minor := v.Minor()
	patch := v.Patch()

	if major > 0 {
		upper, ok := semverutil.ParseVersion(fmt.Sprintf("%d.0.0", major+1))
		if !ok {
			return nil, false
		}
		return upper, true
	}
	if minor > 0 {
		upper, ok := semverutil.ParseVersion(fmt.Sprintf("0.%d.0", minor+1))
		if !ok {
			return nil, false
		}
		return upper, true
	}
	upper, ok := semverutil.ParseVersion(fmt.Sprintf("0.0.%d", patch+1))
	if !ok {
		return nil, false
	}
	return upper, true
}

func buildSemverUpdatePrompt(entries []internalSemverEntry) string {
	var updates []internalSemverEntry
	for _, entry := range entries {
		if len(entry.SuggestedRanges) == 0 {
			continue
		}
		updates = append(updates, entry)
	}

	if len(updates) == 0 {
		return ""
	}

	var b strings.Builder
	b.WriteString("Update suppline.yml using the semver recommendations below.\n")

	for _, entry := range updates {
		b.WriteString("- target: ")
		b.WriteString(entry.Target)
		b.WriteString("\n  semverRange: [")
		b.WriteString(strings.Join(entry.SuggestedRanges, ", "))
		b.WriteString("]\n")
	}

	return b.String()
}

func buildVEXExpiryPrompt(entries []VEXExpiryTaskEntry) string {
	if len(entries) == 0 {
		return ""
	}

	var b strings.Builder
	b.WriteString("Update suppline.yml VEX statements that are expired or expiring soon.\n")
	b.WriteString("For each entry, either extend expires_at with a justified new date or remove the vex statement if no longer needed.\n")

	for _, entry := range entries {
		b.WriteString("- cve_id: ")
		b.WriteString(entry.CVEID)
		b.WriteString("\n  status: ")
		b.WriteString(entry.Status)
		b.WriteString("\n  expires_at: ")
		b.WriteString(time.Unix(entry.ExpiresAt, 0).UTC().Format(time.RFC3339))
		b.WriteString("\n  repositories: [")
		b.WriteString(strings.Join(entry.Repositories, ", "))
		b.WriteString("]\n")
	}

	return b.String()
}
