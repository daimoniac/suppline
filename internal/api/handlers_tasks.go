package api

import (
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strings"

	semver "github.com/Masterminds/semver/v3"
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
	for i, entry := range s.regsyncConfig.Sync {
		if entry.Tags == nil || len(entry.Tags.SemverRange) == 0 {
			continue
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
	}

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

			// Build: imageRef -> deduplicated set of semver tags
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
					if _, err := semver.NewVersion(img.Tag); err != nil {
						continue // not a semver tag
					}
					if _, ok := imageTagMap[img.ImageRef]; !ok {
						imageTagMap[img.ImageRef] = make(map[string]struct{})
					}
					imageTagMap[img.ImageRef][img.Tag] = struct{}{}
				}
			}

			// Match runtime images to sync entries by comparing imageRef to entry.Target.
			for i := range candidates {
				c := &candidates[i]
				for imageRef, tagSet := range imageTagMap {
					if !strings.EqualFold(imageRef, c.Target) {
						continue
					}
					for tag := range tagSet {
						c.RuntimeVersions = append(c.RuntimeVersions, tag)
					}
				}
				sort.Slice(c.RuntimeVersions, func(a, b int) bool {
					va, _ := semver.NewVersion(c.RuntimeVersions[a])
					vb, _ := semver.NewVersion(c.RuntimeVersions[b])
					return va.LessThan(vb)
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
		constraint, err := semver.NewConstraint(constraintStr)
		if err != nil {
			s.logger.Warn("failed to parse semver constraint", "constraint", constraintStr, "error", err)
			c.Status = "no_runtime_data"
			continue
		}

		var outOfRange []*semver.Version
		var allVersions []*semver.Version
		for _, tag := range c.RuntimeVersions {
			v, err := semver.NewVersion(tag)
			if err != nil {
				continue
			}
			allVersions = append(allVersions, v)
			if !constraint.Check(v) {
				outOfRange = append(outOfRange, v)
				c.OutOfRangeVersions = append(c.OutOfRangeVersions, tag)
			}
		}

		if len(allVersions) == 0 {
			c.Status = "no_runtime_data"
			continue
		}

		sort.Slice(allVersions, func(a, b int) bool { return allVersions[a].LessThan(allVersions[b]) })
		minVer := allVersions[0]

		suggestedLower := suggestedLowerBound(minVer, c.CurrentRanges)
		suggestedRange := formatSuggestedLowerOnlyRange(suggestedLower, strings.Join(c.CurrentRanges, " "))
		tightenRanges, hasTighteningSuggestion := suggestedRangesForTighten(c.CurrentRanges, allVersions)

		if len(outOfRange) == 0 {
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
	currentLower, err := semver.NewVersion(m[1])
	if err != nil {
		return false
	}
	proposed, err := semver.NewVersion(proposedLower)
	if err != nil {
		return false
	}
	return currentLower.Equal(proposed)
}

func suggestedLowerBound(minVer *semver.Version, currentRanges []string) string {
	if !rangesIncludePrereleaseMarker(currentRanges) {
		return minVer.String()
	}

	// Keep prerelease inclusion semantics when existing constraints use -0.
	return fmt.Sprintf("%d.%d.%d-0", minVer.Major(), minVer.Minor(), minVer.Patch())
}

func rangesIncludePrereleaseMarker(ranges []string) bool {
	for _, r := range ranges {
		if strings.Contains(r, "-0") {
			return true
		}
	}
	return false
}

func suggestedRangesForTighten(currentRanges []string, runtimeVersions []*semver.Version) ([]string, bool) {
	suggested := make([]string, 0, len(currentRanges))
	changed := false
	sort.Slice(runtimeVersions, func(i, j int) bool { return runtimeVersions[i].LessThan(runtimeVersions[j]) })
	runtimeFloor := runtimeVersions[0]

	for _, current := range currentRanges {
		constraint, err := semver.NewConstraint(current)
		if err != nil {
			suggested = append(suggested, current)
			continue
		}

		matching := make([]*semver.Version, 0, len(runtimeVersions))
		for _, v := range runtimeVersions {
			if constraint.Check(v) {
				matching = append(matching, v)
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

		sort.Slice(matching, func(i, j int) bool { return matching[i].LessThan(matching[j]) })
		trimmedCurrent := strings.TrimSpace(current)
		if exactVersionRangeRe.MatchString(trimmedCurrent) {
			suggested = append(suggested, trimmedCurrent)
			continue
		}

		lower := suggestedLowerBound(matching[0], []string{current})
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
		v, err := semver.NewVersion(verStr)
		if err != nil {
			continue
		}

		if inclusive {
			if v.LessThan(floor) {
				return true
			}
			continue
		}

		if v.LessThan(floor) || v.Equal(floor) {
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
				if upper.LessThan(floor) || upper.Equal(floor) {
					return true
				}
			}
		}

		if strings.HasPrefix(token, "^") {
			if upper, ok := inferredUpperBoundForCaret(strings.TrimPrefix(token, "^")); ok {
				if upper.LessThan(floor) || upper.Equal(floor) {
					return true
				}
			}
		}

		if exactVersionRangeRe.MatchString(token) {
			v, err := semver.NewVersion(token)
			if err == nil && v.LessThan(floor) {
				return true
			}
		}
	}

	return false
}

func inferredUpperBoundForTilde(raw string) (*semver.Version, bool) {
	v, err := semver.NewVersion(raw)
	if err != nil {
		return nil, false
	}
	upper, err := semver.NewVersion(fmt.Sprintf("%d.%d.0", v.Major(), v.Minor()+1))
	if err != nil {
		return nil, false
	}
	return upper, true
}

func inferredUpperBoundForCaret(raw string) (*semver.Version, bool) {
	v, err := semver.NewVersion(raw)
	if err != nil {
		return nil, false
	}

	major := v.Major()
	minor := v.Minor()
	patch := v.Patch()

	if major > 0 {
		upper, err := semver.NewVersion(fmt.Sprintf("%d.0.0", major+1))
		if err != nil {
			return nil, false
		}
		return upper, true
	}
	if minor > 0 {
		upper, err := semver.NewVersion(fmt.Sprintf("0.%d.0", minor+1))
		if err != nil {
			return nil, false
		}
		return upper, true
	}
	upper, err := semver.NewVersion(fmt.Sprintf("0.0.%d", patch+1))
	if err != nil {
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
