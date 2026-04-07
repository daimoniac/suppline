package api

import (
	"bytes"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"

	semver "github.com/Masterminds/semver/v3"
	"gopkg.in/yaml.v3"
)

// SemverUpdateEntry describes the state of a single sync entry with semverRange.
type SemverUpdateEntry struct {
	Source             string   `json:"source"`
	Target             string   `json:"target"`
	CurrentRanges      []string `json:"current_ranges"`
	RuntimeVersions    []string `json:"runtime_versions"`
	OutOfRangeVersions []string `json:"out_of_range_versions"`
	SuggestedRanges    []string `json:"suggested_ranges,omitempty"`
	// Status is one of "current", "outdated", or "no_runtime_data".
	Status string `json:"status"`
}

// SemverUpdateTasksResponse is returned by GET /api/v1/tasks/semver-updates.
type SemverUpdateTasksResponse struct {
	Entries         []SemverUpdateEntry `json:"entries"`
	SuggestedConfig string              `json:"suggested_config"`
	NoRuntimeData   bool                `json:"no_runtime_data"`
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
			Entries:         []SemverUpdateEntry{},
			SuggestedConfig: "",
			NoRuntimeData:   false,
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

			// Build: imageRef → deduplicated set of semver tags
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

		// Join multiple range strings with a space; Masterminds treats spaces as AND.
		constraintStr := strings.Join(c.CurrentRanges, " ")
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

		suggestedLower := minVer.String()
		suggestedRange := fmt.Sprintf(">=%s", suggestedLower)

		if len(outOfRange) == 0 {
			c.Status = "current"
			if !sameSemverLowerOnlyRange(c.CurrentRanges, suggestedLower) {
				c.SuggestedRanges = []string{suggestedRange}
			}
			continue
		}

		c.Status = "outdated"
		c.SuggestedRanges = []string{suggestedRange}
	}

	// Build the public-facing entry list.
	publicEntries := make([]SemverUpdateEntry, len(candidates))
	for i, c := range candidates {
		publicEntries[i] = c.SemverUpdateEntry
	}

	// Generate an updated suppline.yml with suggested ranges applied.
	suggestedConfig := ""
	if !noRuntimeData {
		configPath := os.Getenv("SUPPLINE_CONFIG")
		if configPath == "" {
			configPath = "suppline.yml"
		}
		rawYAML, err := os.ReadFile(configPath)
		if err != nil {
			s.logger.Warn("could not read config file for suggested config generation", "path", configPath, "error", err)
		} else {
			updated, err := updateSemverRangesInYAML(rawYAML, candidates)
			if err != nil {
				s.logger.Warn("could not generate suggested config YAML", "error", err)
			} else {
				suggestedConfig = updated
			}
		}
	}

	s.respondJSON(w, http.StatusOK, SemverUpdateTasksResponse{
		Entries:         publicEntries,
		SuggestedConfig: suggestedConfig,
		NoRuntimeData:   noRuntimeData,
	})
}

var lowerOnlyRangeRe = regexp.MustCompile(`^>=\s*(\S+)\s*$`)

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

// updateSemverRangesInYAML parses rawYAML with yaml.Node (preserving template
// variables and comments) and replaces semverRange sequences for outdated entries.
func updateSemverRangesInYAML(rawYAML []byte, entries []internalSemverEntry) (string, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(rawYAML, &doc); err != nil {
		return "", fmt.Errorf("parse yaml: %w", err)
	}
	if len(doc.Content) == 0 {
		return string(rawYAML), nil
	}
	root := doc.Content[0]

	// Find the "sync" sequence in the root mapping.
	var syncSeq *yaml.Node
	for i := 0; i+1 < len(root.Content); i += 2 {
		if root.Content[i].Value == "sync" {
			syncSeq = root.Content[i+1]
			break
		}
	}
	if syncSeq == nil {
		return string(rawYAML), nil
	}

	for _, entry := range entries {
		if len(entry.SuggestedRanges) == 0 {
			continue
		}
		if entry.syncIndex >= len(syncSeq.Content) {
			continue
		}
		syncNode := syncSeq.Content[entry.syncIndex]

		// Navigate: sync entry mapping → "tags" → mapping → "semverRange" → sequence
		for i := 0; i+1 < len(syncNode.Content); i += 2 {
			if syncNode.Content[i].Value != "tags" {
				continue
			}
			tagsNode := syncNode.Content[i+1]
			for j := 0; j+1 < len(tagsNode.Content); j += 2 {
				if tagsNode.Content[j].Value != "semverRange" {
					continue
				}
				seqNode := tagsNode.Content[j+1]
				newItems := make([]*yaml.Node, len(entry.SuggestedRanges))
				for k, r := range entry.SuggestedRanges {
					newItems[k] = &yaml.Node{
						Kind:  yaml.ScalarNode,
						Value: r,
						Tag:   "!!str",
					}
				}
				seqNode.Content = newItems
				break
			}
			break
		}
	}

	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(&doc); err != nil {
		return "", fmt.Errorf("encode yaml: %w", err)
	}
	return buf.String(), nil
}
