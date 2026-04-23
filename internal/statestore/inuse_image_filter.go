package statestore

import (
	semver "github.com/Masterminds/semver/v3"
	"github.com/daimoniac/suppline/internal/semverutil"
)

// InUseImageFilter extends runtime "in use" filtering for API consumers.
// Unspecified means use only the legacy InUse *bool on filters.
type InUseImageFilter uint8

const (
	// InUseImageFilterUnspecified: use InUse *bool only (legacy).
	InUseImageFilterUnspecified InUseImageFilter = 0
	// InUseImageFilterInUseOrNewerSemver includes rows in use plus tags whose semver is
	// greater than the maximum semver among in-use tags in the same repository.
	InUseImageFilterInUseOrNewerSemver InUseImageFilter = 1
)

func inUseImageFilterApplies(f InUseImageFilter) bool {
	return f == InUseImageFilterInUseOrNewerSemver
}

// needsInUsePostFilter reports whether list endpoints must post-filter using runtime data.
func needsInUsePostFilter(inUse *bool, f InUseImageFilter) bool {
	return inUse != nil || inUseImageFilterApplies(f)
}

// inUseTagRow is one artifact row (repository + tag) with runtime in-use state.
type inUseTagRow struct {
	repository string
	tag        string
	used       bool
}

// maxInUseSemverByRepository builds, for each repository, the max semver among tags
// that are currently in use.
func maxInUseSemverByRepository(rows []inUseTagRow) map[string]*semver.Version {
	out := make(map[string]*semver.Version)
	for _, row := range rows {
		if !row.used {
			continue
		}
		v, ok := semverutil.ParseVersion(row.tag)
		if !ok {
			continue
		}
		cur, has := out[row.repository]
		if !has || v.GreaterThan(cur) {
			out[row.repository] = v
		}
	}
	return out
}

// recordPassesInUseImageFilter applies legacy InUse *bool or InUseOrNewerSemver rules.
func recordPassesInUseImageFilter(used bool, repository, tag string, inUse *bool, f InUseImageFilter, maxInUseByRepo map[string]*semver.Version) bool {
	if inUseImageFilterApplies(f) {
		if used {
			return true
		}
		maxInUse := maxInUseByRepo[repository]
		v, ok := semverutil.ParseVersion(tag)
		if !ok || maxInUse == nil {
			return false
		}
		return v.GreaterThan(maxInUse)
	}
	if inUse == nil {
		return true
	}
	return used == *inUse
}
