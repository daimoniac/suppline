package statestore

import (
	"github.com/daimoniac/suppline/internal/semverutil"
)

// ImageUsage is the unified filter for runtime image usage in list and detail views.
type ImageUsage uint8

const (
	// ImageUsageAll: do not filter by in-use or semver-newer.
	ImageUsageAll ImageUsage = 0
	// ImageUsageInUse: only rows currently in use (runtime-observed).
	ImageUsageInUse ImageUsage = 1
	// ImageUsageNotInUse: only rows not in use.
	ImageUsageNotInUse ImageUsage = 2
	// ImageUsageInUseOrNewerSemver: in use, or image tag strictly greater than the max in-use tag in the repository.
	ImageUsageInUseOrNewerSemver ImageUsage = 3
)

func needsInUsePostFilter(f ImageUsage) bool {
	return f != ImageUsageAll
}

// inUseTagRow is one artifact row (repository + tag) with runtime in-use state.
type inUseTagRow struct {
	repository string
	tag        string
	used       bool
}

// maxInUseImageTagByRepository is the greatest in-use tag per repository, using the same
// ordering as semverutil.CompareImageTagOrder (strict SemVer plus multi-segment build numbers
// like 15.8.1.060 that are not valid SemVer 2.0 in Masterminds).
func maxInUseImageTagByRepository(rows []inUseTagRow) map[string]string {
	byRepo := make(map[string][]string)
	for _, row := range rows {
		if !row.used {
			continue
		}
		byRepo[row.repository] = append(byRepo[row.repository], row.tag)
	}
	out := make(map[string]string)
	for repo, tags := range byRepo {
		if m := semverutil.MaxImageTagInList(tags); m != "" {
			out[repo] = m
		}
	}
	return out
}

// recordPassesImageUsage returns whether a scan/tag row is visible for the given image usage mode.
// maxInUseTagByRepo comes from maxInUseImageTagByRepository (only for InUseOrNewer; may be nil).
func recordPassesImageUsage(used bool, repository, tag string, f ImageUsage, maxInUseTagByRepo map[string]string) bool {
	switch f {
	case ImageUsageAll:
		return true
	case ImageUsageInUse:
		return used
	case ImageUsageNotInUse:
		return !used
	case ImageUsageInUseOrNewerSemver:
		if used {
			return true
		}
		maxTag, ok := maxInUseTagByRepo[repository]
		if !ok || maxTag == "" {
			return false
		}
		return semverutil.ImageTagIsStrictlyGreater(tag, maxTag)
	default:
		return true
	}
}

// PolicyArtifactMatchesInUseOrNewer reports whether an artifact matches the "in use + newer" image
// filter: in runtime use, or tag strictly greater than the max in-use tag for the repository.
func PolicyArtifactMatchesInUseOrNewer(used bool, repository, tag string, maxInUseTagByRepo map[string]string) bool {
	return recordPassesImageUsage(used, repository, tag, ImageUsageInUseOrNewerSemver, maxInUseTagByRepo)
}
