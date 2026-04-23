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
	// ImageUsageInUseOrNewerSemver: in use, or image tag strictly greater than the minimum in-use tag
	// (i.e. not strictly older than every in-use tag — includes intermediate versions between deployed lines).
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

// latestArtifactTagRow is one (repository, tag, digest) from the global latest-per-tag artifact table.
type latestArtifactTagRow struct {
	repo, tag, digest string
}

// runtimeUseForDigest returns in-use state and the merged runtime payload for a digest
// (same keys as GetRuntimeUsageForScans).
func runtimeUseForDigest(usageByDigest map[string]RuntimeUsage, digest string) (used bool, u RuntimeUsage) {
	u, ok := usageByDigest[digest]
	if !ok {
		return false, RuntimeUsage{}
	}
	return u.RuntimeUsed, u
}

func appendInUseTagRow(out []inUseTagRow, repository, tag, digest string, usageByDigest map[string]RuntimeUsage) []inUseTagRow {
	used, _ := runtimeUseForDigest(usageByDigest, digest)
	return append(out, inUseTagRow{repository: repository, tag: tag, used: used})
}

// inUseTagRowsFromScanRecords builds rows for max-in-use computation from a list scan.
func inUseTagRowsFromScanRecords(records []*ScanRecord, usageByDigest map[string]RuntimeUsage) []inUseTagRow {
	out := make([]inUseTagRow, 0, len(records))
	for _, record := range records {
		out = appendInUseTagRow(out, record.Repository, record.Tag, record.Digest, usageByDigest)
	}
	return out
}

// inUseTagRowsFromRepositoryTags builds rows for max-in-use from repository detail tags.
func inUseTagRowsFromRepositoryTags(repositoryName string, tags []TagInfo, usageByDigest map[string]RuntimeUsage) []inUseTagRow {
	out := make([]inUseTagRow, 0, len(tags))
	for _, tag := range tags {
		out = appendInUseTagRow(out, repositoryName, tag.Name, tag.Digest, usageByDigest)
	}
	return out
}

// inUseTagRowsFromLatestArtifactRows builds rows from global latest (repository, tag, digest) tuples.
func inUseTagRowsFromLatestArtifactRows(rows []latestArtifactTagRow, usageByDigest map[string]RuntimeUsage) []inUseTagRow {
	out := make([]inUseTagRow, 0, len(rows))
	for _, row := range rows {
		out = appendInUseTagRow(out, row.repo, row.tag, row.digest, usageByDigest)
	}
	return out
}

// minInUseImageTagByRepository is the smallest in-use tag per repository (the "floor" below which
// unscanned tags are hidden for InUseOrNewer). Uses semverutil.CompareImageTagOrder.
func minInUseImageTagByRepository(rows []inUseTagRow) map[string]string {
	byRepo := make(map[string][]string)
	for _, row := range rows {
		if !row.used {
			continue
		}
		byRepo[row.repository] = append(byRepo[row.repository], row.tag)
	}
	out := make(map[string]string)
	for repo, tags := range byRepo {
		if m := semverutil.MinImageTagInList(tags); m != "" {
			out[repo] = m
		}
	}
	return out
}

// matchesInUseOrNewer is the "in use + newer" visibility predicate: in runtime use, or a tag
// strictly greater than the minimum in-use tag for that repository (so intermediate releases
// between different deployed versions still appear).
func matchesInUseOrNewer(used bool, repository, tag string, minInUseTagByRepo map[string]string) bool {
	if used {
		return true
	}
	minTag, ok := minInUseTagByRepo[repository]
	if !ok || minTag == "" {
		return false
	}
	return semverutil.ImageTagIsStrictlyGreater(tag, minTag)
}

// recordPassesImageUsage returns whether a scan/tag row is visible for the given image usage mode.
// minInUseTagByRepo comes from minInUseImageTagByRepository (only for InUseOrNewer; may be nil).
func recordPassesImageUsage(used bool, repository, tag string, f ImageUsage, minInUseTagByRepo map[string]string) bool {
	switch f {
	case ImageUsageAll:
		return true
	case ImageUsageInUse:
		return used
	case ImageUsageNotInUse:
		return !used
	case ImageUsageInUseOrNewerSemver:
		return matchesInUseOrNewer(used, repository, tag, minInUseTagByRepo)
	default:
		return true
	}
}

// filterScanRecordsByImageUsage filters and annotates scan rows with runtime fields (in-memory post-filter).
func filterScanRecordsByImageUsage(
	records []*ScanRecord,
	usageByDigest map[string]RuntimeUsage,
	minTagByRepo map[string]string,
	filter ImageUsage,
) []*ScanRecord {
	filtered := make([]*ScanRecord, 0, len(records))
	for _, record := range records {
		used, u := runtimeUseForDigest(usageByDigest, record.Digest)
		if !recordPassesImageUsage(used, record.Repository, record.Tag, filter, minTagByRepo) {
			continue
		}
		record.RuntimeUsed = used
		if used {
			record.Runtime = u.Runtime
		}
		filtered = append(filtered, record)
	}
	return filtered
}

// filterTagInfoByImageUsage filters and annotates tag rows for a single repository.
func filterTagInfoByImageUsage(
	tags []TagInfo,
	repositoryName string,
	usageByDigest map[string]RuntimeUsage,
	minTagByRepo map[string]string,
	filter ImageUsage,
) []TagInfo {
	filtered := make([]TagInfo, 0, len(tags))
	for _, tag := range tags {
		used, u := runtimeUseForDigest(usageByDigest, tag.Digest)
		if !recordPassesImageUsage(used, repositoryName, tag.Name, filter, minTagByRepo) {
			continue
		}
		tag.RuntimeUsed = used
		if used {
			tag.Runtime = u.Runtime
		}
		filtered = append(filtered, tag)
	}
	return filtered
}

// PolicyArtifactMatchesInUseOrNewer reports whether an artifact matches the "in use + newer" image
// filter: in runtime use, or tag strictly greater than the minimum in-use tag for the repository.
func PolicyArtifactMatchesInUseOrNewer(used bool, repository, tag string, minInUseTagByRepo map[string]string) bool {
	return matchesInUseOrNewer(used, repository, tag, minInUseTagByRepo)
}
