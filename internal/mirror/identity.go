package mirror

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"

	"github.com/daimoniac/suppline/internal/config"
	"github.com/regclient/regclient/types/ref"
)

type keyedSync struct {
	key      string
	entry    config.SyncEntry
	position int
	schedule string
}

func assignSyncKeys(syncs []config.SyncEntry) []keyedSync {
	counts := map[string]int{}
	out := make([]keyedSync, len(syncs))
	for i, entry := range syncs {
		base := syncIdentityKey(entry)
		counts[base]++
		key := base
		if counts[base] > 1 {
			key = fmt.Sprintf("%s~%d", base, counts[base])
		}
		out[i] = keyedSync{
			key:      key,
			entry:    entry,
			position: i,
			schedule: scheduleLabel(entry),
		}
	}
	return out
}

func syncIdentityKey(entry config.SyncEntry) string {
	sum := sha256.Sum256([]byte(canonicalSyncIdentity(entry)))
	return hex.EncodeToString(sum[:8])
}

func canonicalSyncIdentity(entry config.SyncEntry) string {
	var b strings.Builder
	fmt.Fprintf(&b, "source=%s\ntarget=%s\ntype=%s\n", entry.Source, entry.Target, entry.Type)
	writeTagFilter(&b, "tags", entry.Tags)
	for i, set := range entry.TagSets {
		writeTagFilter(&b, fmt.Sprintf("tagset.%d", i), &set)
	}
	fmt.Fprintf(&b, "repos.allow=%s\nrepos.deny=%s\n", joinSorted(entry.Repos.Allow), joinSorted(entry.Repos.Deny))
	return b.String()
}

func writeTagFilter(b *strings.Builder, name string, filter *config.TagFilter) {
	if filter == nil {
		fmt.Fprintf(b, "%s=\n", name)
		return
	}
	fmt.Fprintf(b, "%s.allow=%s\n%s.deny=%s\n%s.semver=%s\n",
		name, joinSorted(filter.Allow),
		name, joinSorted(filter.Deny),
		name, joinSorted(filter.SemverRange),
	)
}

func joinSorted(values []string) string {
	if len(values) == 0 {
		return ""
	}
	copied := append([]string(nil), values...)
	slices.Sort(copied)
	return strings.Join(copied, ",")
}

func scheduleLabel(entry config.SyncEntry) string {
	if entry.Schedule != "" {
		return entry.Schedule
	}
	if entry.Interval != 0 {
		return "@every " + entry.Interval.String()
	}
	return ""
}

func targetRepoAndTag(raw string) (repository, tag string, ok bool) {
	parsed, err := ref.New(raw)
	if err != nil || parsed.Repository == "" {
		return "", "", false
	}
	return refRepository(parsed), parsed.Tag, true
}

func refRepository(parsed ref.Ref) string {
	if parsed.Registry != "" {
		return parsed.Registry + "/" + parsed.Repository
	}
	return parsed.Repository
}

func entryTargetsRepository(entry config.SyncEntry, repository string) bool {
	switch entry.Type {
	case "image", "repository":
		repo, _, ok := targetRepoAndTag(entry.Target)
		return ok && repo == repository
	case "registry":
		rel, ok := relativeRepo(entry.Target, repository)
		if !ok {
			return false
		}
		return repoAllowed(entry.Repos, rel)
	default:
		return false
	}
}

func entryWantsImage(entry config.SyncEntry, repository, tag string) bool {
	switch entry.Type {
	case "image":
		repo, wantTag, ok := targetRepoAndTag(entry.Target)
		if !ok || wantTag == "" {
			repo, wantTag, ok = targetRepoAndTag(entry.Source)
		}
		return ok && repo == repository && wantTag == tag
	case "repository", "registry":
		if !entryTargetsRepository(entry, repository) {
			return false
		}
		return tagAllowed(entry, tag)
	default:
		return false
	}
}

func tagAllowed(entry config.SyncEntry, tag string) bool {
	sets := entryTagSets(entry)
	if len(sets) == 0 {
		return true
	}
	for _, set := range sets {
		got, err := filterTagList(set, []string{tag})
		if err != nil {
			continue
		}
		if len(got) == 1 {
			return true
		}
	}
	return false
}

func repoAllowed(repos config.RepoFilter, name string) bool {
	got, err := filterRepoList(repos, []string{name})
	return err == nil && len(got) == 1
}

func relativeRepo(target, repository string) (string, bool) {
	target = strings.TrimSuffix(strings.TrimSpace(target), "/")
	if target == "" || repository == "" || repository == target {
		return "", false
	}
	if strings.HasPrefix(repository, target+"/") {
		return strings.TrimPrefix(repository, target+"/"), true
	}
	repo, _, ok := targetRepoAndTag(target)
	if !ok || repository == repo {
		return "", false
	}
	if strings.HasPrefix(repository, repo+"/") {
		return strings.TrimPrefix(repository, repo+"/"), true
	}
	return "", false
}
