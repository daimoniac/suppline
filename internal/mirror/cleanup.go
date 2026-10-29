package mirror

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/daimoniac/suppline/internal/config"
	"github.com/regclient/regclient"
	"github.com/regclient/regclient/types/errs"
	"github.com/regclient/regclient/types/ref"
)

// digestTagRe matches cosign-style digest tags "<alg>-<hex>.(att|sig)".
var digestTagRe = regexp.MustCompile(`^([a-z0-9]+)-([0-9a-f]+)\.(att|sig)$`)

func matchesExclusionPattern(tag string, patterns []string) (bool, string, error) {
	for _, pattern := range patterns {
		exp, err := regexp.Compile(pattern)
		if err != nil {
			return false, "", fmt.Errorf("invalid exclusion pattern %q: %w", pattern, err)
		}
		if exp.MatchString(tag) {
			return true, pattern, nil
		}
	}
	return false, "", nil
}

func isOrphanedDigestTag(ctx context.Context, rc *regclient.RegClient, tgtRef ref.Ref, tag string) (bool, error) {
	m := digestTagRe.FindStringSubmatch(tag)
	if m == nil {
		return false, nil
	}
	digestStr := m[1] + ":" + m[2]
	digestRef := tgtRef.SetTag("").SetDigest(digestStr)
	_, err := rc.ManifestHead(ctx, digestRef)
	if err == nil {
		return false, nil
	}
	if errors.Is(err, errs.ErrNotFound) || strings.Contains(err.Error(), "404") {
		return true, nil
	}
	return false, err
}

// tagsToDelete chooses tags that no sync entry wants.
// Orphaned .att/.sig tags are deleted even when a filter or exclusion would keep them.
func tagsToDelete(present, wanted, excludes []string, orphan func(string) (bool, error)) ([]string, error) {
	out := []string{}
	for _, tag := range present {
		if slices.Contains(wanted, tag) {
			orphaned, err := orphan(tag)
			if err != nil {
				return nil, err
			}
			if orphaned {
				out = append(out, tag)
			}
			continue
		}
		excluded, _, err := matchesExclusionPattern(tag, excludes)
		if err != nil {
			return nil, err
		}
		if excluded {
			orphaned, err := orphan(tag)
			if err != nil {
				return nil, err
			}
			if !orphaned {
				continue
			}
		}
		out = append(out, tag)
	}
	return out, nil
}

func (m *runner) findSyncEntriesForTarget(tgt string) []config.SyncEntry {
	var entries []config.SyncEntry
	for _, sync := range m.cfg.Sync {
		if sync.Target == tgt {
			entries = append(entries, sync)
		}
	}
	return entries
}

func (m *runner) cleanupTags(ctx context.Context, tgt string) error {
	tgtRef, err := ref.New(tgt)
	if err != nil {
		return err
	}
	tTags, err := m.rc.TagList(ctx, tgtRef)
	if err != nil {
		return err
	}
	tTagsList, err := tTags.GetTags()
	if err != nil {
		return err
	}

	syncEntries := m.findSyncEntriesForTarget(tgt)
	wanted, excludes, err := wantedTags(syncEntries, tTagsList)
	if err != nil {
		return err
	}
	toDelete, err := tagsToDelete(tTagsList, wanted, excludes, func(tag string) (bool, error) {
		return isOrphanedDigestTag(ctx, m.rc, tgtRef, tag)
	})
	if err != nil {
		return err
	}

	var errs []error
	for _, tag := range toDelete {
		if err := ctx.Err(); err != nil {
			return err
		}
		m.log.Info("deleting tag", "target", tgtRef.CommonName(), "tag", tag)
		if err := m.rc.TagDelete(ctx, tgtRef.SetTag(tag)); err != nil {
			m.log.Error("failed to delete tag", "target", tgtRef.CommonName(), "tag", tag, "error", err.Error())
			errs = append(errs, fmt.Errorf("delete tag %s:%s: %w", tgtRef.CommonName(), tag, err))
		}
	}
	return errors.Join(errs...)
}

func wantedTags(entries []config.SyncEntry, present []string) (wanted, excludes []string, err error) {
	allSetsEmpty := true
	for _, syncEntry := range entries {
		sets := entryTagSets(syncEntry)
		if len(sets) > 0 {
			allSetsEmpty = false
			for _, set := range sets {
				filtered, ferr := filterTagList(set, present)
				if ferr != nil {
					return nil, nil, ferr
				}
				for _, tag := range filtered {
					if !slices.Contains(wanted, tag) {
						wanted = append(wanted, tag)
					}
				}
			}
		}
		excludes = append(excludes, syncEntry.CleanupTagsExclude...)
	}
	if allSetsEmpty {
		wanted = present
	}
	return wanted, excludes, nil
}

func (m *runner) runCleanupForAllTargets(ctx context.Context) error {
	targetMap := map[string]struct{}{}
	for _, s := range m.cfg.Sync {
		if s.Target == "" || s.CleanupTags == nil || !*s.CleanupTags {
			continue
		}
		targetMap[s.Target] = struct{}{}
	}
	if len(targetMap) == 0 {
		m.log.Debug("no targets with cleanup enabled")
		return nil
	}
	m.log.Info("running startup cleanup", "targets", len(targetMap))
	var errs []error
	for tgt := range targetMap {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := m.cleanupTags(ctx, tgt); err != nil {
			m.log.Error("startup cleanup failed", "target", tgt, "error", err.Error())
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
