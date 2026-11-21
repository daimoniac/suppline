package mirror

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/regclient/regclient"
	"github.com/regclient/regclient/types/ref"

	"github.com/daimoniac/suppline/internal/config"
)

// createdTTL is how long a tag's build time is trusted before it is read
// again. Only a re-pushed tag changes it, and a stale value can only shift
// which tags fall inside a newest window, never what is copied for a tag.
const createdTTL = 24 * time.Hour

// selectNewest keeps the n tags built last. Ties, including images whose
// created field is unset or fixed by a reproducible build, go to the higher
// tag name. n <= 0 keeps every tag. The result is newest first.
func selectNewest(tags []string, n int, created func(tag string) (time.Time, error)) ([]string, error) {
	if n <= 0 || len(tags) <= n {
		return tags, nil
	}
	type dated struct {
		tag     string
		created time.Time
	}
	all := make([]dated, 0, len(tags))
	for _, tag := range tags {
		at, err := created(tag)
		if err != nil {
			return nil, err
		}
		all = append(all, dated{tag: tag, created: at})
	}
	slices.SortFunc(all, func(a, b dated) int {
		if c := b.created.Compare(a.created); c != 0 {
			return c
		}
		return strings.Compare(b.tag, a.tag)
	})
	out := make([]string, 0, n)
	for _, d := range all[:n] {
		out = append(out, d.tag)
	}
	return out, nil
}

// createdCache remembers when the image behind each tag was built, per
// repository. It lives in memory only: after a restart the times are read
// again from the registry, so the database stays safe to throw away.
type createdCache struct {
	mu    sync.Mutex
	repos map[string]map[string]createdEntry
	now   func() time.Time
}

type createdEntry struct {
	created time.Time
	readAt  time.Time
}

func newCreatedCache() *createdCache {
	return &createdCache{repos: map[string]map[string]createdEntry{}, now: time.Now}
}

func (c *createdCache) get(repo, tag string) (time.Time, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.repos[repo][tag]
	if !ok || c.now().Sub(e.readAt) > createdTTL {
		return time.Time{}, false
	}
	return e.created, true
}

func (c *createdCache) put(repo, tag string, created time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.repos[repo] == nil {
		c.repos[repo] = map[string]createdEntry{}
	}
	c.repos[repo][tag] = createdEntry{created: created, readAt: c.now()}
}

// retain forgets the tags of repo that are no longer listed.
func (c *createdCache) retain(repo string, tags []string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	cached := c.repos[repo]
	if cached == nil {
		return
	}
	keep := make(map[string]struct{}, len(tags))
	for _, tag := range tags {
		keep[tag] = struct{}{}
	}
	for tag := range cached {
		if _, ok := keep[tag]; !ok {
			delete(cached, tag)
		}
	}
}

// newestTags applies the set's newest window to tags of repo, which have
// already passed the set's allow, deny and semver filters.
func (m *runner) newestTags(ctx context.Context, s config.SyncEntry, set config.TagFilter, repo string, tags []string) ([]string, error) {
	if set.Newest <= 0 || len(tags) <= set.Newest {
		return tags, nil
	}
	cache := m.created
	if cache == nil {
		cache = newCreatedCache()
	}
	var opts []regclient.ImageOpts
	switch {
	case s.Platform != "":
		opts = append(opts, regclient.ImageWithPlatform(s.Platform))
	case len(s.Platforms) > 0:
		opts = append(opts, regclient.ImageWithPlatform(s.Platforms[0]))
	}
	return selectNewest(tags, set.Newest, func(tag string) (time.Time, error) {
		if at, ok := cache.get(repo, tag); ok {
			return at, nil
		}
		r, err := ref.New(repo + ":" + tag)
		if err != nil {
			return time.Time{}, fmt.Errorf("parse %s:%s: %w", repo, tag, err)
		}
		cfg, err := m.rc.ImageConfig(ctx, r, opts...)
		if err != nil {
			return time.Time{}, fmt.Errorf("read build time of %s: %w", r.CommonName(), err)
		}
		var at time.Time
		if c := cfg.GetConfig().Created; c != nil {
			at = c.UTC()
		}
		cache.put(repo, tag, at)
		return at, nil
	})
}

// selectTags returns the tags of repo that any of the entry's tag sets
// selects. Without tag sets every tag is selected.
func (m *runner) selectTags(ctx context.Context, s config.SyncEntry, repo string, tags []string) ([]string, error) {
	sets := entryTagSets(s)
	if len(sets) == 0 {
		return tags, nil
	}
	if m.created != nil {
		m.created.retain(repo, tags)
	}
	selected := []string{}
	for _, set := range sets {
		filtered, err := filterTagList(set, tags)
		if err != nil {
			return nil, err
		}
		filtered, err = m.newestTags(ctx, s, set, repo, filtered)
		if err != nil {
			return nil, err
		}
		for _, tag := range filtered {
			if !slices.Contains(selected, tag) {
				selected = append(selected, tag)
			}
		}
	}
	return selected, nil
}
