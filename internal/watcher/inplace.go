package watcher

import (
	"context"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/daimoniac/suppline/internal/config"
	"github.com/daimoniac/suppline/internal/statestore"
	"github.com/daimoniac/suppline/internal/tagselect"
)

// builtTTL is how long the build time read for a tag is trusted. CI tags are
// not re-pushed in practice; a stale value can only shift which tags fall in a
// newest window.
const builtTTL = 24 * time.Hour

// inPlaceTags returns the tags of an in-place repository to scan: the ones the
// entry's tag sets select, plus every tag a cluster runs, so a running image
// keeps being rescanned and its attestation renewed after newer builds push it
// out of the newest window. The mirror does the same with cleanupKeepRunning.
func (w *watcherImpl) inPlaceTags(ctx context.Context, repo string, entry config.SyncEntry) ([]string, error) {
	all, err := w.registryClient.ListTags(ctx, repo)
	if err != nil {
		return nil, fmt.Errorf("failed to list tags: %w", err)
	}
	w.built.retain(repo, all)
	selected, err := tagselect.Select(entry, all, func(tag string) (time.Time, error) {
		return w.builtAt(ctx, repo, tag)
	})
	if err != nil {
		return nil, fmt.Errorf("select tags: %w", err)
	}
	running, err := w.runningTags(ctx, repo)
	if err != nil {
		// Without inventory the window alone is scanned; running tags outside
		// it come back on the next cycle that can read the inventory.
		w.logger.Warn("failed to read cluster inventory for in-place repository", "repo", repo, "error", err)
	}
	for _, tag := range all {
		if _, ok := running[tag]; ok && !slices.Contains(selected, tag) {
			selected = append(selected, tag)
		}
	}
	return selected, nil
}

// builtAt returns when the image behind tag was built. Unknown build times
// are the zero time, which sorts oldest.
func (w *watcherImpl) builtAt(ctx context.Context, repo, tag string) (time.Time, error) {
	if at, ok := w.built.get(repo, tag); ok {
		return at, nil
	}
	digest, err := w.registryClient.GetDigest(ctx, repo, tag)
	if err != nil {
		return time.Time{}, fmt.Errorf("resolve %s:%s: %w", repo, tag, err)
	}
	manifest, err := w.registryClient.GetManifest(ctx, repo, digest)
	if err != nil {
		return time.Time{}, fmt.Errorf("read manifest %s@%s: %w", repo, digest, err)
	}
	var at time.Time
	if manifest != nil && manifest.CreatedAt != nil {
		at = manifest.CreatedAt.UTC()
	}
	w.built.put(repo, tag, at)
	return at, nil
}

// clusterInventory is the clusterstate-agent inventory the watcher reads to
// keep running tags of an in-place repository in scan.
type clusterInventory interface {
	ListClusterSummaries(ctx context.Context) ([]statestore.ClusterSummary, error)
	ListClusterImages(ctx context.Context, clusterName string) ([]statestore.ClusterImageSummary, error)
}

// runningTags returns the tags of repo that the latest report of any cluster runs.
func (w *watcherImpl) runningTags(ctx context.Context, repo string) (map[string]struct{}, error) {
	tags := map[string]struct{}{}
	inventory, ok := w.stateStore.(clusterInventory)
	if !ok {
		return tags, nil
	}
	clusters, err := inventory.ListClusterSummaries(ctx)
	if err != nil {
		return tags, fmt.Errorf("list clusters: %w", err)
	}
	want := statestore.NormalizeRepositoryRef(repo)
	for _, cluster := range clusters {
		if cluster.LastReported == nil {
			continue
		}
		images, err := inventory.ListClusterImages(ctx, cluster.Name)
		if err != nil {
			return tags, fmt.Errorf("list images of cluster %s: %w", cluster.Name, err)
		}
		for _, image := range images {
			if image.Tag != "" && statestore.NormalizeRepositoryRef(image.ImageRef) == want {
				tags[image.Tag] = struct{}{}
			}
		}
	}
	return tags, nil
}

// builtCache remembers build times per repository and tag, in memory only.
type builtCache struct {
	mu    sync.Mutex
	repos map[string]map[string]builtEntry
	now   func() time.Time
}

type builtEntry struct {
	at   time.Time
	read time.Time
}

func (c *builtCache) get(repo, tag string) (time.Time, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.repos[repo][tag]
	if !ok || c.clock().Sub(entry.read) > builtTTL {
		return time.Time{}, false
	}
	return entry.at, true
}

func (c *builtCache) put(repo, tag string, at time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.repos == nil {
		c.repos = map[string]map[string]builtEntry{}
	}
	if c.repos[repo] == nil {
		c.repos[repo] = map[string]builtEntry{}
	}
	c.repos[repo][tag] = builtEntry{at: at, read: c.clock()}
}

// retain forgets tags that are gone from the repository.
func (c *builtCache) retain(repo string, tags []string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	known := c.repos[repo]
	for tag := range known {
		if !slices.Contains(tags, tag) {
			delete(known, tag)
		}
	}
}

func (c *builtCache) clock() time.Time {
	if c.now != nil {
		return c.now()
	}
	return time.Now()
}
