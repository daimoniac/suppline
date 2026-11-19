package mirror

import (
	"context"
	"fmt"

	"github.com/daimoniac/suppline/internal/statestore"
)

// ClusterInventory is the clusterstate-agent inventory cleanup reads to keep
// tags that are still running.
type ClusterInventory interface {
	ListClusterSummaries(ctx context.Context) ([]statestore.ClusterSummary, error)
	ListClusterImages(ctx context.Context, clusterName string) ([]statestore.ClusterImageSummary, error)
}

// WithInventory lets cleanup keep target tags a cluster reports running, for
// sync entries with cleanupKeepRunning.
func WithInventory(inv ClusterInventory) Option {
	return func(m *runner) {
		m.inventory = inv
	}
}

// runningTags returns the tags of repository that the latest report of any
// cluster runs, stale clusters included. known is false when no cluster has
// reported, for example right after the database was rebuilt: then nobody can
// say which tags run.
func (m *runner) runningTags(ctx context.Context, repository string) (tags map[string]struct{}, known bool, err error) {
	if m.inventory == nil {
		return nil, false, nil
	}
	clusters, err := m.inventory.ListClusterSummaries(ctx)
	if err != nil {
		return nil, false, fmt.Errorf("list clusters: %w", err)
	}
	want := statestore.NormalizeRepositoryRef(repository)
	tags = map[string]struct{}{}
	for _, cluster := range clusters {
		if cluster.LastReported == nil {
			continue
		}
		known = true
		images, err := m.inventory.ListClusterImages(ctx, cluster.Name)
		if err != nil {
			return nil, false, fmt.Errorf("list images of cluster %s: %w", cluster.Name, err)
		}
		for _, image := range images {
			if image.Tag == "" || statestore.NormalizeRepositoryRef(image.ImageRef) != want {
				continue
			}
			tags[image.Tag] = struct{}{}
		}
	}
	return tags, known, nil
}

// keepRunning drops from toDelete the tags a cluster runs. When no cluster
// has reported it keeps every tag except cosign digest tags, whose deletion
// only follows their subject.
func (m *runner) keepRunning(ctx context.Context, repository string, toDelete []string) ([]string, error) {
	running, known, err := m.runningTags(ctx, repository)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(toDelete))
	for _, tag := range toDelete {
		if isCosignTag(tag) {
			out = append(out, tag)
			continue
		}
		if !known {
			continue
		}
		if _, ok := running[tag]; ok {
			m.log.Info("keeping running tag", "target", repository, "tag", tag)
			continue
		}
		out = append(out, tag)
	}
	if !known && len(out) < len(toDelete) {
		m.log.Warn("no cluster inventory yet; cleanup keeps tags it would delete", "target", repository, "kept", len(toDelete)-len(out))
	}
	return out, nil
}

func isCosignTag(tag string) bool {
	return digestTagRe.MatchString(tag) || cosignFallbackTagRe.MatchString(tag)
}
