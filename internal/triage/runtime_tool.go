package triage

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/daimoniac/suppline/internal/statestore"
)

// clusterRuntimeStore reads the latest snapshots reported by cluster agents.
type clusterRuntimeStore interface {
	ListClusterSummaries(ctx context.Context) ([]statestore.ClusterSummary, error)
	SearchClusterImages(ctx context.Context, cluster, namespace, image string, limit int) ([]statestore.ClusterRuntimeHit, error)
}

// runtimeTool answers cluster_runtime lookups. Results are capped.
type runtimeTool struct {
	store clusterRuntimeStore
}

func (t runtimeTool) Query(ctx context.Context, cluster, namespace, image string) (string, error) {
	if t.store == nil {
		return "", fmt.Errorf("cluster runtime is unavailable")
	}
	cluster = strings.TrimSpace(cluster)
	namespace = strings.TrimSpace(namespace)
	image = strings.TrimSpace(image)
	if image == "" && namespace == "" {
		return t.summaries(ctx, cluster)
	}
	if cluster != "" {
		if err := t.knownCluster(ctx, cluster); err != nil {
			return "", err
		}
	}
	hits, err := t.store.SearchClusterImages(ctx, cluster, namespace, image, maxToolMatches+1)
	if err != nil {
		return "", err
	}
	if len(hits) == 0 {
		return "", nil
	}
	truncated := len(hits) > maxToolMatches
	if truncated {
		hits = hits[:maxToolMatches]
	}
	var b strings.Builder
	for _, hit := range hits {
		ref := hit.ImageRef
		if hit.Tag != "" && !strings.Contains(ref, ":"+hit.Tag) && !strings.Contains(ref, "@") {
			ref += ":" + hit.Tag
		}
		fmt.Fprintf(&b, "%s/%s %s %s\n", hit.Cluster, hit.Namespace, ref, hit.Digest)
	}
	if truncated {
		b.WriteString("... truncated, narrow the image or namespace\n")
	}
	return b.String(), nil
}

func (t runtimeTool) summaries(ctx context.Context, cluster string) (string, error) {
	summaries, err := t.store.ListClusterSummaries(ctx)
	if err != nil {
		return "", err
	}
	if cluster != "" {
		if err := matchCluster(summaries, cluster); err != nil {
			return "", err
		}
	}
	var b strings.Builder
	for _, summary := range summaries {
		if cluster != "" && !strings.EqualFold(summary.Name, cluster) {
			continue
		}
		reported := "never"
		if summary.LastReported != nil && *summary.LastReported > 0 {
			reported = time.Unix(*summary.LastReported, 0).UTC().Format(time.RFC3339)
		}
		fmt.Fprintf(&b, "%s images=%d reported=%s\n", summary.Name, summary.ImageCount, reported)
	}
	if cluster != "" {
		b.WriteString("pass image or namespace to list workloads\n")
	}
	return b.String(), nil
}

func (t runtimeTool) knownCluster(ctx context.Context, cluster string) error {
	summaries, err := t.store.ListClusterSummaries(ctx)
	if err != nil {
		return err
	}
	return matchCluster(summaries, cluster)
}

func matchCluster(summaries []statestore.ClusterSummary, cluster string) error {
	names := make([]string, 0, len(summaries))
	for _, summary := range summaries {
		if strings.EqualFold(summary.Name, cluster) {
			return nil
		}
		names = append(names, summary.Name)
	}
	if len(names) == 0 {
		return fmt.Errorf("unknown cluster %q", cluster)
	}
	return fmt.Errorf("unknown cluster %q, known clusters: %s", cluster, strings.Join(names, ", "))
}
