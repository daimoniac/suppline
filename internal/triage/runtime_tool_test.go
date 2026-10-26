package triage

import (
	"context"
	"strings"
	"testing"

	"github.com/daimoniac/suppline/internal/statestore"
)

type stubClusterStore struct {
	summaries []statestore.ClusterSummary
	hits      []statestore.ClusterRuntimeHit
}

func (s stubClusterStore) ListClusterSummaries(context.Context) ([]statestore.ClusterSummary, error) {
	return s.summaries, nil
}

func (s stubClusterStore) SearchClusterImages(context.Context, string, string, string, int) ([]statestore.ClusterRuntimeHit, error) {
	return s.hits, nil
}

func TestRuntimeToolListsClustersAndImages(t *testing.T) {
	reported := int64(1_760_000_000)
	tool := runtimeTool{store: stubClusterStore{
		summaries: []statestore.ClusterSummary{
			{Name: "internal1", ImageCount: 335, LastReported: &reported},
			{Name: "hetzner1", ImageCount: 102},
		},
		hits: []statestore.ClusterRuntimeHit{{
			Cluster: "internal1", Namespace: "kube-system", ImageRef: "ghcr.io/example/nginx", Tag: "1.29.5", Digest: "sha256:abc",
		}},
	}}

	summary, err := tool.Query(context.Background(), "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(summary, "internal1 images=335 reported=2025-10-09T08:53:20Z") || !strings.Contains(summary, "hetzner1 images=102 reported=never") {
		t.Fatalf("summary = %q", summary)
	}

	one, err := tool.Query(context.Background(), "internal1", "", "")
	if err != nil || !strings.Contains(one, "pass image or namespace") || strings.Contains(one, "hetzner1") {
		t.Fatalf("cluster summary = %q err=%v", one, err)
	}

	rows, err := tool.Query(context.Background(), "internal1", "kube-system", "nginx")
	if err != nil {
		t.Fatal(err)
	}
	if rows != "internal1/kube-system ghcr.io/example/nginx:1.29.5 sha256:abc\n" {
		t.Fatalf("rows = %q", rows)
	}

	if _, err := tool.Query(context.Background(), "missing", "", "nginx"); err == nil || !strings.Contains(err.Error(), "unknown cluster") {
		t.Fatalf("err = %v", err)
	}
}

func TestRuntimeToolTruncates(t *testing.T) {
	hits := make([]statestore.ClusterRuntimeHit, maxToolMatches+1)
	for i := range hits {
		hits[i] = statestore.ClusterRuntimeHit{Cluster: "c", Namespace: "ns", ImageRef: "app", Digest: "sha256:x"}
	}
	tool := runtimeTool{store: stubClusterStore{
		summaries: []statestore.ClusterSummary{{Name: "c", ImageCount: len(hits)}},
		hits:      hits,
	}}
	out, err := tool.Query(context.Background(), "c", "ns", "app")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(out, "\n") != maxToolMatches+1 || !strings.Contains(out, "truncated") {
		t.Fatalf("lines=%d out=%q", strings.Count(out, "\n"), out)
	}
}

func TestClusterRuntimeToolIsAdvertised(t *testing.T) {
	defs := toolDefinitions(true)
	found := false
	for _, def := range defs {
		if def.Function.Name == "cluster_runtime" {
			found = true
		}
	}
	if !found {
		t.Fatal("cluster_runtime missing")
	}
	if strings.Contains(systemPrompt(nil, false, "", 0), "cluster_runtime") {
		t.Fatal("prompt mentions the tool when runtime is unavailable")
	}
	if !strings.Contains(systemPrompt(nil, true, "", 0), "cluster_runtime") {
		t.Fatal("prompt omits the tool")
	}
}
