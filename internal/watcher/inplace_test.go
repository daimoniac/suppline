package watcher

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/daimoniac/suppline/internal/config"
	"github.com/daimoniac/suppline/internal/observability"
	"github.com/daimoniac/suppline/internal/registry"
	"github.com/daimoniac/suppline/internal/statestore"
)

type builtRegistry struct {
	mockRegistryClient
	built         map[string]time.Time // digest -> build time
	manifestReads int
}

func (r *builtRegistry) GetManifest(_ context.Context, _ string, digest string) (*registry.Manifest, error) {
	r.manifestReads++
	at := r.built[digest]
	return &registry.Manifest{Digest: digest, CreatedAt: &at}, nil
}

type inventoryStore struct {
	*mockStateStore
	images []statestore.ClusterImageSummary
}

func (s *inventoryStore) ListClusterSummaries(context.Context) ([]statestore.ClusterSummary, error) {
	reported := time.Now().Unix()
	return []statestore.ClusterSummary{{Name: "prod", LastReported: &reported}}, nil
}

func (s *inventoryStore) ListClusterImages(context.Context, string) ([]statestore.ClusterImageSummary, error) {
	return s.images, nil
}

func TestInPlaceTags_WindowPlusRunningTags(t *testing.T) {
	repo := "registry.gitlab.com/cmd/dev/shcomp"
	day := func(d int) time.Time { return time.Date(2026, 11, d, 0, 0, 0, 0, time.UTC) }
	tags := []string{"sha00000001", "sha00000002", "sha00000003", "sha00000004", "latest"}
	reg := &builtRegistry{
		mockRegistryClient: mockRegistryClient{tags: map[string][]string{repo: tags}, digests: map[string]string{}},
		built:              map[string]time.Time{},
	}
	for i, tag := range tags {
		digest := "sha256:" + tag
		reg.digests[repo+":"+tag] = digest
		reg.built[digest] = day(i + 1)
	}
	store := &inventoryStore{
		mockStateStore: &mockStateStore{},
		images: []statestore.ClusterImageSummary{
			{ImageRef: repo, Tag: "sha00000001"},                // running, outside the window
			{ImageRef: "other.example/app", Tag: "sha00000002"}, // another repository
			{ImageRef: repo, Tag: "sha99999999"},                // gone from the registry
		},
	}
	w := &watcherImpl{registryClient: reg, stateStore: store, logger: observability.NewLogger("error")}
	entry := config.SyncEntry{
		Target: repo, Type: "repository", InPlace: true,
		Tags: &config.TagFilter{Allow: []string{"sha[0-9a-f]{8,}"}, Newest: 2},
	}

	got, err := w.inPlaceTags(context.Background(), repo, entry)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"sha00000004", "sha00000003", "sha00000001"}
	if !slices.Equal(got, want) {
		t.Fatalf("inPlaceTags = %#v, want %#v", got, want)
	}

	reads := reg.manifestReads
	if _, err := w.inPlaceTags(context.Background(), repo, entry); err != nil {
		t.Fatal(err)
	}
	if reg.manifestReads != reads {
		t.Fatalf("build times were read again: %d -> %d", reads, reg.manifestReads)
	}
}
