package mirror

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"github.com/olareg/olareg"
	oConfig "github.com/olareg/olareg/config"
	"github.com/opencontainers/go-digest"
	"github.com/regclient/regclient"
	rcconfig "github.com/regclient/regclient/config"
	"github.com/regclient/regclient/types/descriptor"
	"github.com/regclient/regclient/types/manifest"
	"github.com/regclient/regclient/types/mediatype"
	"github.com/regclient/regclient/types/ref"

	"github.com/daimoniac/suppline/internal/config"
	"github.com/daimoniac/suppline/internal/statestore"
)

func TestCreatedCache_TTLAndRetain(t *testing.T) {
	now := time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC)
	c := newCreatedCache()
	c.now = func() time.Time { return now }
	built := now.Add(-time.Hour)
	c.put("repo", "a", built)
	c.put("repo", "b", built)

	if got, ok := c.get("repo", "a"); !ok || !got.Equal(built) {
		t.Fatalf("get a = %v, %v", got, ok)
	}
	c.retain("repo", []string{"a"})
	if _, ok := c.get("repo", "b"); ok {
		t.Fatal("b must be forgotten once it is no longer listed")
	}
	now = now.Add(createdTTL + time.Second)
	if _, ok := c.get("repo", "a"); ok {
		t.Fatal("a must be read again after the TTL")
	}
}

func TestRun_NewestCopiesWindowAndCleansUpOlderTags(t *testing.T) {
	deleteEnabled := true
	regHandler := olareg.New(oConfig.Config{
		Storage: oConfig.ConfigStorage{StoreType: oConfig.StoreMem},
		API:     oConfig.ConfigAPI{DeleteEnabled: &deleteEnabled},
	})
	ts := httptest.NewServer(regHandler)
	t.Cleanup(func() {
		ts.Close()
		_ = regHandler.Close()
	})
	host := mustHost(t, ts.URL)
	rc := regclient.New(regclient.WithConfigHost(rcconfig.Host{
		Name:     host,
		Hostname: host,
		TLS:      rcconfig.TLSDisabled,
	}))

	src := host + "/src"
	dst := host + "/dst"
	base := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	// Tag names sort in a different order than build times.
	builds := map[string]int{"sha9999": 1, "sha1111": 2, "sha5555": 3, "sha3333": 4}
	for tag, day := range builds {
		putCreatedImage(t, rc, src, tag, base.AddDate(0, 0, day))
	}
	putCreatedImage(t, rc, src, "latest", base.AddDate(0, 0, 9))
	// A copy from an earlier pass that has since fallen out of the window.
	putCreatedImage(t, rc, dst, "sha9999", base.AddDate(0, 0, 1))

	cfgPath := writeConfig(t, fmt.Sprintf(`version: 1
creds:
  - registry: %s
    tls: disabled
defaults:
  parallel: 1
  interval: 1h
  skipDockerConfig: true
  cleanupTags: true
sync:
  - source: %s
    target: %s
    type: repository
    tags:
      allow:
        - 'sha[0-9]+'
      newest: 2
`, host, src, dst))
	cfg, err := config.ParseRegsync(cfgPath)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() {
		errCh <- Run(ctx, cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	}()

	want := []string{"sha3333", "sha5555"}
	deadline := time.Now().Add(20 * time.Second)
	for {
		tags := listTags(t, rc, dst)
		slices.Sort(tags)
		if slices.Equal(tags, want) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("target tags = %#v, want %#v", tags, want)
		}
		time.Sleep(100 * time.Millisecond)
	}
	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("mirror did not stop")
	}
}

func TestKeepRunning(t *testing.T) {
	cosign := "sha256-0a.sig"
	toDelete := []string{"sha1111", "sha2222", cosign}
	reported := int64(1)
	inv := &fakeInventory{
		clusters: []statestore.ClusterSummary{{Name: "prod", LastReported: &reported}},
		images: map[string][]statestore.ClusterImageSummary{"prod": {
			{ImageRef: "docker.io/hostingmaloonde/shcomp", Tag: "sha1111"},
			{ImageRef: "docker.io/hostingmaloonde/other", Tag: "sha2222"},
		}},
	}
	m := &runner{log: slog.New(slog.NewTextHandler(io.Discard, nil)), inventory: inv}

	got, err := m.keepRunning(context.Background(), "hostingmaloonde/shcomp", toDelete)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"sha2222", cosign}; !slices.Equal(got, want) {
		t.Fatalf("with inventory: delete %#v, want %#v", got, want)
	}

	inv.clusters = nil
	got, err = m.keepRunning(context.Background(), "hostingmaloonde/shcomp", toDelete)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{cosign}; !slices.Equal(got, want) {
		t.Fatalf("without inventory: delete %#v, want %#v", got, want)
	}
}

type fakeInventory struct {
	clusters []statestore.ClusterSummary
	images   map[string][]statestore.ClusterImageSummary
}

func (f *fakeInventory) ListClusterSummaries(context.Context) ([]statestore.ClusterSummary, error) {
	return f.clusters, nil
}

func (f *fakeInventory) ListClusterImages(_ context.Context, name string) ([]statestore.ClusterImageSummary, error) {
	return f.images[name], nil
}

func putCreatedImage(t *testing.T, rc *regclient.RegClient, repo, tag string, created time.Time) {
	t.Helper()
	ctx := context.Background()
	body := []byte(fmt.Sprintf(`{"architecture":"amd64","os":"linux","created":"%s","rootfs":{"type":"layers","diff_ids":[]}}`,
		created.UTC().Format(time.RFC3339)))
	repoRef, err := ref.New(repo)
	if err != nil {
		t.Fatal(err)
	}
	desc := descriptor.Descriptor{
		MediaType: mediatype.OCI1ImageConfig,
		Size:      int64(len(body)),
		Digest:    digest.FromBytes(body),
	}
	if _, err := rc.BlobPut(ctx, repoRef, desc, bytes.NewReader(body)); err != nil {
		t.Fatal(err)
	}
	raw := fmt.Sprintf(`{"schemaVersion":2,"mediaType":"%s","config":{"mediaType":"%s","digest":"%s","size":%d},"layers":[]}`,
		mediatype.OCI1Manifest, desc.MediaType, desc.Digest, desc.Size)
	man, err := manifest.New(manifest.WithRaw([]byte(raw)))
	if err != nil {
		t.Fatal(err)
	}
	tagRef, err := ref.New(repo + ":" + tag)
	if err != nil {
		t.Fatal(err)
	}
	if err := rc.ManifestPut(ctx, tagRef, man); err != nil {
		t.Fatal(err)
	}
}
