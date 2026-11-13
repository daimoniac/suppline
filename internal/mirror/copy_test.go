package mirror

import (
	"bytes"
	"context"
	_ "crypto/sha256"
	"fmt"
	"io"
	"log/slog"
	"net/http/httptest"
	"net/url"
	"os"
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
	"github.com/daimoniac/suppline/internal/queue"
	"github.com/daimoniac/suppline/internal/runway"
	"github.com/daimoniac/suppline/internal/scanenqueue"
	"github.com/daimoniac/suppline/internal/statestore"
)

func TestRun_CopiesMissingPrefixedTagAndCleansUp(t *testing.T) {
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
	for _, tag := range []string{"alpine-v1.2.3", "alpine-v0.9.0", "latest"} {
		putImage(t, rc, src, tag)
	}
	putImage(t, rc, dst, "obsolete")

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
      semverRange:
        - ">=1.2.0"
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

	deadline := time.Now().Add(20 * time.Second)
	var tags []string
	for {
		tags = listTags(t, rc, dst)
		if slices.Contains(tags, "alpine-v1.2.3") && !slices.Contains(tags, "obsolete") &&
			!slices.Contains(tags, "alpine-v0.9.0") && !slices.Contains(tags, "latest") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("tags = %#v", tags)
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

func mustHost(t *testing.T, raw string) string {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u.Host
}

func writeConfig(t *testing.T, content string) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "suppline-*.yml")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(content); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	return f.Name()
}

func TestProcessImage_RunwayHoldsExistingTagUntilAttested(t *testing.T) {
	regHandler := olareg.New(oConfig.Config{Storage: oConfig.ConfigStorage{StoreType: oConfig.StoreMem}})
	ts := httptest.NewServer(regHandler)
	t.Cleanup(func() {
		ts.Close()
		_ = regHandler.Close()
	})
	host := mustHost(t, ts.URL)
	rc := regclient.New(regclient.WithConfigHost(rcconfig.Host{
		Name: host, Hostname: host, TLS: rcconfig.TLSDisabled,
	}))
	src := host + "/src"
	dst := host + "/dst"
	putImageConfig(t, rc, src, "app", "amd64-old")
	oldDigest := putImageConfig(t, rc, dst, "app", "amd64-old")
	newDigest := putImageConfig(t, rc, src, "app", "amd64-new")
	if oldDigest == newDigest {
		t.Fatal("test images share a digest")
	}

	putImageConfig(t, rc, src, "fresh", "amd64-fresh")

	ctx := context.Background()
	scans := &scanState{}
	rw := runway.New(runway.Config{
		Store:     scans,
		Tagger:    regTagger{rc: rc},
		Scheduler: scans,
		Log:       slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	m := &runner{
		log:       slog.New(slog.NewTextHandler(io.Discard, nil)),
		rc:        rc,
		throttle:  newGate(1),
		manifests: map[string]manifest.Manifest{},
		runway:    rw,
	}
	entry := config.SyncEntry{
		Source: src, Target: dst, Type: "repository",
		MediaTypes: []string{mediatype.OCI1Manifest},
	}
	mirrorTag := func(tag string) {
		t.Helper()
		if err := m.processImage(ctx, entry, src+":"+tag, dst+":"+tag, actionCopy); err != nil {
			t.Fatal(err)
		}
	}

	mirrorTag("fresh")
	if !slices.Contains(listTags(t, rc, dst), "fresh") {
		t.Fatal("new tag was not published")
	}

	mirrorTag("app")
	if got := tagDigest(t, rc, dst+":app"); got != oldDigest {
		t.Fatalf("tag digest = %s, want held %s", got, oldDigest)
	}
	if !digestExists(t, rc, dst, newDigest) {
		t.Fatalf("new digest %s was not copied", newDigest)
	}
	if len(scans.queued) != 1 || scans.queued[0] != dst+":app@"+newDigest {
		t.Fatalf("queued scans = %v, want the held digest", scans.queued)
	}

	scans.rec = &statestore.ScanRecord{PolicyPassed: true, SCAIAttested: true, CreatedAt: time.Now().Unix()}
	rw.Scanned(ctx, dst, newDigest)
	if got := tagDigest(t, rc, dst+":app"); got != newDigest {
		t.Fatalf("tag digest = %s, want published %s", got, newDigest)
	}
	if len(scans.bindings) != 1 || scans.bindings[0] != dst+":app@"+newDigest {
		t.Fatalf("bindings = %v, want the moved tag", scans.bindings)
	}
}

// scanState is the scan store and scheduler the runway sees in mirror tests.
type scanState struct {
	rec      *statestore.ScanRecord
	queued   []string
	bindings []string
}

func (s *scanState) GetLastRepositoryScan(context.Context, string, string) (*statestore.ScanRecord, error) {
	if s.rec == nil {
		return nil, statestore.ErrScanNotFound
	}
	return s.rec, nil
}

func (s *scanState) EnsureArtifactTagBinding(_ context.Context, repository, digest, tag string) (bool, error) {
	s.bindings = append(s.bindings, repository+":"+tag+"@"+digest)
	return false, nil
}

func (s *scanState) EnqueueDiscovery(_ context.Context, image scanenqueue.Image, _ scanenqueue.DiscoveryKind) (*queue.ScanTask, error) {
	s.queued = append(s.queued, image.Repository+":"+image.Tag+"@"+image.Digest)
	return &queue.ScanTask{}, nil
}

// regTagger moves tags in the test registry.
type regTagger struct{ rc *regclient.RegClient }

func (r regTagger) MoveTag(ctx context.Context, repository, tag, dig string) error {
	src, err := ref.New(repository + "@" + dig)
	if err != nil {
		return err
	}
	dst, err := ref.New(repository + ":" + tag)
	if err != nil {
		return err
	}
	man, err := r.rc.ManifestGet(ctx, src)
	if err != nil {
		return err
	}
	return r.rc.ManifestPut(ctx, dst, man)
}

func putImage(t *testing.T, rc *regclient.RegClient, repo, tag string) {
	t.Helper()
	putImageConfig(t, rc, repo, tag, "amd64")
}

func putImageConfig(t *testing.T, rc *regclient.RegClient, repo, tag, arch string) string {
	t.Helper()
	ctx := context.Background()
	body := []byte(fmt.Sprintf(`{"architecture":"%s","os":"linux","rootfs":{"type":"layers","diff_ids":[]}}`, arch))
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
	return manifest.GetDigest(man).String()
}

func tagDigest(t *testing.T, rc *regclient.RegClient, image string) string {
	t.Helper()
	imageRef, err := ref.New(image)
	if err != nil {
		t.Fatal(err)
	}
	man, err := rc.ManifestHead(context.Background(), imageRef, regclient.WithManifestRequireDigest())
	if err != nil {
		t.Fatal(err)
	}
	return manifest.GetDigest(man).String()
}

func digestExists(t *testing.T, rc *regclient.RegClient, repo, dig string) bool {
	t.Helper()
	imageRef, err := ref.New(repo + "@" + dig)
	if err != nil {
		t.Fatal(err)
	}
	_, err = rc.ManifestHead(context.Background(), imageRef)
	return err == nil
}

func listTags(t *testing.T, rc *regclient.RegClient, repo string) []string {
	t.Helper()
	repoRef, err := ref.New(repo)
	if err != nil {
		t.Fatal(err)
	}
	tags, err := rc.TagList(context.Background(), repoRef)
	if err != nil {
		return nil
	}
	list, err := tags.GetTags()
	if err != nil {
		t.Fatal(err)
	}
	return list
}
