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

func putImage(t *testing.T, rc *regclient.RegClient, repo, tag string) {
	t.Helper()
	ctx := context.Background()
	body := []byte(`{"architecture":"amd64","os":"linux","rootfs":{"type":"layers","diff_ids":[]}}`)
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
