package mirror

import (
	"context"
	"io"
	"log/slog"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/olareg/olareg"
	oConfig "github.com/olareg/olareg/config"
	"github.com/regclient/regclient"
	rcconfig "github.com/regclient/regclient/config"
	"github.com/regclient/regclient/types/manifest"

	"github.com/daimoniac/suppline/internal/statestore"
)

func TestProcessRepoBackfillsExistingTagWithoutCopy(t *testing.T) {
	regHandler := olareg.New(oConfig.Config{
		Storage: oConfig.ConfigStorage{StoreType: oConfig.StoreMem},
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
	putImage(t, rc, src, "1.2.3")
	putImage(t, rc, dst, "1.2.3")
	putImage(t, rc, dst, "obsolete")

	cfg := testMirrorConfig(t, `
version: 1
creds:
  - registry: `+host+`
    tls: disabled
defaults:
  parallel: 1
  interval: 60m
  skipDockerConfig: true
sync:
  - source: `+src+`
    target: `+dst+`
    type: repository
    tags:
      semverRange:
        - ">=1.2.0"
`)
	store, err := statestore.NewSQLiteStore(filepath.Join(t.TempDir(), "mirror.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	journal := newJournal(store, NewActivity(), cfg, logger)
	if err := journal.Bind(context.Background()); err != nil {
		t.Fatal(err)
	}
	m := &runner{
		cfg:       cfg,
		log:       logger,
		rc:        rc,
		throttle:  newGate(1),
		journal:   journal,
		manifests: map[string]manifest.Manifest{},
	}
	key := journal.entries[0].key
	ctx := withSyncKey(context.Background(), key)
	journal.Begin(key)
	if err := m.process(ctx, cfg.Sync[0], actionMissing); err != nil {
		t.Fatal(err)
	}
	journal.Finish(ctx, key, nil)

	images, total, err := store.ListMirrorImages(context.Background(), key, 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if total != 1 || len(images) != 1 || images[0].Tag != "1.2.3" || images[0].Repository != dst {
		t.Fatalf("images = %+v total %d", images, total)
	}
	tags := listTags(t, rc, dst)
	for _, tag := range tags {
		if tag == "obsolete" {
			continue
		}
	}
	if !containsTag(tags, "1.2.3") || !containsTag(tags, "obsolete") {
		t.Fatalf("target tags changed: %v", tags)
	}
}

func containsTag(tags []string, want string) bool {
	for _, tag := range tags {
		if tag == want {
			return true
		}
	}
	return false
}
