package mirror

import (
	"context"
	"io"
	"log/slog"
	"net/http/httptest"
	"testing"

	"github.com/olareg/olareg"
	oConfig "github.com/olareg/olareg/config"
	"github.com/regclient/regclient"
	rcconfig "github.com/regclient/regclient/config"
	"github.com/regclient/regclient/types/manifest"
	"github.com/regclient/regclient/types/mediatype"

	"github.com/daimoniac/suppline/internal/runway"
)

// While the runway holds a new digest until it is attested, the tag still names
// its previous digest. The journal must keep it, or the run prunes the tag from
// the Mirror page until the runway moves it.
func TestJournalKeepsTagHeldByRunway(t *testing.T) {
	regHandler := olareg.New(oConfig.Config{Storage: oConfig.ConfigStorage{StoreType: oConfig.StoreMem}})
	ts := httptest.NewServer(regHandler)
	t.Cleanup(func() {
		ts.Close()
		_ = regHandler.Close()
	})
	host := mustHost(t, ts.URL)
	rc := regclient.New(regclient.WithConfigHost(rcconfig.Host{Name: host, Hostname: host, TLS: rcconfig.TLSDisabled}))
	src := host + "/src"
	dst := host + "/dst"
	putImageConfig(t, rc, src, "app", "amd64-old")
	oldDigest := putImageConfig(t, rc, dst, "app", "amd64-old")
	putImageConfig(t, rc, src, "app", "amd64-new")

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
`)
	journal, store := testJournal(t, cfg)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	scans := &scanState{}
	m := &runner{
		cfg:       cfg,
		log:       logger,
		rc:        rc,
		throttle:  newGate(1),
		journal:   journal,
		manifests: map[string]manifest.Manifest{},
		runway: runway.New(runway.Config{
			Store: scans, Tagger: regTagger{rc: rc}, Scheduler: scans, Log: logger,
		}),
	}
	entry := cfg.Sync[0]
	entry.MediaTypes = []string{mediatype.OCI1Manifest}

	key := journal.entries[0].key
	ctx := withSyncKey(context.Background(), key)
	journal.Begin(key)
	if err := m.processImage(ctx, entry, src+":app", dst+":app", actionCopy); err != nil {
		t.Fatal(err)
	}
	if got := tagDigest(t, rc, dst+":app"); got != oldDigest {
		t.Fatalf("tag digest = %s, want it held at %s", got, oldDigest)
	}
	journal.Finish(ctx, key, nil)

	images, total, err := store.ListMirrorImages(context.Background(), key, 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if total != 1 || images[0].Repository != dst || images[0].Tag != "app" {
		t.Fatalf("mirror images = %+v (total %d), want the held tag %s:app", images, total, dst)
	}
}
