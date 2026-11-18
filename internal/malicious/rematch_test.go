package malicious

import (
	"context"
	"path/filepath"
	"sort"
	"testing"

	"github.com/daimoniac/suppline/internal/statestore"
	"github.com/daimoniac/suppline/internal/types"
)

type recordedRescans struct {
	images []string
}

func (q *recordedRescans) RescanMalicious(_ context.Context, repository, digest, tag string) error {
	q.images = append(q.images, repository+"@"+digest+":"+tag)
	return nil
}

func (q *recordedRescans) take() []string {
	out := q.images
	q.images = nil
	sort.Strings(out)
	return out
}

const (
	digestEvil  = "sha256:aaaa000000000000000000000000000000000000000000000000000000000000"
	digestClean = "sha256:bbbb000000000000000000000000000000000000000000000000000000000000"
	digestLate  = "sha256:cccc000000000000000000000000000000000000000000000000000000000000"
	digestCrate = "sha256:dddd000000000000000000000000000000000000000000000000000000000000"
)

type rematchFixture struct {
	t       *testing.T
	store   *statestore.SQLiteStore
	service *Service
	feed    *fakeFeed
	queue   *recordedRescans
	r       *Rematcher
}

func newRematchFixture(t *testing.T) *rematchFixture {
	t.Helper()
	store, err := statestore.NewSQLiteStore(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	feed := &fakeFeed{
		result:  SyncResult{Current: hash(1)},
		entries: map[string]*Entry{"a": entry("MAL-EVIL", EcosystemNPM, "evil", nil, allVersions())},
	}
	service, err := newService(feed, ServiceConfig{}, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	queue := &recordedRescans{}
	f := &rematchFixture{t: t, store: store, service: service, feed: feed, queue: queue}
	f.r = NewRematcher(service, store, queue, nil, nil)
	return f
}

// scan records a scan with the given check and the image's packages, the
// way the worker does.
func (f *rematchFixture) scan(digest string, check *types.MaliciousCheck, packages ...Package) {
	f.t.Helper()
	ctx := context.Background()
	if err := f.store.RecordScan(ctx, &statestore.ScanRecord{
		Repository: "library/app", Digest: digest, Tag: digest[7:11], PolicyPassed: true, PolicyStatus: "passed", Malicious: check,
	}); err != nil {
		f.t.Fatal(err)
	}
	if err := f.store.ReplacePackageInventory(ctx, digest, PackageRefs(packages)); err != nil {
		f.t.Fatal(err)
	}
}

func (f *rematchFixture) check(digest string) *types.MaliciousCheck {
	f.t.Helper()
	scans, err := f.store.ListLatestDigestScans(context.Background(), digest)
	if err != nil || len(scans) != 1 {
		f.t.Fatalf("latest scans of %s: %v %+v", digest, err, scans)
	}
	return scans[0].Malicious
}

func npm(name, version string) Package {
	return Package{Ecosystem: EcosystemNPM, Name: name, Version: version, PURL: "pkg:npm/" + name + "@" + version}
}

func TestRematchFullCatchUp(t *testing.T) {
	f := newRematchFixture(t)
	unavailable := &types.MaliciousCheck{Status: types.MaliciousCheckUnavailable}
	f.scan(digestEvil, unavailable, npm("evil", "1.0.0"))
	f.scan(digestClean, &types.MaliciousCheck{Status: types.MaliciousCheckOK}, npm("good", "1.0.0"))
	f.scan(digestLate, unavailable, npm("good", "1.0.0"))

	var updates []Update
	f.service.OnUpdate(func(_ context.Context, u Update) { updates = append(updates, u) })
	f.service.Sync(context.Background())
	if len(updates) != 1 || !updates[0].Full {
		t.Fatalf("expected a full update, got %+v", updates)
	}
	if err := f.r.Process(context.Background(), updates[0]); err != nil {
		t.Fatal(err)
	}

	if got := f.queue.take(); len(got) != 1 || got[0] != "library/app@"+digestEvil+":aaaa" {
		t.Fatalf("only the malicious digest should be rescanned, got %v", got)
	}
	if c := f.check(digestLate); c == nil || c.Status != types.MaliciousCheckOK || c.Commit != hash(1).String() {
		t.Fatalf("late-checked clean digest should be confirmed, got %+v", c)
	}
	if c := f.check(digestEvil); c.Status != types.MaliciousCheckUnavailable {
		t.Fatalf("a digest with a hit is rescanned, not confirmed, got %+v", c)
	}

	// Running the full match again after the rescan recorded the finding queues nothing.
	f.scan(digestEvil, &types.MaliciousCheck{Status: types.MaliciousCheckOK, Findings: []types.MaliciousFinding{{ID: "MAL-EVIL"}}}, npm("evil", "1.0.0"))
	if err := f.r.Process(context.Background(), Update{Full: true}); err != nil {
		t.Fatal(err)
	}
	if got := f.queue.take(); len(got) != 0 {
		t.Fatalf("known findings must not be rescanned again, got %v", got)
	}
}

func TestRematchIncremental(t *testing.T) {
	f := newRematchFixture(t)
	ok := &types.MaliciousCheck{Status: types.MaliciousCheckOK}
	f.scan(digestEvil, ok, npm("evil", "1.0.0"))
	f.scan(digestClean, ok, npm("good", "1.0.0"))
	f.scan(digestLate, ok, npm("good", "2.0.0"))
	f.scan(digestCrate, ok, Package{Ecosystem: EcosystemCratesIO, Name: "amzn_client", Version: "99.0.1", PURL: "pkg:cargo/amzn_client@99.0.1"})
	f.service.Sync(context.Background())

	changed := []*Entry{
		entry("MAL-GOOD", EcosystemNPM, "good", []string{"1.0.0"}),
		entry("MAL-CRATE", EcosystemCratesIO, "amzn-client", []string{"99.0.1"}),
	}
	if err := f.r.Process(context.Background(), Update{Changed: changed}); err != nil {
		t.Fatal(err)
	}
	got := f.queue.take()
	want := []string{"library/app@" + digestClean + ":bbbb", "library/app@" + digestCrate + ":dddd"}
	if len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("want %v, got %v", want, got)
	}
}

func TestRematchSkipsWhileUnavailable(t *testing.T) {
	f := newRematchFixture(t)
	f.scan(digestEvil, &types.MaliciousCheck{Status: types.MaliciousCheckUnavailable}, npm("evil", "1.0.0"))
	if err := f.r.Process(context.Background(), Update{Full: true}); err != nil {
		t.Fatal(err)
	}
	if got := f.queue.take(); len(got) != 0 {
		t.Fatalf("nothing can be matched before the index loads, got %v", got)
	}
}

func TestRematchCoalesce(t *testing.T) {
	r := NewRematcher(nil, nil, nil, nil, nil)
	a := entry("MAL-A", EcosystemNPM, "a", nil)
	b := entry("MAL-B", EcosystemNPM, "b", nil)

	r.Notify(context.Background(), Update{Changed: []*Entry{b}})
	if got := r.coalesce(Update{Changed: []*Entry{a}}); got.Full || len(got.Changed) != 2 {
		t.Fatalf("incremental updates should merge, got %+v", got)
	}

	r.Notify(context.Background(), Update{Full: true})
	if got := r.coalesce(Update{Changed: []*Entry{a}}); !got.Full {
		t.Fatalf("a queued full update wins, got %+v", got)
	}

	for i := 0; i < cap(r.updates)+1; i++ {
		r.Notify(context.Background(), Update{Changed: []*Entry{a}})
	}
	first := <-r.updates
	if got := r.coalesce(first); !got.Full {
		t.Fatalf("a dropped update forces a full re-match, got %+v", got)
	}
}

// A scan can check before the index loads and be saved after the full
// re-match ran (seen in production). The next sync's catch-up resolves it.
func TestRematchCatchUpAfterFullRematch(t *testing.T) {
	f := newRematchFixture(t)
	f.service.Sync(context.Background())
	if err := f.r.Process(context.Background(), Update{Full: true}); err != nil {
		t.Fatal(err)
	}

	unavailable := &types.MaliciousCheck{Status: types.MaliciousCheckUnavailable}
	f.scan(digestEvil, unavailable, npm("evil", "1.0.0"))
	f.scan(digestLate, unavailable, npm("good", "1.0.0"))

	// An hourly sync with no upstream change.
	if err := f.r.Process(context.Background(), Update{}); err != nil {
		t.Fatal(err)
	}
	if got := f.queue.take(); len(got) != 1 || got[0] != "library/app@"+digestEvil+":aaaa" {
		t.Fatalf("the late malicious digest should be rescanned, got %v", got)
	}
	if c := f.check(digestLate); c == nil || c.Status != types.MaliciousCheckOK {
		t.Fatalf("the late clean digest should be confirmed, got %+v", c)
	}
}

// An image without language packages has no inventory rows; a full re-match
// must still confirm a check recorded as unavailable (seen in production).
func TestRematchFullConfirmsImageWithoutPackages(t *testing.T) {
	f := newRematchFixture(t)
	f.scan(digestLate, &types.MaliciousCheck{Status: types.MaliciousCheckUnavailable})
	f.service.Sync(context.Background())
	if err := f.r.Process(context.Background(), Update{Full: true}); err != nil {
		t.Fatal(err)
	}
	if c := f.check(digestLate); c == nil || c.Status != types.MaliciousCheckOK {
		t.Fatalf("expected the check to be confirmed, got %+v", c)
	}
	if got := f.queue.take(); len(got) != 0 {
		t.Fatalf("nothing to rescan, got %v", got)
	}
}

// Confirming a stale check keeps the exemption the scan's policy decided.
func TestRematchConfirmKeepsExemptions(t *testing.T) {
	f := newRematchFixture(t)
	stale := &types.MaliciousCheck{Status: types.MaliciousCheckStale, Findings: []types.MaliciousFinding{{ID: "MAL-EVIL", PackageName: "evil", Exempted: true}}}
	f.scan(digestEvil, stale, npm("evil", "1.0.0"))
	f.service.Sync(context.Background())
	if err := f.r.Process(context.Background(), Update{Full: true}); err != nil {
		t.Fatal(err)
	}
	if got := f.queue.take(); len(got) != 0 {
		t.Fatalf("a known finding is not rescanned, got %v", got)
	}
	c := f.check(digestEvil)
	if c.Status != types.MaliciousCheckOK || len(c.Findings) != 1 || !c.Findings[0].Exempted {
		t.Fatalf("expected an ok check that keeps the exemption, got %+v", c)
	}
}
