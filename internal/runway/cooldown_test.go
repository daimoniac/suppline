package runway

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"slices"
	"testing"
	"time"

	"github.com/daimoniac/suppline/internal/policy"
	"github.com/daimoniac/suppline/internal/registry"
	"github.com/daimoniac/suppline/internal/scanenqueue"
	"github.com/daimoniac/suppline/internal/statestore"
)

const cooldown = 7 * 24 * time.Hour

// cooldownRegistry adds per-digest scans and hold tags to fakeRegistry.
type cooldownRegistry struct {
	fakeRegistry
	recs     map[string]*statestore.ScanRecord
	holds    map[string]registry.Hold
	deleted  []string
	putErr   error
	released map[string]bool
}

func newCooldownRegistry(tags map[string]string) *cooldownRegistry {
	return &cooldownRegistry{
		fakeRegistry: fakeRegistry{tags: tags},
		recs:         map[string]*statestore.ScanRecord{},
		holds:        map[string]registry.Hold{},
		released:     map[string]bool{},
	}
}

func (f *cooldownRegistry) GetLastRepositoryScanSummary(_ context.Context, _, digest string) (*statestore.ScanRecord, error) {
	if rec := f.recs[digest]; rec != nil {
		return rec, nil
	}
	return nil, statestore.ErrScanNotFound
}

func (f *cooldownRegistry) ListHolds(context.Context, string) ([]registry.Hold, error) {
	var out []registry.Hold
	for _, h := range f.holds {
		out = append(out, h)
	}
	return out, nil
}

func (f *cooldownRegistry) PutHold(_ context.Context, _ string, h registry.Hold) error {
	if f.putErr != nil {
		return f.putErr
	}
	f.holds[h.Digest] = h
	return nil
}

func (f *cooldownRegistry) DeleteHold(_ context.Context, _, digest string) error {
	delete(f.holds, digest)
	f.deleted = append(f.deleted, digest)
	return nil
}

// clock is a settable Now.
type clock struct{ now time.Time }

func (c *clock) Now() time.Time { return c.now }

func newCooldownRunway(f *cooldownRegistry, c *clock) *Runway {
	return New(Config{
		Store:          f,
		Tagger:         f,
		Scheduler:      f,
		Holds:          f,
		RescanInterval: func(string) time.Duration { return 7 * 24 * time.Hour },
		Cooldown:       func(string) time.Duration { return cooldown },
		Released:       func(_, digest string) bool { return f.released[digest] },
		Now:            c.Now,
		Log:            slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
}

func passed(at time.Time) *statestore.ScanRecord {
	return &statestore.ScanRecord{PolicyPassed: true, SCAIAttested: true, PolicyStatus: policy.PolicyStatusPassed, CreatedAt: at.Unix()}
}

func pending(at time.Time, age time.Duration) *statestore.ScanRecord {
	return &statestore.ScanRecord{
		PolicyStatus:             policy.PolicyStatusPending,
		MinimumReleaseAgeSeconds: int64(cooldown.Seconds()),
		ReleaseAgeSeconds:        int64(age.Seconds()),
		CreatedAt:                at.Unix(),
	}
}

// A new upstream version is the main way a malicious release comes in, so a
// new tag waits for its cooldown like a moved one.
func TestCooldown_NewTagIsHeldWithHoldTag(t *testing.T) {
	ctx := context.Background()
	c := &clock{now: time.Date(2026, 11, 18, 10, 0, 0, 0, time.UTC)}
	f := newCooldownRegistry(map[string]string{})
	r := newCooldownRunway(f, c)

	published, err := r.Offer(ctx, Candidate{Repository: repo, Tag: "1.2.4", Digest: newDig, Source: "docker.io/team/app"})
	if err != nil || published {
		t.Fatalf("Offer() = %t, %v; want held", published, err)
	}
	if _, ok := f.tags["1.2.4"]; ok {
		t.Fatal("new tag was published during its cooldown")
	}
	hold, ok := f.holds[newDig]
	if !ok || !hold.FirstSeen.Equal(c.now) || hold.Source != "docker.io/team/app" || !slices.Equal(hold.Tags, []string{"1.2.4"}) {
		t.Fatalf("hold = %+v (present %t)", hold, ok)
	}
	if len(f.queued) != 1 || f.queued[0] != scanenqueue.DiscoveryFirstScan {
		t.Fatalf("queued = %v, want the first scan during the hold", f.queued)
	}
	firstSeen, err := r.FirstSeen(ctx, repo, newDig)
	if err != nil || firstSeen == nil || !firstSeen.Equal(c.now) {
		t.Fatalf("FirstSeen() = %v, %v", firstSeen, err)
	}

	// Once the cooldown is over the rescan attests the digest and the tag
	// is created.
	c.now = c.now.Add(cooldown)
	f.recs[newDig] = passed(c.now)
	r.Scanned(ctx, repo, newDig)
	if f.tags["1.2.4"] != newDig {
		t.Fatalf("tag = %q after attested scan, want %s", f.tags["1.2.4"], newDig)
	}
	if _, ok := f.holds[newDig]; ok {
		t.Fatal("hold tag kept after publishing")
	}
}

// A failing digest keeps its hold tag so it can be triaged in suppline.
func TestCooldown_FailedDigestStaysHeld(t *testing.T) {
	ctx := context.Background()
	c := &clock{now: time.Now()}
	f := newCooldownRegistry(map[string]string{tag: oldDig})
	r := newCooldownRunway(f, c)

	if _, err := r.Offer(ctx, Candidate{Repository: repo, Tag: tag, Digest: newDig, Previous: oldDig}); err != nil {
		t.Fatal(err)
	}
	f.recs[newDig] = &statestore.ScanRecord{PolicyStatus: policy.PolicyStatusFailed, CreatedAt: c.now.Unix()}
	r.Scanned(ctx, repo, newDig)
	if f.tags[tag] != oldDig {
		t.Fatalf("failed digest published: tag = %s", f.tags[tag])
	}
	if _, ok := f.holds[newDig]; !ok {
		t.Fatal("hold tag of a failed digest was removed")
	}
}

// Upstream publishing faster than the cooldown must not starve the tag: it
// moves to the newest candidate that is attested.
func TestCooldown_NewestAttestedCandidateWins(t *testing.T) {
	ctx := context.Background()
	start := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	c := &clock{now: start}
	f := newCooldownRegistry(map[string]string{tag: oldDig})
	r := newCooldownRunway(f, c)

	const d1, d2, d3 = "sha256:d1", "sha256:d2", "sha256:d3"
	offer := func(digest string) bool {
		t.Helper()
		published, err := r.Offer(ctx, Candidate{Repository: repo, Tag: tag, Digest: digest, Previous: f.tags[tag]})
		if err != nil {
			t.Fatal(err)
		}
		return published
	}
	offer(d1)
	c.now = start.Add(3 * 24 * time.Hour)
	offer(d2)
	c.now = start.Add(6 * 24 * time.Hour)
	offer(d3)

	// Day 7: d1 is past its cooldown and attested, d2 and d3 are pending.
	c.now = start.Add(7 * 24 * time.Hour)
	f.recs[d1] = passed(c.now)
	f.recs[d2] = pending(c.now, 4*24*time.Hour)
	f.recs[d3] = pending(c.now, 24*time.Hour)
	if offer(d3) {
		t.Fatal("pending d3 published")
	}
	if f.tags[tag] != d1 {
		t.Fatalf("tag = %s, want the newest attested candidate d1", f.tags[tag])
	}
	if _, ok := f.holds[d1]; ok {
		t.Error("published d1 kept its hold tag")
	}
	if got := r.HeldDigests(repo); !slices.Equal(got, []string{d2, d3}) {
		t.Fatalf("held = %v, want d2 and d3", got)
	}

	// d3 attests before d2: d2 is superseded and released.
	f.recs[d3] = passed(c.now)
	r.Scanned(ctx, repo, d3)
	if f.tags[tag] != d3 {
		t.Fatalf("tag = %s, want d3", f.tags[tag])
	}
	if len(r.HeldDigests(repo)) != 0 || len(f.holds) != 0 {
		t.Fatalf("held = %v, holds = %v; want none after the newest is published", r.HeldDigests(repo), f.holds)
	}
}

// A release pulled upstream must never be published here later.
func TestCooldown_SettleAndRetainDropCandidates(t *testing.T) {
	ctx := context.Background()
	c := &clock{now: time.Now()}
	f := newCooldownRegistry(map[string]string{tag: oldDig})
	r := newCooldownRunway(f, c)

	if _, err := r.Offer(ctx, Candidate{Repository: repo, Tag: tag, Digest: newDig, Previous: oldDig}); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Offer(ctx, Candidate{Repository: repo, Tag: "1.2.4", Digest: "sha256:pulled"}); err != nil {
		t.Fatal(err)
	}

	r.Settle(ctx, repo, tag)
	if _, ok := f.holds[newDig]; ok {
		t.Error("Settle kept the candidate of a tag upstream moved back")
	}

	r.Retain(ctx, repo, []string{tag})
	if _, ok := f.holds["sha256:pulled"]; ok {
		t.Error("Retain kept the candidate of a tag deleted upstream")
	}
	if len(r.HeldDigests(repo)) != 0 {
		t.Fatalf("held = %v", r.HeldDigests(repo))
	}
}

// The registry is the durable record: a fresh runway (new process or new
// database) gets each hold's first-seen time back from its hold tag.
func TestCooldown_RestoresHoldsFromRegistry(t *testing.T) {
	ctx := context.Background()
	firstSeen := time.Date(2026, 11, 13, 9, 0, 0, 0, time.UTC)
	c := &clock{now: firstSeen.Add(5 * 24 * time.Hour)}
	f := newCooldownRegistry(map[string]string{tag: oldDig})
	f.holds[newDig] = registry.Hold{Digest: newDig, FirstSeen: firstSeen, Source: "docker.io/team/app", Tags: []string{tag}}
	r := newCooldownRunway(f, c)

	holding, err := r.Holding(ctx, repo)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := holding[newDig]; !ok {
		t.Fatalf("Holding() = %v, want restored digest", holding)
	}
	got, err := r.FirstSeen(ctx, repo, newDig)
	if err != nil || got == nil || !got.Equal(firstSeen) {
		t.Fatalf("FirstSeen() = %v, %v; want %v", got, err, firstSeen)
	}

	// Offering it again keeps the restored clock.
	if _, err := r.Offer(ctx, Candidate{Repository: repo, Tag: tag, Digest: newDig, Previous: oldDig}); err != nil {
		t.Fatal(err)
	}
	if !f.holds[newDig].FirstSeen.Equal(firstSeen) {
		t.Fatalf("hold first seen = %v, want %v", f.holds[newDig].FirstSeen, firstSeen)
	}
	held := r.Held()
	if len(held) != 1 || held[0].Cooldown != cooldown || !slices.Equal(held[0].Tags, []string{tag}) {
		t.Fatalf("Held() = %+v", held)
	}
}

func TestCooldown_ReleaseStopsTheClock(t *testing.T) {
	ctx := context.Background()
	f := newCooldownRegistry(map[string]string{tag: oldDig})
	r := newCooldownRunway(f, &clock{now: time.Now()})
	if _, err := r.Offer(ctx, Candidate{Repository: repo, Tag: tag, Digest: newDig, Previous: oldDig}); err != nil {
		t.Fatal(err)
	}
	f.released[newDig] = true
	got, err := r.FirstSeen(ctx, repo, newDig)
	if err != nil || got != nil {
		t.Fatalf("FirstSeen() = %v, %v; want no clock for a released digest", got, err)
	}
}

// A digest is never scanned or published held without its hold tag.
func TestCooldown_HoldTagFailureStopsTheOffer(t *testing.T) {
	f := newCooldownRegistry(map[string]string{tag: oldDig})
	f.putErr = errors.New("registry rejects nested index")
	r := newCooldownRunway(f, &clock{now: time.Now()})

	if _, err := r.Offer(context.Background(), Candidate{Repository: repo, Tag: tag, Digest: newDig, Previous: oldDig}); err == nil {
		t.Fatal("Offer() error = nil, want hold tag failure")
	}
	if len(f.queued) != 0 || len(r.HeldDigests(repo)) != 0 {
		t.Fatalf("queued = %v, held = %v; want nothing", f.queued, r.HeldDigests(repo))
	}
}

// An attested digest is grandfathered: no clock starts for it.
func TestCooldown_AttestedDigestPublishesWithoutHold(t *testing.T) {
	f := newCooldownRegistry(map[string]string{})
	f.recs[newDig] = passed(time.Now())
	r := newCooldownRunway(f, &clock{now: time.Now()})
	published, err := r.Offer(context.Background(), Candidate{Repository: repo, Tag: "alias", Digest: newDig})
	if err != nil || !published || f.tags["alias"] != newDig {
		t.Fatalf("Offer() = %t, %v; tags = %v", published, err, f.tags)
	}
	if len(f.holds) != 0 {
		t.Fatalf("holds = %v, want none", f.holds)
	}
}

// A Cooldown release must reach a digest whose scan is pending: the API
// queues an urgent rescan at once, and the next offer rescans it as well.
func TestCooldown_ReleaseRescansPendingDigest(t *testing.T) {
	ctx := context.Background()
	c := &clock{now: time.Date(2026, 11, 18, 16, 0, 0, 0, time.UTC)}
	f := newCooldownRegistry(map[string]string{})
	r := newCooldownRunway(f, c)
	offer := Candidate{Repository: repo, Tag: "v0.65.6", Digest: newDig}
	if _, err := r.Offer(ctx, offer); err != nil {
		t.Fatal(err)
	}
	f.recs[newDig] = pending(c.now, time.Minute)
	f.queued = nil

	// Before the release, the pending scan is not due for days.
	if _, err := r.Offer(ctx, offer); err != nil {
		t.Fatal(err)
	}
	if len(f.queued) != 0 {
		t.Fatalf("queued = %v before the release", f.queued)
	}

	f.released[newDig] = true
	held, err := r.Release(ctx, repo, newDig)
	if err != nil || !held {
		t.Fatalf("Release() = %t, %v", held, err)
	}
	if len(f.urgent) != 1 || f.urgent[0].Tag != "v0.65.6" {
		t.Fatalf("urgent = %v, want one rescan under the held tag", f.urgent)
	}
	f.queued = nil
	if _, err := r.Offer(ctx, offer); err != nil {
		t.Fatal(err)
	}
	if len(f.queued) != 1 {
		t.Fatalf("queued = %v, want the next offer to rescan the released digest", f.queued)
	}

	// The rescan passes without the cooldown and publishes the tag.
	f.recs[newDig] = passed(c.now)
	r.Scanned(ctx, repo, newDig)
	if f.tags["v0.65.6"] != newDig {
		t.Fatalf("tag = %q, want published", f.tags["v0.65.6"])
	}
	if _, ok := f.holds[newDig]; ok || !slices.Contains(f.deleted, newDig) {
		t.Fatalf("holds = %v, deleted = %v; want the hold tag deleted", f.holds, f.deleted)
	}

	if held, err := r.Release(ctx, repo, "sha256:unknown"); err != nil || held {
		t.Fatalf("Release() of an unheld digest = %t, %v", held, err)
	}
}
