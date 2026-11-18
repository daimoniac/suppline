// Package runway owns the path a mirrored digest takes onto its registry tag.
//
// The mirror copies a digest into the target repository by digest and offers
// it here. A tag moves, or a new tag is created, only once the digest has a
// passing SCAI attestation, so a cluster pulling the tag never resolves an
// image Kyverno cannot verify.
//
// A repository with a Cooldown holds every new digest, new tags included,
// until the cooldown is over: the policy keeps the scan pending, without an
// attestation, until then. A Held digest is protected from registry GC by a
// hold tag whose index records when suppline first saw it. The registry is
// the durable record; the runway rebuilds its candidates from the hold tags,
// so suppline's database stays safe to throw away.
//
// Without a cooldown a tag the repository does not have yet is published at
// once: there is no verified image to keep it on.
//
// The runway is the only writer of a mirrored tag, and the Current tag binding
// it leaves behind follows the registry move in the same step.
package runway

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/daimoniac/suppline/internal/policy"
	"github.com/daimoniac/suppline/internal/queue"
	"github.com/daimoniac/suppline/internal/registry"
	"github.com/daimoniac/suppline/internal/scanenqueue"
	"github.com/daimoniac/suppline/internal/statestore"
)

const defaultRescanInterval = 7 * 24 * time.Hour

// Candidate is a digest that is stored in Repository and should be named Tag.
type Candidate struct {
	Repository string
	Tag        string
	Digest     string
	// Previous is the digest Tag names now. Empty means the tag is new.
	Previous string
	// Source is the upstream repository the digest was copied from.
	Source string
}

// Store is the scan state the runway reads and the binding it writes.
type Store interface {
	GetLastRepositoryScanSummary(ctx context.Context, repository, digest string) (*statestore.ScanRecord, error)
	EnsureArtifactTagBinding(ctx context.Context, repository, digest, tag string) (bool, error)
}

// Tagger points a tag at a digest that is already stored in the repository.
type Tagger interface {
	MoveTag(ctx context.Context, repository, tag, digest string) error
}

// Holds reads and writes the hold tags that keep Held digests from registry
// GC and record when suppline first saw them.
type Holds interface {
	ListHolds(ctx context.Context, repository string) ([]registry.Hold, error)
	PutHold(ctx context.Context, repository string, hold registry.Hold) error
	DeleteHold(ctx context.Context, repository, digest string) error
}

// Scheduler submits the Scan request that attests a held digest.
type Scheduler interface {
	EnqueueDiscovery(ctx context.Context, image scanenqueue.Image, kind scanenqueue.DiscoveryKind) (*queue.ScanTask, error)
	EnqueueUrgentRescan(ctx context.Context, image scanenqueue.Image) (*queue.ScanTask, error)
}

// Config wires a Runway. Store, Tagger and Scheduler are required; Holds is
// required for a repository with a cooldown.
type Config struct {
	Store     Store
	Tagger    Tagger
	Scheduler Scheduler
	Holds     Holds
	// RescanInterval is how long a failed digest waits before another scan.
	RescanInterval func(repository string) time.Duration
	// Cooldown is a repository's cooldown. Nil or zero means none.
	Cooldown func(repository string) time.Duration
	// Released reports a Cooldown release of digest in repository.
	Released func(repository, digest string) bool
	Now      func() time.Time
	Log      *slog.Logger
}

// HeldDigest is one Held digest as the UI shows it.
type HeldDigest struct {
	Repository string
	Digest     string
	Source     string
	// Tags are the tags the digest is a candidate for, sorted.
	Tags      []string
	FirstSeen time.Time
	// Cooldown is the repository's cooldown now. Zero means the digest only
	// waits for its attestation.
	Cooldown time.Duration
	Released bool
}

// Runway decides and performs tag moves for mirrored digests.
type Runway struct {
	cfg Config

	mu    sync.Mutex
	repos map[string]*repoState
}

type repoState struct {
	loaded bool
	held   map[string]*candidate
}

// candidate is a Held digest of one repository.
type candidate struct {
	digest    string
	source    string
	firstSeen time.Time
	// tags maps each tag the digest is a candidate for to the digest the tag
	// named when it was offered. Empty means the tag was new or unknown.
	tags map[string]string
	// persisted reports a hold tag in the registry.
	persisted bool
}

// New returns a Runway.
func New(cfg Config) *Runway {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	return &Runway{cfg: cfg, repos: map[string]*repoState{}}
}

// Offer publishes c.Tag on c.Digest when the runway allows it, and otherwise
// holds c.Digest and requests the scans that are due. Every offer also
// reviews the tag's older candidates, so the newest attested one is published
// even when upstream moves the tag faster than the cooldown.
// It reports whether the tag now names c.Digest.
func (r *Runway) Offer(ctx context.Context, c Candidate) (bool, error) {
	if c.Repository == "" || c.Tag == "" || c.Digest == "" {
		return false, fmt.Errorf("runway candidate needs repository, tag and digest: %+v", c)
	}
	cooldown := r.cooldown(c.Repository)
	if cooldown <= 0 && c.Previous == "" {
		return true, r.publish(ctx, c.Repository, c.Tag, c.Digest, "new tag")
	}
	if err := r.load(ctx, c.Repository); err != nil {
		return false, err
	}
	rec, err := r.lastScan(ctx, c.Repository, c.Digest)
	if err != nil {
		return false, err
	}
	if attested(rec) {
		// The attestation shows the cooldown is over, released, or never
		// applied. c is upstream's current digest, so it is the newest.
		return true, r.publish(ctx, c.Repository, c.Tag, c.Digest, "digest attested")
	}
	if err := r.hold(ctx, c, cooldown > 0); err != nil {
		return false, err
	}
	published, err := r.reviewTag(ctx, c.Repository, c.Tag)
	return published == c.Digest, err
}

// Scanned is called after a scan of repository@digest is persisted. Each tag
// held for that digest moves now when the scan attested it; otherwise it waits
// for the mirror's next offer, which also decides when to scan again.
func (r *Runway) Scanned(ctx context.Context, repository, digest string) {
	for _, tag := range r.tagsOf(repository, digest) {
		rec, err := r.lastScan(ctx, repository, digest)
		if err != nil {
			r.cfg.Log.Warn("cannot read scan of held digest",
				"repository", repository, "tag", tag, "digest", digest, "error", err)
			continue
		}
		if !attested(rec) {
			r.cfg.Log.Info("holding tag; new digest is not attested as passed",
				"repository", repository, "tag", tag, "digest", digest,
				"policy_status", statusOf(rec))
			continue
		}
		if err := r.publish(ctx, repository, tag, digest, "digest attested"); err != nil {
			r.cfg.Log.Warn("failed to move tag to attested digest; next mirror run retries",
				"repository", repository, "tag", tag, "digest", digest, "error", err)
		}
	}
}

// Settle drops every candidate of tag: upstream names the digest the tag
// already has again, for example after a release was pulled upstream.
func (r *Runway) Settle(ctx context.Context, repository, tag string) {
	r.loadOrWarn(ctx, repository)
	r.dropTags(ctx, repository, func(t string, _ *candidate) bool { return t == tag }, "upstream tag matches published tag")
}

// Retain drops the candidates of every tag upstream no longer has, so a
// release deleted upstream is never published here.
func (r *Runway) Retain(ctx context.Context, repository string, upstreamTags []string) {
	r.loadOrWarn(ctx, repository)
	keep := make(map[string]struct{}, len(upstreamTags))
	for _, tag := range upstreamTags {
		keep[tag] = struct{}{}
	}
	r.dropTags(ctx, repository, func(t string, _ *candidate) bool {
		_, ok := keep[t]
		return !ok
	}, "tag gone upstream")
}

// Holding reports the digests the runway holds in repository, reading the
// repository's hold tags first when it has not yet. Mirror cleanup keeps the
// hold tag of each of them and deletes any other.
func (r *Runway) Holding(ctx context.Context, repository string) (map[string]struct{}, error) {
	if err := r.load(ctx, repository); err != nil {
		return nil, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	out := map[string]struct{}{}
	for digest := range r.state(repository).held {
		out[digest] = struct{}{}
	}
	return out, nil
}

// FirstSeen returns when suppline first saw a Held digest upstream. Nil means
// no Cooldown clock runs for it: it is not held behind a hold tag (it was
// grandfathered or published), or a Cooldown release names it.
func (r *Runway) FirstSeen(ctx context.Context, repository, digest string) (*time.Time, error) {
	if r.released(repository, digest) {
		return nil, nil
	}
	if err := r.load(ctx, repository); err != nil {
		return nil, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	cand := r.state(repository).held[digest]
	if cand == nil || !cand.persisted {
		return nil, nil
	}
	firstSeen := cand.firstSeen
	return &firstSeen, nil
}

// Release requests an urgent rescan of a Held digest a Cooldown release
// names, so its tag moves as soon as the scan attests it instead of on the
// next mirror pass. It reports whether the runway holds the digest.
func (r *Runway) Release(ctx context.Context, repository, digest string) (bool, error) {
	if err := r.load(ctx, repository); err != nil {
		return false, err
	}
	tags := r.tagsOf(repository, digest)
	if len(tags) == 0 {
		return false, nil
	}
	if _, err := r.cfg.Scheduler.EnqueueUrgentRescan(ctx, scanenqueue.Image{
		Repository: repository,
		Tag:        tags[0],
		Digest:     digest,
	}); err != nil {
		return true, fmt.Errorf("enqueue rescan of released digest: %w", err)
	}
	r.cfg.Log.Info("queued rescan of released digest",
		"repository", repository, "digest", digest, "tags", tags)
	return true, nil
}

// HeldDigests lists the digests held off a tag in repository.
func (r *Runway) HeldDigests(repository string) []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []string
	for digest := range r.state(repository).held {
		out = append(out, digest)
	}
	sort.Strings(out)
	return out
}

// Held lists every Held digest the runway knows, oldest first.
func (r *Runway) Held() []HeldDigest {
	r.mu.Lock()
	var out []HeldDigest
	for repository, st := range r.repos {
		for _, cand := range st.held {
			out = append(out, HeldDigest{
				Repository: repository,
				Digest:     cand.digest,
				Source:     cand.source,
				Tags:       cand.sortedTags(),
				FirstSeen:  cand.firstSeen,
			})
		}
	}
	r.mu.Unlock()
	for i := range out {
		out[i].Cooldown = r.cooldown(out[i].Repository)
		out[i].Released = r.released(out[i].Repository, out[i].Digest)
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].FirstSeen.Equal(out[j].FirstSeen) {
			return out[i].FirstSeen.Before(out[j].FirstSeen)
		}
		return out[i].Repository+out[i].Digest < out[j].Repository+out[j].Digest
	})
	return out
}

// reviewTag publishes the newest attested candidate of tag and queues the
// scans that are due for the newer ones. It returns the published digest.
func (r *Runway) reviewTag(ctx context.Context, repository, tag string) (string, error) {
	for _, digest := range r.candidatesNewestFirst(repository, tag) {
		rec, err := r.lastScan(ctx, repository, digest)
		if err != nil {
			return "", err
		}
		if attested(rec) {
			return digest, r.publish(ctx, repository, tag, digest, "digest attested")
		}
		if !scanDue(rec, r.cfg.Now(), r.rescanInterval(repository)) && !r.releasedWhilePending(repository, digest, rec) {
			r.cfg.Log.Info("holding tag; scan is not due yet",
				"repository", repository, "tag", tag, "digest", digest,
				"policy_status", statusOf(rec))
			continue
		}
		kind := scanenqueue.DiscoveryRescan
		if rec == nil {
			kind = scanenqueue.DiscoveryFirstScan
		}
		if _, err := r.cfg.Scheduler.EnqueueDiscovery(ctx, scanenqueue.Image{
			Repository: repository,
			Tag:        tag,
			Digest:     digest,
		}, kind); err != nil {
			return "", fmt.Errorf("enqueue scan for held digest: %w", err)
		}
		r.cfg.Log.Info("holding tag; queued scan of held digest",
			"repository", repository, "tag", tag, "digest", digest)
	}
	return "", nil
}

// publish moves tag to digest and drops every candidate of tag that is not
// newer than digest: they are superseded.
func (r *Runway) publish(ctx context.Context, repository, tag, digest, reason string) error {
	if err := r.cfg.Tagger.MoveTag(ctx, repository, tag, digest); err != nil {
		return fmt.Errorf("move %s:%s to %s: %w", repository, tag, digest, err)
	}
	r.cfg.Log.Info("published tag",
		"repository", repository, "tag", tag, "digest", digest, "reason", reason)

	r.mu.Lock()
	published := r.cfg.Now()
	if cand := r.state(repository).held[digest]; cand != nil {
		published = cand.firstSeen
	}
	r.mu.Unlock()
	r.dropTags(ctx, repository, func(t string, cand *candidate) bool {
		return t == tag && !cand.firstSeen.After(published)
	}, "superseded by published digest")

	rec, err := r.lastScan(ctx, repository, digest)
	if err != nil {
		r.cfg.Log.Warn("cannot read scan of published digest; watcher reconciles it",
			"repository", repository, "tag", tag, "digest", digest, "error", err)
		return nil
	}
	if rec == nil {
		// The first scan records the binding. Queue it now: the watcher would
		// only reach the tag on its next full pass over every repository.
		r.queueFirstScan(ctx, repository, tag, digest)
		return nil
	}
	if _, err := r.cfg.Store.EnsureArtifactTagBinding(ctx, repository, digest, tag); err != nil {
		r.cfg.Log.Warn("tag moved but current binding not updated; watcher reconciles it",
			"repository", repository, "tag", tag, "digest", digest, "error", err)
	}
	return nil
}

// queueFirstScan requests the first scan of a newly published tag's digest.
// The tag is already published, so a failure only delays the scan until the
// watcher finds the tag.
func (r *Runway) queueFirstScan(ctx context.Context, repository, tag, digest string) {
	if _, err := r.cfg.Scheduler.EnqueueDiscovery(ctx, scanenqueue.Image{
		Repository: repository,
		Tag:        tag,
		Digest:     digest,
	}, scanenqueue.DiscoveryFirstScan); err != nil {
		r.cfg.Log.Warn("cannot queue first scan of new tag; watcher queues it",
			"repository", repository, "tag", tag, "digest", digest, "error", err)
		return
	}
	r.cfg.Log.Info("queued first scan of new tag",
		"repository", repository, "tag", tag, "digest", digest)
}

// hold records c as a candidate. With persist, the digest gets a hold tag
// before anything else happens to it, so its first-seen time survives a
// restart or a new database.
func (r *Runway) hold(ctx context.Context, c Candidate, persist bool) error {
	r.mu.Lock()
	st := r.state(c.Repository)
	cand, existed := st.held[c.Digest]
	if !existed {
		cand = &candidate{digest: c.Digest, source: c.Source, firstSeen: r.cfg.Now().UTC(), tags: map[string]string{}}
		st.held[c.Digest] = cand
	}
	_, hadTag := cand.tags[c.Tag]
	cand.tags[c.Tag] = c.Previous
	if cand.source == "" {
		cand.source = c.Source
	}
	write := persist && (!cand.persisted || !hadTag)
	snapshot := cand.hold()
	r.mu.Unlock()

	if !write {
		return nil
	}
	if err := r.cfg.Holds.PutHold(ctx, c.Repository, snapshot); err != nil {
		r.mu.Lock()
		if !existed {
			delete(st.held, c.Digest)
		} else if !hadTag {
			delete(cand.tags, c.Tag)
		}
		r.mu.Unlock()
		return fmt.Errorf("write hold tag for %s@%s: %w", c.Repository, c.Digest, err)
	}
	r.mu.Lock()
	cand.persisted = true
	r.mu.Unlock()
	r.cfg.Log.Info("holding digest",
		"repository", c.Repository, "tag", c.Tag, "digest", c.Digest,
		"first_seen", snapshot.FirstSeen.Format(time.RFC3339))
	return nil
}

// dropTags removes the tags drop selects from every candidate of repository.
// A candidate left without tags is released and loses its hold tag; one
// that keeps tags gets its hold tag rewritten. Registry failures are logged:
// mirror cleanup deletes a stray hold tag, and a rewrite is retried with the
// next hold.
func (r *Runway) dropTags(ctx context.Context, repository string, drop func(tag string, cand *candidate) bool, reason string) {
	type change struct {
		hold    registry.Hold
		release bool
	}
	var changes []change
	r.mu.Lock()
	st := r.state(repository)
	for digest, cand := range st.held {
		var dropped []string
		for tag := range cand.tags {
			if drop(tag, cand) {
				dropped = append(dropped, tag)
			}
		}
		if len(dropped) == 0 {
			continue
		}
		for _, tag := range dropped {
			delete(cand.tags, tag)
		}
		r.cfg.Log.Info("dropped held candidate",
			"repository", repository, "digest", digest, "tags", dropped, "reason", reason)
		released := len(cand.tags) == 0
		if released {
			delete(st.held, digest)
		}
		if cand.persisted {
			changes = append(changes, change{hold: cand.hold(), release: released})
		}
	}
	r.mu.Unlock()

	if r.cfg.Holds == nil {
		return
	}
	for _, ch := range changes {
		var err error
		if ch.release {
			err = r.cfg.Holds.DeleteHold(ctx, repository, ch.hold.Digest)
		} else {
			err = r.cfg.Holds.PutHold(ctx, repository, ch.hold)
		}
		if err != nil {
			r.cfg.Log.Warn("failed to update hold tag",
				"repository", repository, "digest", ch.hold.Digest, "release", ch.release, "error", err)
		}
	}
}

// load reads repository's hold tags once. A hold tag's first-seen time wins
// over what the runway already knows: the registry is the durable record.
func (r *Runway) load(ctx context.Context, repository string) error {
	if r.cfg.Holds == nil {
		return nil
	}
	r.mu.Lock()
	loaded := r.state(repository).loaded
	r.mu.Unlock()
	if loaded {
		return nil
	}
	holds, err := r.cfg.Holds.ListHolds(ctx, repository)
	if err != nil {
		return fmt.Errorf("read hold tags of %s: %w", repository, err)
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	st := r.state(repository)
	if st.loaded {
		return nil
	}
	for _, h := range holds {
		cand := st.held[h.Digest]
		if cand == nil {
			cand = &candidate{digest: h.Digest, tags: map[string]string{}}
			st.held[h.Digest] = cand
		} else if !cand.firstSeen.Equal(h.FirstSeen) {
			r.cfg.Log.Warn("hold tag and runway disagree on first seen; hold tag wins",
				"repository", repository, "digest", h.Digest,
				"hold_tag", h.FirstSeen.Format(time.RFC3339), "runway", cand.firstSeen.Format(time.RFC3339))
		}
		cand.firstSeen = h.FirstSeen
		cand.persisted = true
		if h.Source != "" {
			cand.source = h.Source
		}
		for _, tag := range h.Tags {
			if _, ok := cand.tags[tag]; !ok {
				cand.tags[tag] = ""
			}
		}
	}
	st.loaded = true
	if len(holds) > 0 {
		r.cfg.Log.Info("restored held digests from hold tags", "repository", repository, "count", len(holds))
	}
	return nil
}

// loadOrWarn loads repository's hold tags for a caller that has no error to
// return. The next call that needs them tries again.
func (r *Runway) loadOrWarn(ctx context.Context, repository string) {
	if err := r.load(ctx, repository); err != nil {
		r.cfg.Log.Warn("cannot read hold tags", "repository", repository, "error", err)
	}
}

func (r *Runway) state(repository string) *repoState {
	st := r.repos[repository]
	if st == nil {
		st = &repoState{held: map[string]*candidate{}}
		r.repos[repository] = st
	}
	return st
}

func (r *Runway) tagsOf(repository, digest string) []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if cand := r.state(repository).held[digest]; cand != nil {
		return cand.sortedTags()
	}
	return nil
}

func (r *Runway) candidatesNewestFirst(repository, tag string) []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var cands []*candidate
	for _, cand := range r.state(repository).held {
		if _, ok := cand.tags[tag]; ok {
			cands = append(cands, cand)
		}
	}
	sort.Slice(cands, func(i, j int) bool {
		if !cands[i].firstSeen.Equal(cands[j].firstSeen) {
			return cands[i].firstSeen.After(cands[j].firstSeen)
		}
		return cands[i].digest < cands[j].digest
	})
	out := make([]string, len(cands))
	for i, cand := range cands {
		out[i] = cand.digest
	}
	return out
}

func (r *Runway) lastScan(ctx context.Context, repository, digest string) (*statestore.ScanRecord, error) {
	rec, err := r.cfg.Store.GetLastRepositoryScanSummary(ctx, repository, digest)
	if errors.Is(err, statestore.ErrScanNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read scan of %s@%s: %w", repository, digest, err)
	}
	return rec, nil
}

func (r *Runway) cooldown(repository string) time.Duration {
	if r.cfg.Cooldown == nil {
		return 0
	}
	return r.cfg.Cooldown(repository)
}

func (r *Runway) released(repository, digest string) bool {
	return r.cfg.Released != nil && r.cfg.Released(repository, digest)
}

// releasedWhilePending reports a Cooldown release that came after the
// digest's last scan: that scan is still pending for the cooldown, so the
// rescan it waits for would only come once the cooldown is over.
func (r *Runway) releasedWhilePending(repository, digest string, rec *statestore.ScanRecord) bool {
	return rec != nil && rec.PolicyStatus == policy.PolicyStatusPending && r.released(repository, digest)
}

func (r *Runway) rescanInterval(repository string) time.Duration {
	if r.cfg.RescanInterval == nil {
		return defaultRescanInterval
	}
	if interval := r.cfg.RescanInterval(repository); interval > 0 {
		return interval
	}
	return defaultRescanInterval
}

func (c *candidate) sortedTags() []string {
	tags := make([]string, 0, len(c.tags))
	for tag := range c.tags {
		tags = append(tags, tag)
	}
	slices.Sort(tags)
	return tags
}

func (c *candidate) hold() registry.Hold {
	return registry.Hold{Digest: c.digest, FirstSeen: c.firstSeen, Source: c.source, Tags: c.sortedTags()}
}

// attested is the runway's pass predicate: the scan passed policy and its
// SCAI attestation was written, which is what the cluster policy verifies.
func attested(rec *statestore.ScanRecord) bool {
	return rec != nil && rec.PolicyPassed && rec.SCAIAttested && rec.ErrorMessage == ""
}

// scanDue reports whether a held digest should be scanned again. A pending
// scan is due once its cooldown is over.
func scanDue(rec *statestore.ScanRecord, now time.Time, rescan time.Duration) bool {
	if rec == nil {
		return true
	}
	age := now.Sub(time.Unix(rec.CreatedAt, 0))
	if rec.PolicyStatus == policy.PolicyStatusPending {
		wait := time.Duration(rec.MinimumReleaseAgeSeconds-rec.ReleaseAgeSeconds) * time.Second
		return age >= max(wait, 0)
	}
	if rec.PolicyPassed && !rec.SCAIAttested {
		return true
	}
	return age >= rescan
}

func statusOf(rec *statestore.ScanRecord) string {
	if rec == nil {
		return ""
	}
	return rec.PolicyStatus
}
