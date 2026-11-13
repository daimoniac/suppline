// Package runway owns the path a mirrored digest takes onto its registry tag.
//
// The mirror copies a digest into the target repository by digest and offers
// it here. A tag that already names an image moves only once the new digest
// has a passing SCAI attestation, so a cluster pulling the tag never resolves
// an image Kyverno cannot verify. A tag the repository does not have yet is
// published at once: there is no verified image to keep it on.
//
// The runway is the only writer of a mirrored tag, and the Current tag binding
// it leaves behind follows the registry move in the same step.
package runway

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/daimoniac/suppline/internal/policy"
	"github.com/daimoniac/suppline/internal/queue"
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
}

// Store is the scan state the runway reads and the binding it writes.
type Store interface {
	GetLastRepositoryScan(ctx context.Context, repository, digest string) (*statestore.ScanRecord, error)
	EnsureArtifactTagBinding(ctx context.Context, repository, digest, tag string) (bool, error)
}

// Tagger points a tag at a digest that is already stored in the repository.
type Tagger interface {
	MoveTag(ctx context.Context, repository, tag, digest string) error
}

// Scheduler submits the Scan request that attests a held digest.
type Scheduler interface {
	EnqueueDiscovery(ctx context.Context, image scanenqueue.Image, kind scanenqueue.DiscoveryKind) (*queue.ScanTask, error)
}

// Config wires a Runway. Store, Tagger and Scheduler are required.
type Config struct {
	Store     Store
	Tagger    Tagger
	Scheduler Scheduler
	// RescanInterval is how long a failed digest waits before another scan.
	RescanInterval func(repository string) time.Duration
	Now            func() time.Time
	Log            *slog.Logger
}

// Runway decides and performs tag moves for mirrored digests.
type Runway struct {
	cfg Config

	mu   sync.Mutex
	held map[heldKey]Candidate
}

type heldKey struct {
	repository string
	digest     string
	tag        string
}

// New returns a Runway.
func New(cfg Config) *Runway {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	return &Runway{cfg: cfg, held: map[heldKey]Candidate{}}
}

// Offer publishes c.Tag on c.Digest when the runway allows it, and otherwise
// holds the tag on c.Previous and requests a scan when one is due.
// It reports whether the tag now names c.Digest.
func (r *Runway) Offer(ctx context.Context, c Candidate) (bool, error) {
	if c.Repository == "" || c.Tag == "" || c.Digest == "" {
		return false, fmt.Errorf("runway candidate needs repository, tag and digest: %+v", c)
	}
	if c.Previous == "" {
		return true, r.publish(ctx, c, "new tag")
	}
	rec, err := r.lastScan(ctx, c)
	if err != nil {
		return false, err
	}
	if attested(rec) {
		return true, r.publish(ctx, c, "digest attested")
	}
	r.hold(c)
	if !scanDue(rec, r.cfg.Now(), r.rescanInterval(c.Repository)) {
		r.cfg.Log.Info("holding tag; scan is not due yet",
			"repository", c.Repository, "tag", c.Tag, "digest", c.Digest,
			"policy_status", statusOf(rec))
		return false, nil
	}
	kind := scanenqueue.DiscoveryRescan
	if rec == nil {
		kind = scanenqueue.DiscoveryFirstScan
	}
	if _, err := r.cfg.Scheduler.EnqueueDiscovery(ctx, scanenqueue.Image{
		Repository: c.Repository,
		Tag:        c.Tag,
		Digest:     c.Digest,
	}, kind); err != nil {
		return false, fmt.Errorf("enqueue scan for held digest: %w", err)
	}
	r.cfg.Log.Info("holding tag; queued scan of new digest",
		"repository", c.Repository, "tag", c.Tag, "digest", c.Digest)
	return false, nil
}

// Scanned is called after a scan of repository@digest is persisted. A tag held
// for that digest moves now when the scan attested it; otherwise it waits for
// the mirror's next offer, which also decides when to scan again.
func (r *Runway) Scanned(ctx context.Context, repository, digest string) {
	for _, c := range r.heldFor(repository, digest) {
		rec, err := r.lastScan(ctx, c)
		if err != nil {
			r.cfg.Log.Warn("cannot read scan of held digest",
				"repository", c.Repository, "tag", c.Tag, "digest", c.Digest, "error", err)
			continue
		}
		if !attested(rec) {
			r.cfg.Log.Info("holding tag; new digest is not attested as passed",
				"repository", c.Repository, "tag", c.Tag, "digest", c.Digest,
				"policy_status", statusOf(rec))
			continue
		}
		if err := r.publish(ctx, c, "digest attested"); err != nil {
			r.cfg.Log.Warn("failed to move tag to attested digest; next mirror run retries",
				"repository", c.Repository, "tag", c.Tag, "digest", c.Digest, "error", err)
		}
	}
}

func (r *Runway) publish(ctx context.Context, c Candidate, reason string) error {
	if err := r.cfg.Tagger.MoveTag(ctx, c.Repository, c.Tag, c.Digest); err != nil {
		return fmt.Errorf("move %s:%s to %s: %w", c.Repository, c.Tag, c.Digest, err)
	}
	r.release(c)
	r.cfg.Log.Info("published tag",
		"repository", c.Repository, "tag", c.Tag, "digest", c.Digest,
		"previous", c.Previous, "reason", reason)
	if c.Previous == "" {
		// A new tag has no scan yet; the watcher's first scan records the binding.
		return nil
	}
	if _, err := r.cfg.Store.EnsureArtifactTagBinding(ctx, c.Repository, c.Digest, c.Tag); err != nil {
		r.cfg.Log.Warn("tag moved but current binding not updated; watcher reconciles it",
			"repository", c.Repository, "tag", c.Tag, "digest", c.Digest, "error", err)
	}
	return nil
}

func (r *Runway) lastScan(ctx context.Context, c Candidate) (*statestore.ScanRecord, error) {
	rec, err := r.cfg.Store.GetLastRepositoryScan(ctx, c.Repository, c.Digest)
	if errors.Is(err, statestore.ErrScanNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read scan of %s@%s: %w", c.Repository, c.Digest, err)
	}
	return rec, nil
}

func (r *Runway) hold(c Candidate) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.held[keyOf(c)] = c
}

func (r *Runway) release(c Candidate) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.held, keyOf(c))
}

func (r *Runway) heldFor(repository, digest string) []Candidate {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []Candidate
	for k, c := range r.held {
		if k.repository == repository && k.digest == digest {
			out = append(out, c)
		}
	}
	return out
}

// HeldDigests lists the digests held off a tag in repository.
func (r *Runway) HeldDigests(repository string) []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []string
	for k := range r.held {
		if k.repository == repository {
			out = append(out, k.digest)
		}
	}
	return out
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

func keyOf(c Candidate) heldKey {
	return heldKey{repository: c.Repository, digest: c.Digest, tag: c.Tag}
}

// attested is the runway's pass predicate: the scan passed policy and its
// SCAI attestation was written, which is what the cluster policy verifies.
func attested(rec *statestore.ScanRecord) bool {
	return rec != nil && rec.PolicyPassed && rec.SCAIAttested && rec.ErrorMessage == ""
}

// scanDue reports whether a held digest should be scanned again.
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
