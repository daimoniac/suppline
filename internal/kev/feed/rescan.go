package feed

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"sync"
)

// Image is one stored digest to rescan.
type Image struct {
	Repository string
	Digest     string
	Tag        string
}

// ImageFinder lists the current images whose latest scan has any of the
// given CVEs.
type ImageFinder interface {
	ImagesWithCVEs(ctx context.Context, cveIDs []string) ([]Image, error)
}

// RescanQueue queues an urgent rescan; the rescan re-runs policy.
type RescanQueue interface {
	RescanKEV(ctx context.Context, image Image) error
}

// RescanCounter counts the rescans queued.
type RescanCounter interface {
	Inc()
}

// Rescanner re-runs policy on images whose findings were just added to the
// KEV catalog, so a policy that reads KEV acts the same day instead of at
// the next rescan interval. It must run on the leader only.
type Rescanner struct {
	finder  ImageFinder
	queue   RescanQueue
	usesKEV func(repository string) bool
	counter RescanCounter
	logger  *slog.Logger
	wake    chan struct{}
	mu      sync.Mutex
	pending map[string]struct{}
}

// NewRescanner creates a rescanner. usesKEV reports whether a repository's
// policy reads KEV fields; only those repositories are rescanned. counter
// may be nil.
func NewRescanner(finder ImageFinder, queue RescanQueue, usesKEV func(repository string) bool, counter RescanCounter, logger *slog.Logger) *Rescanner {
	if logger == nil {
		logger = slog.Default()
	}
	return &Rescanner{
		finder:  finder,
		queue:   queue,
		usesKEV: usesKEV,
		counter: counter,
		logger:  logger,
		wake:    make(chan struct{}, 1),
		pending: map[string]struct{}{},
	}
}

// Notify records newly listed CVEs without blocking the sync. Use it as the
// Service.OnAdded listener.
func (r *Rescanner) Notify(_ context.Context, added []string) {
	r.mu.Lock()
	for _, id := range added {
		r.pending[id] = struct{}{}
	}
	r.mu.Unlock()
	select {
	case r.wake <- struct{}{}:
	default:
	}
}

// Run processes notified CVEs until ctx is done.
func (r *Rescanner) Run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-r.wake:
			ids := r.take()
			if len(ids) == 0 {
				continue
			}
			if err := r.Process(ctx, ids); err != nil && ctx.Err() == nil {
				r.logger.Error("KEV rescan failed", "cves", len(ids), "error", err)
				r.requeue(ids)
			}
		}
	}
}

func (r *Rescanner) take() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	ids := make([]string, 0, len(r.pending))
	for id := range r.pending {
		ids = append(ids, id)
	}
	r.pending = map[string]struct{}{}
	sort.Strings(ids)
	return ids
}

// requeue puts ids back for the next notification. A failed lookup is
// retried with the next sync that adds CVEs; the regular rescan interval
// covers the rest.
func (r *Rescanner) requeue(ids []string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, id := range ids {
		r.pending[id] = struct{}{}
	}
}

// Process queues a rescan for each current image with one of ids, once per
// digest, when its repository's policy reads KEV.
func (r *Rescanner) Process(ctx context.Context, ids []string) error {
	images, err := r.finder.ImagesWithCVEs(ctx, ids)
	if err != nil {
		return fmt.Errorf("find images with newly listed KEV CVEs: %w", err)
	}
	seen := map[string]struct{}{}
	policyReadsKEV := map[string]bool{}
	queued, skipped := 0, 0
	for _, image := range images {
		key := image.Repository + "@" + image.Digest
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		uses, known := policyReadsKEV[image.Repository]
		if !known {
			uses = r.usesKEV(image.Repository)
			policyReadsKEV[image.Repository] = uses
		}
		if !uses {
			skipped++
			continue
		}
		if err := r.queue.RescanKEV(ctx, image); err != nil {
			r.logger.Warn("KEV rescan not queued", "repository", image.Repository, "digest", image.Digest, "error", err)
			continue
		}
		queued++
		if r.counter != nil {
			r.counter.Inc()
		}
	}
	r.logger.Info("newly listed KEV CVEs checked against stored images",
		"cves", len(ids), "images", len(seen), "rescans_queued", queued, "policy_ignores_kev", skipped)
	return nil
}
