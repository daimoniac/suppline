package malicious

import (
	"context"
	"fmt"
	"log/slog"
	"sync"

	"github.com/daimoniac/suppline/internal/statestore"
	"github.com/daimoniac/suppline/internal/types"
)

// RematchStore is the state the rematcher reads and updates.
type RematchStore interface {
	ListInventoryDigests(ctx context.Context) ([]string, error)
	ListPackageInventory(ctx context.Context, digest string) ([]types.PackageRef, error)
	ListInventoryByPackage(ctx context.Context, ecosystem, name string) ([]statestore.InventoryPackage, error)
	ListLatestDigestScans(ctx context.Context, digest string) ([]statestore.DigestScan, error)
	ListDigestsWithMaliciousStatus(ctx context.Context, statuses ...string) ([]string, error)
	UpdateMaliciousCheck(ctx context.Context, scanID int64, check *types.MaliciousCheck) error
}

// RescanQueue queues an urgent rescan of one image.
type RescanQueue interface {
	RescanMalicious(ctx context.Context, repository, digest, tag string) error
}

// RematchCounter counts rescans the rematcher queued.
type RematchCounter interface {
	Inc()
}

// Rematcher matches stored package inventories against the index after each
// sync. A digest is rescanned only when an advisory now matches it that its
// latest scan did not record; the rescan re-runs policy and re-signs SCAI.
// A digest whose latest scan ran while the check was unavailable or stale,
// and that has no new match, gets its stored check updated instead
// (the signed SCAI stays as it was; see ADR 0001).
type Rematcher struct {
	service  *Service
	store    RematchStore
	queue    RescanQueue
	rescans  RematchCounter
	logger   *slog.Logger
	updates  chan Update
	mu       sync.Mutex
	fullDrop bool
}

// NewRematcher creates a rematcher. rescans may be nil.
func NewRematcher(service *Service, store RematchStore, queue RescanQueue, rescans RematchCounter, logger *slog.Logger) *Rematcher {
	if logger == nil {
		logger = slog.Default()
	}
	return &Rematcher{
		service: service,
		store:   store,
		queue:   queue,
		rescans: rescans,
		logger:  logger,
		updates: make(chan Update, 16),
	}
}

// Notify hands an update to the rematcher without blocking the sync. If the
// backlog is full, the next run becomes a full re-match.
func (r *Rematcher) Notify(_ context.Context, update Update) {
	select {
	case r.updates <- update:
	default:
		r.mu.Lock()
		r.fullDrop = true
		r.mu.Unlock()
		r.logger.Warn("malicious-packages re-match backlog full, next run re-matches everything")
	}
}

// Run processes updates until ctx is done.
func (r *Rematcher) Run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case update := <-r.updates:
			update = r.coalesce(update)
			if err := r.Process(ctx, update); err != nil && ctx.Err() == nil {
				r.logger.Error("malicious-packages re-match failed", "full", update.Full, "error", err)
			}
		}
	}
}

// coalesce folds queued updates into one. Any full update, or a dropped one,
// makes the result full.
func (r *Rematcher) coalesce(update Update) Update {
	for {
		select {
		case next := <-r.updates:
			if next.Full || update.Full {
				update = Update{Full: true, Commit: next.Commit}
				continue
			}
			update.Changed = append(update.Changed, next.Changed...)
			update.Commit = next.Commit
		default:
			r.mu.Lock()
			if r.fullDrop {
				update = Update{Full: true, Commit: update.Commit}
				r.fullDrop = false
			}
			r.mu.Unlock()
			return update
		}
	}
}

// Process runs one re-match against the service's current snapshot.
func (r *Rematcher) Process(ctx context.Context, update Update) error {
	snapshot := r.service.Snapshot()
	if snapshot.Status == StatusUnavailable {
		return nil
	}
	var handled map[string]bool
	if update.Full {
		var err error
		if handled, err = r.full(ctx, snapshot); err != nil {
			return err
		}
	} else if err := r.incremental(ctx, snapshot, update.Changed); err != nil {
		return err
	}
	// Also covers images with no language packages: they have no inventory
	// rows, so the full re-match never visits them.
	return r.catchUp(ctx, snapshot, handled)
}

// catchUp matches digests whose latest scan ran while the index was
// unavailable or stale. A full re-match covers them too, but a scan that
// checked before the index loaded can be saved after that re-match ran.
func (r *Rematcher) catchUp(ctx context.Context, snapshot Snapshot, skip map[string]bool) error {
	if snapshot.Status != StatusOK {
		return nil
	}
	digests, err := r.store.ListDigestsWithMaliciousStatus(ctx, types.MaliciousCheckUnavailable, types.MaliciousCheckStale)
	if err != nil {
		return fmt.Errorf("list unchecked digests: %w", err)
	}
	rescanned, confirmed, visited := 0, 0, 0
	for _, digest := range digests {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if skip[digest] {
			continue
		}
		visited++
		refs, err := r.store.ListPackageInventory(ctx, digest)
		if err != nil {
			return fmt.Errorf("list inventory of %s: %w", digest, err)
		}
		n, c, err := r.reconcile(ctx, digest, CheckPackages(snapshot, Packages(refs)), true)
		if err != nil {
			return err
		}
		rescanned += n
		confirmed += c
	}
	if visited > 0 {
		r.logger.Info("malicious-packages catch-up finished",
			"digests", visited, "rescans_queued", rescanned, "checks_confirmed", confirmed)
	}
	return nil
}

// full re-matches every digest with a stored inventory and returns them.
func (r *Rematcher) full(ctx context.Context, snapshot Snapshot) (map[string]bool, error) {
	digests, err := r.store.ListInventoryDigests(ctx)
	if err != nil {
		return nil, fmt.Errorf("list inventory digests: %w", err)
	}
	handled := make(map[string]bool, len(digests))
	rescanned, confirmed := 0, 0
	for _, digest := range digests {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		refs, err := r.store.ListPackageInventory(ctx, digest)
		if err != nil {
			return nil, fmt.Errorf("list inventory of %s: %w", digest, err)
		}
		check := CheckPackages(snapshot, Packages(refs))
		n, c, err := r.reconcile(ctx, digest, check, true)
		if err != nil {
			return nil, err
		}
		handled[digest] = true
		rescanned += n
		confirmed += c
	}
	r.logger.Info("malicious-packages full re-match finished",
		"digests", len(digests), "rescans_queued", rescanned, "checks_confirmed", confirmed)
	return handled, nil
}

// incremental re-matches only digests holding a package that a changed entry
// names, against those entries.
func (r *Rematcher) incremental(ctx context.Context, snapshot Snapshot, changed []*Entry) error {
	if len(changed) == 0 {
		return nil
	}
	entries := make(map[string]*Entry, len(changed))
	for i, entry := range changed {
		entries[fmt.Sprintf("%d", i)] = entry
	}
	changedIndex := NewIndex(entries, r.service.Ecosystems())

	byDigest := make(map[string][]Package)
	for _, entry := range changed {
		for _, pkg := range AffectedPackages(entry, r.service.Ecosystems()) {
			rows, err := r.store.ListInventoryByPackage(ctx, pkg.Ecosystem, pkg.Name)
			if err != nil {
				return fmt.Errorf("list inventory for %s/%s: %w", pkg.Ecosystem, pkg.Name, err)
			}
			for _, row := range rows {
				byDigest[row.Digest] = append(byDigest[row.Digest], Packages([]types.PackageRef{row.Package})...)
			}
		}
	}
	rescanned := 0
	for digest, packages := range byDigest {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		hits := changedIndex.Match(packages)
		if len(hits) == 0 {
			continue
		}
		check := CheckPackages(Snapshot{Index: changedIndex, Status: snapshot.Status, Commit: snapshot.Commit, SyncedAt: snapshot.SyncedAt}, packages)
		n, _, err := r.reconcile(ctx, digest, check, false)
		if err != nil {
			return err
		}
		rescanned += n
	}
	r.logger.Info("malicious-packages re-match finished",
		"changed_entries", len(changed), "candidate_digests", len(byDigest), "rescans_queued", rescanned)
	return nil
}

// reconcile compares a fresh check with each repository's latest scan of the
// digest. A new advisory queues a rescan. With confirm, a latest scan that ran
// without usable data and has nothing new gets its stored check replaced.
func (r *Rematcher) reconcile(ctx context.Context, digest string, check *types.MaliciousCheck, confirm bool) (rescanned, confirmed int, err error) {
	scans, err := r.store.ListLatestDigestScans(ctx, digest)
	if err != nil {
		return 0, 0, fmt.Errorf("latest scans of %s: %w", digest, err)
	}
	for _, scan := range scans {
		if hasNewFinding(scan.Malicious, check) {
			if err := r.queue.RescanMalicious(ctx, scan.Repository, scan.Digest, scan.Tag); err != nil {
				if ctx.Err() != nil {
					return rescanned, confirmed, ctx.Err()
				}
				r.logger.Warn("failed to queue malicious-package rescan",
					"repository", scan.Repository, "digest", scan.Digest, "error", err)
				continue
			}
			rescanned++
			if r.rescans != nil {
				r.rescans.Inc()
			}
			r.logger.Warn("queued rescan for newly matched malicious package",
				"repository", scan.Repository, "digest", scan.Digest, "ids", findingIDs(check))
			continue
		}
		if confirm && scan.Malicious != nil && scan.Malicious.Status != types.MaliciousCheckOK && check.Status == types.MaliciousCheckOK {
			if err := r.store.UpdateMaliciousCheck(ctx, scan.ScanID, check); err != nil {
				return rescanned, confirmed, fmt.Errorf("update check of scan %d: %w", scan.ScanID, err)
			}
			confirmed++
		}
	}
	return rescanned, confirmed, nil
}

// hasNewFinding reports whether check has an advisory the recorded check lacks.
func hasNewFinding(recorded, check *types.MaliciousCheck) bool {
	if check == nil || len(check.Findings) == 0 {
		return false
	}
	known := make(map[string]bool)
	if recorded != nil {
		for _, finding := range recorded.Findings {
			known[finding.ID] = true
		}
	}
	for _, finding := range check.Findings {
		if !known[finding.ID] {
			return true
		}
	}
	return false
}

func findingIDs(check *types.MaliciousCheck) []string {
	if check == nil {
		return nil
	}
	ids := make([]string, 0, len(check.Findings))
	for _, finding := range check.Findings {
		ids = append(ids, finding.ID)
	}
	return ids
}
