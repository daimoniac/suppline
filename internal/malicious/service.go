package malicious

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/go-git/go-git/v5/plumbing"

	"github.com/daimoniac/suppline/internal/observability"
)

// Status says whether a scan's malicious-package check could rely on the data.
type Status string

const (
	// StatusOK means the index is loaded and recently synced.
	StatusOK Status = "ok"
	// StatusUnavailable means no index has been loaded yet.
	StatusUnavailable Status = "unavailable"
	// StatusStale means the last successful sync is older than allowed.
	StatusStale Status = "stale"
)

// HealthComponent is the name the service reports under on /health.
const HealthComponent = "malicious_packages"

// Snapshot is a consistent view of the index for one scan.
type Snapshot struct {
	Index    *Index
	Commit   string
	SyncedAt time.Time
	Status   Status
}

// Update tells listeners what a sync changed. Full means every tracked image
// should be matched again (first load, a re-clone, or recovery from stale);
// otherwise Changed holds the added or modified entries.
type Update struct {
	Full    bool
	Commit  string
	Changed []*Entry
}

// HealthReporter receives the service's status for /health.
type HealthReporter interface {
	UpdateComponentHealth(name string, status observability.ComponentStatus, message string)
}

// feed is the part of Source the service uses.
type feed interface {
	Sync(ctx context.Context) (SyncResult, error)
	LoadAll(ctx context.Context, commit plumbing.Hash) (map[string]*Entry, error)
	Diff(ctx context.Context, from, to plumbing.Hash) (map[string]*Entry, []string, error)
}

// ServiceConfig configures a Service.
type ServiceConfig struct {
	SyncInterval time.Duration
	StaleAfter   time.Duration
	Ecosystems   []string
}

// Service keeps the index current and hands out snapshots. Scans never wait
// for it: before the first load a snapshot reports StatusUnavailable.
type Service struct {
	feed       feed
	cfg        ServiceConfig
	health     HealthReporter
	metrics    *observability.Metrics
	logger     *slog.Logger
	now        func() time.Time
	mu         sync.RWMutex
	index      *Index
	commit     plumbing.Hash
	syncedAt   time.Time
	listenerMu sync.Mutex
	listeners  []func(context.Context, Update)
}

// NewService creates a service over source. health and metrics may be nil.
func NewService(source *Source, cfg ServiceConfig, health HealthReporter, metrics *observability.Metrics, logger *slog.Logger) (*Service, error) {
	return newService(source, cfg, health, metrics, logger)
}

func newService(source feed, cfg ServiceConfig, health HealthReporter, metrics *observability.Metrics, logger *slog.Logger) (*Service, error) {
	for _, ecosystem := range cfg.Ecosystems {
		if !KnownEcosystem(ecosystem) {
			return nil, fmt.Errorf("x-malicious-packages.ecosystems: unsupported ecosystem %q (supported: %v)", ecosystem, DefaultEcosystems)
		}
	}
	if len(cfg.Ecosystems) == 0 {
		cfg.Ecosystems = DefaultEcosystems
	}
	if cfg.SyncInterval <= 0 {
		cfg.SyncInterval = time.Hour
	}
	if cfg.StaleAfter <= 0 {
		cfg.StaleAfter = 6 * time.Hour
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Service{feed: source, cfg: cfg, health: health, metrics: metrics, logger: logger, now: time.Now}, nil
}

// OnUpdate registers a listener called after each sync that changed the index.
// Listeners run on the sync goroutine and must not block for long.
func (s *Service) OnUpdate(fn func(context.Context, Update)) {
	s.listenerMu.Lock()
	defer s.listenerMu.Unlock()
	s.listeners = append(s.listeners, fn)
}

// Snapshot returns the current index and its status.
func (s *Service) Snapshot() Snapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.snapshotLocked()
}

func (s *Service) snapshotLocked() Snapshot {
	snapshot := Snapshot{Index: s.index, SyncedAt: s.syncedAt}
	if !s.commit.IsZero() {
		snapshot.Commit = s.commit.String()
	}
	switch {
	case s.index == nil:
		snapshot.Status = StatusUnavailable
	case s.now().Sub(s.syncedAt) > s.cfg.StaleAfter:
		snapshot.Status = StatusStale
	default:
		snapshot.Status = StatusOK
	}
	return snapshot
}

// Run syncs now and then every SyncInterval until ctx is done.
func (s *Service) Run(ctx context.Context) {
	s.reportHealth("")
	s.Sync(ctx)
	ticker := time.NewTicker(s.cfg.SyncInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.Sync(ctx)
		}
	}
}

// Sync fetches the repository once and updates the index.
func (s *Service) Sync(ctx context.Context) {
	started := s.now()
	update, err := s.sync(ctx)
	if err != nil {
		if ctx.Err() != nil {
			return
		}
		s.logger.Error("malicious-packages sync failed", "error", err)
		if s.metrics != nil {
			s.metrics.MaliciousSyncErrors.Inc()
		}
		s.reportHealth(err.Error())
		return
	}
	snapshot := s.Snapshot()
	s.logger.Info("malicious-packages synced",
		"commit", snapshot.Commit,
		"entries", snapshot.Index.Len(),
		"full", update != nil && update.Full,
		"changed", changedCount(update),
		"duration", s.now().Sub(started).String())
	if s.metrics != nil {
		s.metrics.MaliciousLastSync.Set(float64(snapshot.SyncedAt.Unix()))
		for ecosystem, count := range snapshot.Index.CountByEcosystem() {
			s.metrics.MaliciousPackages.WithLabelValues(ecosystem).Set(float64(count))
		}
	}
	s.reportHealth("")
	if update != nil {
		s.notify(ctx, *update)
	}
}

func changedCount(update *Update) int {
	if update == nil {
		return 0
	}
	return len(update.Changed)
}

func (s *Service) sync(ctx context.Context) (*Update, error) {
	result, err := s.feed.Sync(ctx)
	if err != nil {
		return nil, err
	}

	s.mu.RLock()
	current := s.index
	indexed := s.commit
	wasStale := s.snapshotLocked().Status == StatusStale
	s.mu.RUnlock()

	var next *Index
	var update *Update
	switch {
	case current == nil || result.Previous.IsZero() || result.Previous != indexed:
		entries, err := s.feed.LoadAll(ctx, result.Current)
		if err != nil {
			return nil, fmt.Errorf("load malicious-packages: %w", err)
		}
		next = NewIndex(entries, s.cfg.Ecosystems)
		update = &Update{Full: true}
	case result.Previous == result.Current:
		next = current
	default:
		changed, removed, err := s.feed.Diff(ctx, result.Previous, result.Current)
		if err != nil {
			s.logger.Warn("malicious-packages diff failed, reloading everything", "error", err)
			entries, loadErr := s.feed.LoadAll(ctx, result.Current)
			if loadErr != nil {
				return nil, fmt.Errorf("load malicious-packages: %w", loadErr)
			}
			next = NewIndex(entries, s.cfg.Ecosystems)
			update = &Update{Full: true}
			break
		}
		next = current.Apply(changed, removed)
		if len(changed) > 0 {
			entries := make([]*Entry, 0, len(changed))
			for _, entry := range changed {
				entries = append(entries, entry)
			}
			update = &Update{Changed: entries}
		}
	}
	if wasStale {
		// Scans made while stale need matching against everything we missed.
		update = &Update{Full: true}
	}

	s.mu.Lock()
	s.index = next
	s.commit = result.Current
	s.syncedAt = s.now()
	s.mu.Unlock()

	if update != nil {
		update.Commit = result.Current.String()
	}
	return update, nil
}

func (s *Service) notify(ctx context.Context, update Update) {
	s.listenerMu.Lock()
	listeners := append([]func(context.Context, Update){}, s.listeners...)
	s.listenerMu.Unlock()
	for _, listener := range listeners {
		listener(ctx, update)
	}
}

// reportHealth always reports healthy: /health has no degraded state and an
// unhealthy component would fail the liveness probe, restarting the pod and
// discarding the clone. The status is carried in the message instead.
func (s *Service) reportHealth(syncErr string) {
	if s.health == nil {
		return
	}
	snapshot := s.Snapshot()
	message := string(snapshot.Status)
	if snapshot.Commit != "" {
		message += fmt.Sprintf(": commit %.12s synced %s ago, %d entries",
			snapshot.Commit, s.now().Sub(snapshot.SyncedAt).Round(time.Second), snapshot.Index.Len())
	}
	if syncErr != "" {
		message += "; last sync failed: " + syncErr
	}
	s.health.UpdateComponentHealth(HealthComponent, observability.StatusHealthy, message)
}
