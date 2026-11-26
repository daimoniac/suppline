// Package feed keeps the CISA KEV catalog current.
package feed

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/daimoniac/suppline/internal/kev"
	"github.com/daimoniac/suppline/internal/observability"
)

// HealthComponent is the name the service reports under on /health.
const HealthComponent = "kev"

const (
	userAgent    = "suppline/1.0 (+https://github.com/daimoniac/suppline)"
	maxFeedBytes = 32 << 20
)

// HealthReporter receives the service's status for /health.
type HealthReporter interface {
	UpdateComponentHealth(name string, status observability.ComponentStatus, message string)
}

// Config configures a Service.
type Config struct {
	FeedURL      string
	FallbackURL  string // tried when FeedURL fails; empty means none
	SyncInterval time.Duration
	StaleAfter   time.Duration
}

// Service keeps the catalog current. Readers never wait for it: before the
// first sync a snapshot reports kev.StatusUnavailable.
type Service struct {
	cfg     Config
	client  *http.Client
	health  HealthReporter
	metrics *observability.Metrics
	logger  *slog.Logger
	now     func() time.Time

	mu       sync.RWMutex
	catalog  *kev.Catalog
	syncedAt time.Time
}

// NewService creates a service. health and metrics may be nil.
func NewService(cfg Config, health HealthReporter, metrics *observability.Metrics, logger *slog.Logger) *Service {
	if cfg.SyncInterval <= 0 {
		cfg.SyncInterval = 6 * time.Hour
	}
	if cfg.StaleAfter < cfg.SyncInterval {
		cfg.StaleAfter = cfg.SyncInterval
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Service{
		cfg:     cfg,
		client:  &http.Client{Timeout: 30 * time.Second},
		health:  health,
		metrics: metrics,
		logger:  logger,
		now:     time.Now,
	}
}

// Snapshot returns the current catalog and its status. A nil service reports
// kev.StatusDisabled.
func (s *Service) Snapshot() kev.Snapshot {
	if s == nil {
		return kev.Snapshot{Status: kev.StatusDisabled}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.snapshotLocked()
}

func (s *Service) snapshotLocked() kev.Snapshot {
	snapshot := kev.Snapshot{Catalog: s.catalog, SyncedAt: s.syncedAt}
	switch {
	case s.catalog == nil:
		snapshot.Status = kev.StatusUnavailable
	case s.now().Sub(s.syncedAt) > s.cfg.StaleAfter:
		snapshot.Status = kev.StatusStale
	default:
		snapshot.Status = kev.StatusOK
	}
	return snapshot
}

// Contains reports whether cve is listed. It fails when there is no catalog
// or the catalog is stale, so a caller that must not miss a listed CVE can
// refuse to proceed instead of treating "unknown" as "not listed".
func (s *Service) Contains(_ context.Context, cve string) (bool, error) {
	snapshot := s.Snapshot()
	switch snapshot.Status {
	case kev.StatusOK:
		_, ok := snapshot.Catalog.Lookup(cve)
		return ok, nil
	case kev.StatusStale:
		return false, fmt.Errorf("catalog is stale: last synced %s ago",
			s.now().Sub(snapshot.SyncedAt).Round(time.Second))
	case kev.StatusDisabled:
		return false, errors.New("the kev feed is disabled")
	default:
		return false, errors.New("no catalog loaded yet")
	}
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

// Sync fetches the feed once and replaces the catalog. A failed sync keeps
// the previous catalog.
func (s *Service) Sync(ctx context.Context) {
	started := s.now()
	catalog, err := s.fetch(ctx)
	if err != nil && ctx.Err() != nil {
		return
	}
	if err == nil {
		s.mu.Lock()
		s.catalog = catalog
		s.syncedAt = s.now()
		s.mu.Unlock()
	}

	if err != nil {
		s.logger.Error("CISA KEV sync failed", "error", err)
		if s.metrics != nil {
			s.metrics.KEVSyncErrors.Inc()
		}
		s.reportHealth(err.Error())
		return
	}
	s.logger.Info("CISA KEV synced",
		"catalog_version", catalog.Version,
		"entries", catalog.Len(),
		"duration", s.now().Sub(started).String())
	if s.metrics != nil {
		s.metrics.KEVLastSync.Set(float64(s.Snapshot().SyncedAt.Unix()))
		s.metrics.KEVEntries.Set(float64(catalog.Len()))
	}
	s.reportHealth("")
}

func (s *Service) fetch(ctx context.Context) (*kev.Catalog, error) {
	catalog, err := s.fetchURL(ctx, s.cfg.FeedURL)
	if err == nil || s.cfg.FallbackURL == "" || s.cfg.FallbackURL == s.cfg.FeedURL || ctx.Err() != nil {
		return catalog, err
	}
	fallback, fallbackErr := s.fetchURL(ctx, s.cfg.FallbackURL)
	if fallbackErr != nil {
		return nil, fmt.Errorf("%w; fallback: %w", err, fallbackErr)
	}
	s.logger.Debug("CISA KEV primary feed failed, used the fallback", "error", err)
	return fallback, nil
}

func (s *Service) fetchURL(ctx context.Context, feedURL string) (*kev.Catalog, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, feedURL, nil)
	if err != nil {
		return nil, fmt.Errorf("build CISA KEV request: %w", err)
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "application/json")
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch CISA KEV feed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("CISA KEV feed status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxFeedBytes))
	if err != nil {
		return nil, fmt.Errorf("read CISA KEV feed: %w", err)
	}
	return kev.Parse(body)
}

// reportHealth always reports healthy: /health has no degraded state, and
// the feed being out of date must not take the instance out of service. The
// status is carried in the message instead.
func (s *Service) reportHealth(syncErr string) {
	if s.health == nil {
		return
	}
	snapshot := s.Snapshot()
	message := string(snapshot.Status)
	if snapshot.Catalog != nil {
		message += fmt.Sprintf(": catalog %s synced %s ago, %d entries",
			snapshot.Catalog.Version, s.now().Sub(snapshot.SyncedAt).Round(time.Second), snapshot.Catalog.Len())
	}
	if syncErr != "" {
		message += "; last sync failed: " + syncErr
	}
	s.health.UpdateComponentHealth(HealthComponent, observability.StatusHealthy, message)
}
