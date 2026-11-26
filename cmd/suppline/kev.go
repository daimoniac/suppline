package main

import (
	"context"
	"log/slog"

	"github.com/daimoniac/suppline/internal/config"
	"github.com/daimoniac/suppline/internal/kev/feed"
	"github.com/daimoniac/suppline/internal/observability"
	"github.com/daimoniac/suppline/internal/policy"
	"github.com/daimoniac/suppline/internal/scanenqueue"
	"github.com/daimoniac/suppline/internal/statestore"
)

// newKEVService builds the CISA KEV feed from the kev block. It returns nil
// when the feed is disabled. The caller runs it on every instance: it only
// reads a public feed, and the API on a standby uses it too.
func newKEVService(settings config.KEVSettings, health *observability.HealthChecker, logger *slog.Logger) *feed.Service {
	if !settings.Enabled {
		logger.Info("CISA KEV feed disabled")
		return nil
	}
	moduleLogger := logger.With("module", "kev")
	service := feed.NewService(feed.Config{
		FeedURL:      settings.FeedURL,
		FallbackURL:  settings.FallbackURL,
		SyncInterval: settings.SyncInterval,
		StaleAfter:   settings.StaleAfter,
	}, health, observability.GetMetrics(), moduleLogger)
	health.RegisterComponent(feed.HealthComponent)
	if settings.FromTriage {
		logger.Info("CISA KEV feed configured from triage.kev_feed_url / triage.kev_cache_ttl; prefer the top-level kev block")
	}
	logger.Info("CISA KEV feed enabled",
		"feed_url", settings.FeedURL,
		"fallback_url", settings.FallbackURL,
		"sync_interval", settings.SyncInterval.String(),
		"stale_after", settings.StaleAfter.String())
	return service
}

// kevImageFinder finds current images by CVE for the KEV rescanner.
type kevImageFinder struct {
	store *statestore.Store
}

func (f kevImageFinder) ImagesWithCVEs(ctx context.Context, cveIDs []string) ([]feed.Image, error) {
	records, err := f.store.QueryVulnerabilitiesByCVEIDs(ctx, statestore.VulnFilter{}, cveIDs)
	if err != nil {
		return nil, err
	}
	images := make([]feed.Image, 0, len(records))
	for _, record := range records {
		images = append(images, feed.Image{Repository: record.Repository, Digest: record.Digest, Tag: record.Tag})
	}
	return images, nil
}

// kevRescanQueue queues urgent rescans for the KEV rescanner.
type kevRescanQueue struct {
	enqueuer *scanenqueue.Enqueuer
}

func (q kevRescanQueue) RescanKEV(ctx context.Context, image feed.Image) error {
	_, err := q.enqueuer.EnqueueUrgentRescan(ctx, scanenqueue.Image{Repository: image.Repository, Digest: image.Digest, Tag: image.Tag})
	return err
}

// policyUsesKEV reports whether repository's policy reads KEV fields. A
// policy that cannot be resolved counts as reading them: an extra rescan is
// cheaper than a missed one.
func policyUsesKEV(resolver interface {
	ResolvePolicy(repository string) (policy.PolicyConfig, error)
}) func(string) bool {
	return func(repository string) bool {
		cfg, err := resolver.ResolvePolicy(repository)
		if err != nil {
			return true
		}
		return policy.UsesKEV(cfg.Expression)
	}
}
