package main

import (
	"log/slog"

	"github.com/daimoniac/suppline/internal/config"
	"github.com/daimoniac/suppline/internal/kev/feed"
	"github.com/daimoniac/suppline/internal/observability"
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
