package main

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/daimoniac/suppline/internal/config"
	"github.com/daimoniac/suppline/internal/gitops"
	"github.com/daimoniac/suppline/internal/malicious"
	"github.com/daimoniac/suppline/internal/observability"
	"github.com/daimoniac/suppline/internal/scanenqueue"
)

// newMaliciousService builds the malicious-package feed from malicious-packages.
// It returns nil when the feature is disabled.
func newMaliciousService(cfg *config.MaliciousPackagesConfig, health *observability.HealthChecker, logger *slog.Logger) (*malicious.Service, error) {
	if !cfg.IsEnabled() {
		logger.Info("malicious-package detection disabled")
		return nil, nil
	}
	auth, err := gitops.ResolveAuth(cfg.RepoAuth())
	if err != nil {
		return nil, fmt.Errorf("malicious-packages.repo.auth: %w", err)
	}
	moduleLogger := logger.With("module", "malicious")
	source := malicious.NewSource(cfg.RepoURL(), cfg.RepoRef(), auth, cfg.Dir(), cfg.EcosystemList(), moduleLogger)
	service, err := malicious.NewService(source, malicious.ServiceConfig{
		SyncInterval: cfg.Interval(),
		StaleAfter:   cfg.Staleness(),
		Ecosystems:   cfg.EcosystemList(),
	}, health, observability.GetMetrics(), moduleLogger)
	if err != nil {
		return nil, err
	}
	health.RegisterComponent(malicious.HealthComponent)
	logger.Info("malicious-package detection enabled",
		"repo", cfg.RepoURL(),
		"ref", cfg.RepoRef(),
		"sync_interval", cfg.Interval().String(),
		"stale_after", cfg.Staleness().String())
	return service, nil
}

// maliciousRescanQueue queues urgent rescans for the malicious-package rematcher.
type maliciousRescanQueue struct {
	enqueuer *scanenqueue.Enqueuer
}

func (q maliciousRescanQueue) RescanMalicious(ctx context.Context, repository, digest, tag string) error {
	_, err := q.enqueuer.EnqueueUrgentRescan(ctx, scanenqueue.Image{Repository: repository, Digest: digest, Tag: tag})
	return err
}
