package main

import (
	"fmt"
	"log/slog"

	"github.com/daimoniac/suppline/internal/config"
	"github.com/daimoniac/suppline/internal/gitops"
	"github.com/daimoniac/suppline/internal/malicious"
	"github.com/daimoniac/suppline/internal/observability"
)

// newMaliciousService builds the malicious-package feed from x-malicious-packages.
// It returns nil when the feature is disabled.
func newMaliciousService(cfg *config.MaliciousPackagesConfig, health *observability.HealthChecker, logger *slog.Logger) (*malicious.Service, error) {
	if !cfg.IsEnabled() {
		logger.Info("malicious-package detection disabled")
		return nil, nil
	}
	auth, err := gitops.ResolveAuth(cfg.RepoAuth())
	if err != nil {
		return nil, fmt.Errorf("x-malicious-packages.repo.auth: %w", err)
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
