package cosign

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/suppline/suppline/internal/config"
)

// AuthenticateRegistries logs cosign into all registries from regsync config
// This should be called during initialization phase, not per-attestation
func AuthenticateRegistries(ctx context.Context, client *Client, regsyncCfg *config.RegsyncConfig, logger *slog.Logger) error {
	if logger == nil {
		logger = slog.Default()
	}

	logger.Info("authenticating cosign with registries", "count", len(regsyncCfg.Creds))

	for _, cred := range regsyncCfg.Creds {
		if cred.Registry == "" || cred.User == "" || cred.Pass == "" {
			logger.Warn("skipping incomplete registry credential", "registry", cred.Registry)
			continue
		}

		if err := client.Login(ctx, LoginOptions{
			Registry: cred.Registry,
			Username: cred.User,
			Password: cred.Pass,
		}); err != nil {
			return fmt.Errorf("failed to authenticate registry %s: %w", cred.Registry, err)
		}
	}

	logger.Info("cosign authenticated with all registries")
	return nil
}
