package attestation

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/suppline/suppline/internal/attestation/cosign"
	"github.com/suppline/suppline/internal/config"
)

// AuthenticateCosignRegistries authenticates cosign with all registries from regsync config
// This should be called during initialization phase, after creating the attestor
func AuthenticateCosignRegistries(ctx context.Context, attestor *SigstoreAttestor, regsyncCfg *config.RegsyncConfig, logger *slog.Logger) error {
	if attestor == nil {
		return fmt.Errorf("attestor is nil")
	}

	if regsyncCfg == nil {
		return fmt.Errorf("regsync config is nil")
	}

	return cosign.AuthenticateRegistries(ctx, attestor.cosignClient, regsyncCfg, logger)
}
