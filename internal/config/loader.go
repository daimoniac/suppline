package config

import (
	"fmt"
	"os"
	"strings"

	"github.com/daimoniac/suppline/internal/errors"
)

// Load reads suppline.yml (path from SUPPLINE_CONFIG) for runtime settings
// and the environment for secrets. Only these environment variables are read:
// SUPPLINE_CONFIG, SUPPLINE_API_KEY, POSTGRES_URL, TRIVY_TOKEN,
// ATTESTATION_KEY and ATTESTATION_KEY_PASSWORD. suppline.yml can pull further
// secrets in with {{ env "NAME" }}.
func Load() (*Config, error) {
	regsyncPath := getEnv("SUPPLINE_CONFIG", "suppline.yml")

	regsyncCfg, err := ParseRegsync(regsyncPath)
	if err != nil {
		return nil, fmt.Errorf("load %s: %w", regsyncPath, err)
	}
	return fromFile(regsyncPath, regsyncCfg)
}

// fromFile builds the runtime configuration from a parsed suppline.yml and
// the secret environment variables.
func fromFile(regsyncPath string, file *RegsyncConfig) (*Config, error) {
	workerPollInterval, err := file.GetWorkerPollInterval()
	if err != nil {
		return nil, errors.NewPermanentf("%s", err)
	}
	rescanInterval, err := file.GetRescanInterval("")
	if err != nil {
		return nil, errors.NewPermanentf("defaults.rescanInterval: %s", err)
	}
	workerRetryBackoff, err := file.GetWorkerRetryBackoff()
	if err != nil {
		return nil, errors.NewPermanentf("%s", err)
	}

	trivyTimeout, err := parseDurationSetting("scanner.timeout", file.Scanner.Timeout, defaultTrivyTimeout)
	if err != nil {
		return nil, errors.NewPermanentf("%s", err)
	}
	attestTimeout, err := parseDurationSetting("attestation.commandTimeout", file.Attestation.CommandTimeout, defaultAttestCommandTimeout)
	if err != nil {
		return nil, errors.NewPermanentf("%s", err)
	}

	postgresURL := getEnv("POSTGRES_URL", "")

	cfg := &Config{
		RegsyncPath:   regsyncPath,
		MirrorEnabled: boolOr(file.Mirror.Enabled, true),
		Queue: QueueConfig{
			BufferSize: intOr(file.GetQueueBufferSize(), 1000),
		},
		Worker: WorkerConfig{
			PollInterval:      workerPollInterval,
			RetryAttempts:     intOr(file.GetWorkerRetryAttempts(), 3),
			RetryBackoff:      workerRetryBackoff,
			Concurrency:       intOr(file.GetWorkerConcurrency(), 3),
			UrgentConcurrency: file.GetWorkerUrgentConcurrency(),
		},
		Scanner: ScannerConfig{
			ServerAddr:    stringOr(file.Scanner.Server, defaultTrivyServer),
			Token:         getEnv("TRIVY_TOKEN", ""),
			CustomHeaders: make(map[string]string),
			Timeout:       trivyTimeout,
			Insecure:      file.Scanner.Insecure,
			LocalFallback: boolOr(file.Scanner.LocalFallback, true),
			RegsyncPath:   regsyncPath,
		},
		Attestation: AttestationConfig{
			Key:               getEnv("ATTESTATION_KEY", ""),
			CommandTimeout:    attestTimeout,
			AllowHTTPRegistry: file.Attestation.AllowHTTPRegistry,
			NewBundleFormat:   boolOr(file.Attestation.NewBundleFormat, true),
		},
		StateStore: StateStoreConfig{
			PostgresURL:    postgresURL,
			RescanInterval: rescanInterval,
		},
		API: APIConfig{
			Port:        intOr(file.Server.Port, defaultAPIPort),
			APIKey:      getEnv("SUPPLINE_API_KEY", ""),
			ReadOnly:    file.Server.ReadOnly,
			AllowNoAuth: file.Server.AllowNoAuth,
			BasePath:    file.Server.BasePath,
			OIDC:        file.Server.OIDC,
		},
		Observability: ObservabilityConfig{
			LogLevel: stringOr(file.Observability.LogLevel, defaultLogLevel),
			Port:     intOr(file.Observability.Port, defaultObservabilityPort),
		},
	}

	return cfg, nil
}

// Validate validates the configuration
func (c *Config) Validate() error {
	if c.RegsyncPath == "" {
		return errors.NewPermanentf("regsync path is required")
	}

	if _, err := os.Stat(c.RegsyncPath); os.IsNotExist(err) {
		return errors.NewPermanentf("regsync file not found: %s", c.RegsyncPath)
	}

	if strings.TrimSpace(c.StateStore.PostgresURL) == "" {
		return errors.NewPermanentf("POSTGRES_URL is required: suppline keeps its state in PostgreSQL")
	}

	if c.Attestation.Key == "" {
		return errors.NewPermanentf("ATTESTATION_KEY is required (base64-encoded cosign private key)")
	}

	basePath, err := NormalizeBasePath(c.API.BasePath)
	if err != nil {
		return err
	}
	c.API.BasePath = basePath

	if oidc := c.API.OIDC; oidc != nil {
		if !strings.HasPrefix(oidc.Issuer, "https://") {
			return errors.NewPermanentf("server.oidc.issuer must be an https URL, got %q", oidc.Issuer)
		}
		if strings.TrimSpace(oidc.Audience) == "" {
			return errors.NewPermanentf("server.oidc.audience is required")
		}
		if strings.TrimSpace(oidc.Claim) == "" {
			oidc.Claim = DefaultOIDCClaim
		}
	}

	if strings.TrimSpace(c.API.APIKey) == "" && !c.API.AllowNoAuth {
		return errors.NewPermanentf("SUPPLINE_API_KEY is required (authentication would otherwise be disabled for every route). Set server.allowNoAuth: true in suppline.yml only for isolated evaluation")
	}

	return nil
}

// Helper functions for environment variable parsing
func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
