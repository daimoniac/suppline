package config

import (
	"fmt"
	"os"
	"time"

	"github.com/daimoniac/suppline/internal/errors"
)

// Load loads configuration from environment variables and suppline.yml defaults
func Load() (*Config, error) {
	regsyncPath := getEnv("SUPPLINE_CONFIG", "suppline.yml")

	// Parse regsync config to get defaults
	var workerPollInterval time.Duration
	var rescanInterval time.Duration
	var workerConcurrency int
	var workerRetryAttempts int
	var workerRetryBackoff time.Duration
	var queueBufferSize int

	// Try to load regsync config for defaults
	if regsyncCfg, err := ParseRegsync(regsyncPath); err == nil {
		if interval, err := regsyncCfg.GetWorkerPollInterval(); err == nil {
			workerPollInterval = interval
		}
		if interval, err := regsyncCfg.GetRescanInterval(""); err == nil {
			rescanInterval = interval
		}
		workerConcurrency = regsyncCfg.GetWorkerConcurrency()
		workerRetryAttempts = regsyncCfg.GetWorkerRetryAttempts()
		if backoff, err := regsyncCfg.GetWorkerRetryBackoff(); err == nil {
			workerRetryBackoff = backoff
		}
		queueBufferSize = regsyncCfg.GetQueueBufferSize()
	}

	// Use defaults from suppline.yml, or fall back to hardcoded defaults
	if workerPollInterval == 0 {
		workerPollInterval = 5 * time.Second
	}
	if rescanInterval == 0 {
		rescanInterval = 24 * time.Hour
	}
	if workerConcurrency == 0 {
		workerConcurrency = 3
	}
	if workerRetryAttempts == 0 {
		workerRetryAttempts = 3
	}
	if workerRetryBackoff == 0 {
		workerRetryBackoff = 10 * time.Second
	}
	if queueBufferSize == 0 {
		queueBufferSize = 1000
	}

	cfg := &Config{
		RegsyncPath: regsyncPath,
		Queue: QueueConfig{
			BufferSize: queueBufferSize,
		},
		Worker: WorkerConfig{
			PollInterval:  workerPollInterval,
			RetryAttempts: workerRetryAttempts,
			RetryBackoff:  workerRetryBackoff,
			Concurrency:   workerConcurrency,
		},
		Scanner: ScannerConfig{
			ServerAddr:    getEnv("TRIVY_SERVER_ADDR", "localhost:4954"),
			Token:         getEnv("TRIVY_TOKEN", ""),
			CustomHeaders: make(map[string]string),
			Timeout:       getEnvDuration("TRIVY_TIMEOUT", 5*time.Minute),
			Insecure:      getEnvBool("TRIVY_INSECURE", false),
			RegsyncPath:   getEnv("SUPPLINE_CONFIG", "suppline.yml"),
		},
		Attestation: AttestationConfig{
			KeyBased: struct {
				Key string
			}{
				Key: getEnv("ATTESTATION_KEY", ""),
			},
			RekorURL:     getEnv("REKOR_URL", "https://rekor.sigstore.dev"),
			FulcioURL:    getEnv("FULCIO_URL", "https://fulcio.sigstore.dev"),
			UseKeyless:   getEnvBool("ATTESTATION_USE_KEYLESS", false),
			OIDCIssuer:   getEnv("OIDC_ISSUER", ""),
			OIDCClientID: getEnv("OIDC_CLIENT_ID", ""),
		},
		StateStore: StateStoreConfig{
			Type:           getEnv("STATE_STORE_TYPE", "sqlite"),
			PostgresURL:    getEnv("POSTGRES_URL", ""),
			SQLitePath:     getEnv("SQLITE_PATH", "suppline.db"),
			RescanInterval: rescanInterval,
		},
		API: APIConfig{
			Enabled:  getEnvBool("API_ENABLED", true),
			Port:     getEnvInt("API_PORT", 8080),
			APIKey:   getEnv("SUPPLINE_API_KEY", ""),
			ReadOnly: getEnvBool("API_READ_ONLY", false),
		},
		Observability: ObservabilityConfig{
			LogLevel:        getEnv("LOG_LEVEL", "info"),
			MetricsPort:     getEnvInt("METRICS_PORT", 9090),
			HealthCheckPort: getEnvInt("HEALTH_CHECK_PORT", 8081),
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

	if c.Scanner.ServerAddr == "" {
		return errors.NewPermanentf("TRIVY_SERVER_ADDR environment variable is required (e.g., localhost:4954 or trivy:4954)")
	}

	if c.StateStore.Type != "sqlite" && c.StateStore.Type != "postgres" && c.StateStore.Type != "memory" {
		return errors.NewPermanentf("invalid state store type: %s (must be sqlite, postgres, or memory)", c.StateStore.Type)
	}

	if c.StateStore.Type == "postgres" && c.StateStore.PostgresURL == "" {
		return errors.NewPermanentf("postgres URL is required when using postgres state store")
	}

	if c.StateStore.Type == "sqlite" && c.StateStore.SQLitePath == "" {
		return errors.NewPermanentf("sqlite path is required when using sqlite state store")
	}

	if !c.Attestation.UseKeyless && c.Attestation.KeyBased.Key == "" {
		return errors.NewPermanentf("attestation key is required when not using keyless mode")
	}

	if c.Attestation.UseKeyless && (c.Attestation.OIDCIssuer == "" || c.Attestation.OIDCClientID == "") {
		return errors.NewPermanentf("OIDC issuer and client ID are required when using keyless mode")
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

func getEnvInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		var intValue int
		if _, err := fmt.Sscanf(value, "%d", &intValue); err == nil {
			return intValue
		}
	}
	return defaultValue
}

func getEnvBool(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		return value == "true" || value == "1" || value == "yes"
	}
	return defaultValue
}

func getEnvDuration(key string, defaultValue time.Duration) time.Duration {
	if value := os.Getenv(key); value != "" {
		if duration, err := time.ParseDuration(value); err == nil {
			return duration
		}
	}
	return defaultValue
}
