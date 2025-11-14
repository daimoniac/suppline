package config

import (
	"fmt"
	"os"
	"time"
)

// Load loads configuration from environment variables and suppline.yml defaults
func Load() (*Config, error) {
	regsyncPath := getEnv("SUPPLINE_CONFIG", "suppline.yml")
	
	// Parse regsync config to get defaults
	var workerPollInterval time.Duration
	var rescanInterval time.Duration
	
	// Try to load regsync config for defaults
	if regsyncCfg, err := ParseRegsync(regsyncPath); err == nil {
		if interval, err := regsyncCfg.GetWorkerPollInterval(); err == nil {
			workerPollInterval = interval
		}
		if interval, err := regsyncCfg.GetRescanInterval(""); err == nil {
			rescanInterval = interval
		}
	}
	
	// Use defaults from suppline.yml, or fall back to hardcoded defaults
	if workerPollInterval == 0 {
		workerPollInterval = 5 * time.Second
	}
	if rescanInterval == 0 {
		rescanInterval = 24 * time.Hour
	}
	
	cfg := &Config{
		RegsyncPath: regsyncPath,
		Queue: QueueConfig{
			BufferSize: getEnvInt("QUEUE_BUFFER_SIZE", 1000),
		},
		Worker: WorkerConfig{
			PollInterval:  workerPollInterval,
			RetryAttempts: getEnvInt("WORKER_RETRY_ATTEMPTS", 3),
			RetryBackoff:  getEnvDuration("WORKER_RETRY_BACKOFF", 10*time.Second),
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
				KeyPath     string
				KeyPassword string
			}{
				KeyPath:     getEnv("ATTESTATION_KEY_PATH", ""),
				KeyPassword: getEnv("ATTESTATION_KEY_PASSWORD", ""),
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
			APIKey:   getEnv("API_KEY", ""),
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
		return fmt.Errorf("regsync path is required")
	}

	if _, err := os.Stat(c.RegsyncPath); os.IsNotExist(err) {
		return fmt.Errorf("regsync file not found: %s", c.RegsyncPath)
	}

	if c.Scanner.ServerAddr == "" {
		return fmt.Errorf("trivy server address is required")
	}

	if c.StateStore.Type != "sqlite" && c.StateStore.Type != "postgres" && c.StateStore.Type != "memory" {
		return fmt.Errorf("invalid state store type: %s (must be sqlite, postgres, or memory)", c.StateStore.Type)
	}

	if c.StateStore.Type == "postgres" && c.StateStore.PostgresURL == "" {
		return fmt.Errorf("postgres URL is required when using postgres state store")
	}

	if c.StateStore.Type == "sqlite" && c.StateStore.SQLitePath == "" {
		return fmt.Errorf("sqlite path is required when using sqlite state store")
	}

	if !c.Attestation.UseKeyless && c.Attestation.KeyBased.KeyPath == "" {
		return fmt.Errorf("attestation key path is required when not using keyless mode")
	}

	if c.Attestation.UseKeyless && (c.Attestation.OIDCIssuer == "" || c.Attestation.OIDCClientID == "") {
		return fmt.Errorf("OIDC issuer and client ID are required when using keyless mode")
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
