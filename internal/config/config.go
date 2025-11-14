package config

import (
	"fmt"
	"log/slog"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Config represents the complete application configuration
type Config struct {
	RegsyncPath   string
	Queue         QueueConfig
	Worker        WorkerConfig
	Scanner       ScannerConfig
	Attestation   AttestationConfig
	StateStore    StateStoreConfig
	API           APIConfig
	Observability ObservabilityConfig
}

// QueueConfig configures the in-memory task queue
type QueueConfig struct {
	BufferSize int
}

// WorkerConfig configures the worker behavior
type WorkerConfig struct {
	PollInterval  time.Duration
	RetryAttempts int
	RetryBackoff  time.Duration
}

// ScannerConfig configures the Trivy scanner connection
type ScannerConfig struct {
	ServerAddr    string
	Token         string
	CustomHeaders map[string]string
	Timeout       time.Duration
	Insecure      bool
	RegsyncPath   string // Path to suppline.yml for registry credentials
	Logger        *slog.Logger // Logger instance for structured logging
}

// AttestationConfig configures Sigstore attestation and signing
type AttestationConfig struct {
	KeyBased struct {
		KeyPath     string
		KeyPassword string
	}
	RekorURL     string
	FulcioURL    string
	UseKeyless   bool
	OIDCIssuer   string
	OIDCClientID string
}

// StateStoreConfig configures the state store
type StateStoreConfig struct {
	Type           string
	PostgresURL    string
	SQLitePath     string
	RescanInterval time.Duration
}

// APIConfig configures the HTTP API server
type APIConfig struct {
	Enabled  bool
	Port     int
	APIKey   string
	ReadOnly bool
}

// ObservabilityConfig configures logging and metrics
type ObservabilityConfig struct {
	LogLevel        string
	MetricsPort     int
	HealthCheckPort int
}

// Load loads configuration from environment variables and files
func Load() (*Config, error) {
	regsyncPath := getEnv("SUPPLINE_CONFIG", "suppline.yml")
	
	// Parse regsync config to get defaults
	var workerPollInterval time.Duration
	var rescanInterval time.Duration
	
	// Try to load regsync config for defaults
	if data, err := os.ReadFile(regsyncPath); err == nil {
		// Simple YAML parsing to extract defaults without full regsync package dependency
		// We'll use a minimal struct just for the defaults we need
		var regsyncDefaults struct {
			Defaults struct {
				WorkerPollInterval string `yaml:"x-worker-poll-interval"`
				RescanInterval     string `yaml:"x-rescanInterval"`
			} `yaml:"defaults"`
		}
		
		if err := yaml.Unmarshal(data, &regsyncDefaults); err == nil {
			if regsyncDefaults.Defaults.WorkerPollInterval != "" {
				if d, err := parseInterval(regsyncDefaults.Defaults.WorkerPollInterval); err == nil {
					workerPollInterval = d
				}
			}
			if regsyncDefaults.Defaults.RescanInterval != "" {
				if d, err := parseInterval(regsyncDefaults.Defaults.RescanInterval); err == nil {
					rescanInterval = d
				}
			}
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

// parseInterval parses interval notation (e.g., "2m", "3h", "7d") into time.Duration
func parseInterval(interval string) (time.Duration, error) {
	if len(interval) < 2 {
		return 0, fmt.Errorf("invalid interval format: %s", interval)
	}

	unit := interval[len(interval)-1]
	valueStr := interval[:len(interval)-1]

	// Parse the numeric value
	var value int
	if _, err := fmt.Sscanf(valueStr, "%d", &value); err != nil {
		return 0, fmt.Errorf("invalid interval value: %s", interval)
	}

	if value <= 0 {
		return 0, fmt.Errorf("interval value must be positive: %s", interval)
	}

	switch unit {
	case 'm':
		return time.Duration(value) * time.Minute, nil
	case 'h':
		return time.Duration(value) * time.Hour, nil
	case 'd':
		return time.Duration(value) * 24 * time.Hour, nil
	default:
		return 0, fmt.Errorf("invalid interval unit (must be m, h, or d): %s", interval)
	}
}
