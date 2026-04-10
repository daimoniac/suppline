package config

import (
	"log/slog"
	"time"

	"github.com/daimoniac/suppline/internal/types"
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
	Concurrency   int
}

// ScannerConfig configures the Trivy scanner connection
type ScannerConfig struct {
	ServerAddr    string
	Token         string
	CustomHeaders map[string]string
	Timeout       time.Duration
	Insecure      bool
	LocalFallback bool         // If true, retry without --server when server-mode scan fails
	RegsyncPath   string       // Path to suppline.yml for registry credentials
	Logger        *slog.Logger // Logger instance for structured logging
}

// AttestationConfig configures Sigstore attestation and signing
type AttestationConfig struct {
	KeyBased struct {
		Key string // Base64-encoded key content
	}
	RekorURL     string
	FulcioURL    string
	UseKeyless   bool
	OIDCIssuer   string
	OIDCClientID string
}

// StateStoreConfig configures the state store
type StateStoreConfig struct {
	Type               string
	PostgresURL        string
	SQLitePath         string
	RescanInterval     time.Duration
	RuntimeInUseWindow time.Duration
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

// RegsyncConfig represents the complete regsync configuration
type RegsyncConfig struct {
	Version  int                  `yaml:"version"`
	Creds    []RegistryCredential `yaml:"creds"`
	Defaults Defaults             `yaml:"defaults"`
	Sync     []SyncEntry          `yaml:"sync"`
}

// RegistryCredential contains authentication information for a registry
type RegistryCredential struct {
	Registry      string `yaml:"registry"`
	User          string `yaml:"user"`
	Pass          string `yaml:"pass"`
	RepoAuth      bool   `yaml:"repoAuth"`
	ReqPerSec     int    `yaml:"reqPerSec"`
	ReqConcurrent int    `yaml:"reqConcurrent"`
}

// Defaults contains default configuration values
type Defaults struct {
	Parallel              int                  `yaml:"parallel"`
	RescanInterval        string               `yaml:"x-rescanInterval,omitempty"`
	RuntimeInUseWindow    string               `yaml:"x-runtimeInUseWindow,omitempty"`
	WorkerPollInterval    string               `yaml:"x-worker-poll-interval,omitempty"`
	WorkerConcurrency     int                  `yaml:"x-worker-concurrency,omitempty"`
	WorkerRetryAttempts   int                  `yaml:"x-worker-retry-attempts,omitempty"`
	WorkerRetryBackoff    string               `yaml:"x-worker-retry-backoff,omitempty"`
	QueueBufferSize       int                  `yaml:"x-queue-buffer-size,omitempty"`
	SCAIValidityExtension string               `yaml:"x-scaiValidityExtension,omitempty"`
	Policy                *PolicyConfig        `yaml:"x-policy,omitempty"`
	VEXRepo               *bool                `yaml:"x-vex-repo,omitempty"`
	VEX                   []types.VEXStatement `yaml:"x-vex,omitempty"` // CycloneDX VEX statements merged with sync-specific ones
}

// SyncEntry represents a single sync configuration
type SyncEntry struct {
	Source                string               `yaml:"source"`
	Target                string               `yaml:"target"`
	Type                  string               `yaml:"type"`
	Schedule              string               `yaml:"schedule,omitempty"`
	Platform              string               `yaml:"platform,omitempty"`
	Tags                  *TagFilter           `yaml:"tags,omitempty"`
	VEX                   []types.VEXStatement `yaml:"x-vex,omitempty"` // CycloneDX VEX statements
	RescanInterval        string               `yaml:"x-rescanInterval,omitempty"`
	SCAIValidityExtension string               `yaml:"x-scaiValidityExtension,omitempty"`
	Policy                *PolicyConfig        `yaml:"x-policy,omitempty"`
	VEXRepo               *bool                `yaml:"x-vex-repo,omitempty"`
	Ignore                bool                 `yaml:"-"` // If true, suppline skips this entry entirely
}

// UnmarshalYAML supports both x-suppline-ignore and the legacy x-supplineIgnore field names.
func (s *SyncEntry) UnmarshalYAML(value *yaml.Node) error {
	type syncEntryAlias SyncEntry

	var aux struct {
		syncEntryAlias `yaml:",inline"`
		IgnoreLegacy   bool `yaml:"x-supplineIgnore,omitempty"`
		IgnoreKebab    bool `yaml:"x-suppline-ignore,omitempty"`
	}

	if err := value.Decode(&aux); err != nil {
		return err
	}

	*s = SyncEntry(aux.syncEntryAlias)
	s.Ignore = aux.IgnoreLegacy || aux.IgnoreKebab

	return nil
}

// TagFilter defines tag filtering rules
type TagFilter struct {
	SemverRange []string `yaml:"semverRange,omitempty"`
	Deny        []string `yaml:"deny,omitempty"`
}

// PolicyConfig represents a CEL-based security policy
type PolicyConfig struct {
	Expression        string `yaml:"expression"`
	FailureMessage    string `yaml:"failureMessage,omitempty"`
	MinimumReleaseAge string `yaml:"minimumReleaseAge,omitempty"`
}
