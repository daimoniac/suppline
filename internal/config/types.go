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
	MirrorEnabled bool
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
	Enabled     bool
	Port        int
	APIKey      string
	ReadOnly    bool
	AllowNoAuth bool // explicit opt-in; empty API key otherwise refuses to start
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
	Triage   *TriageConfig        `yaml:"x-triage,omitempty"`
}

// RegistryCredential contains authentication information for a registry.
// Fields match regsync/regclient creds so the in-process mirror can build a host config.
type RegistryCredential struct {
	Registry      string `yaml:"registry"`
	Hostname      string `yaml:"hostname,omitempty"`
	User          string `yaml:"user,omitempty"`
	Pass          string `yaml:"pass,omitempty"`
	Token         string `yaml:"token,omitempty"`
	RepoAuth      bool   `yaml:"repoAuth"`
	ReqPerSec     int    `yaml:"reqPerSec"`
	ReqConcurrent int    `yaml:"reqConcurrent"`
	// TLS controls TLS for this registry: "enabled" (default), "insecure", or "disabled" (HTTP).
	// Matches regsync/regclient creds.tls.
	TLS        string `yaml:"tls,omitempty"`
	RegCert    string `yaml:"regcert,omitempty"`
	ClientCert string `yaml:"clientCert,omitempty"`
	ClientKey  string `yaml:"clientKey,omitempty"`
	CredHelper string `yaml:"credHelper,omitempty"`
	PathPrefix string `yaml:"pathPrefix,omitempty"`
	Scheme     string `yaml:"scheme,omitempty"`
}

// Defaults contains default configuration values.
// Regsync server fields are inherited onto each sync entry by ParseRegsync.
type Defaults struct {
	Parallel             int              `yaml:"parallel"`
	Backup               string           `yaml:"backup,omitempty"`
	Interval             Duration         `yaml:"interval,omitempty"`
	Schedule             string           `yaml:"schedule,omitempty"`
	RateLimit            RateLimit        `yaml:"ratelimit,omitempty"`
	DigestTags           *bool            `yaml:"digestTags,omitempty"`
	Referrers            *bool            `yaml:"referrers,omitempty"`
	ReferrerFilters      []ReferrerFilter `yaml:"referrerFilters,omitempty"`
	ReferrerSrc          string           `yaml:"referrerSource,omitempty"`
	ReferrerTgt          string           `yaml:"referrerTarget,omitempty"`
	ReferrerSlow         *bool            `yaml:"referrerSlow,omitempty"`
	FastCheck            *bool            `yaml:"fastCheck,omitempty"`
	ForceRecursive       *bool            `yaml:"forceRecursive,omitempty"`
	IncludeExternal      *bool            `yaml:"includeExternal,omitempty"`
	MediaTypes           []string         `yaml:"mediaTypes,omitempty"`
	Hooks                Hooks            `yaml:"hooks,omitempty"`
	CleanupTags          *bool            `yaml:"cleanupTags,omitempty"`
	CleanupTagsExclude   []string         `yaml:"cleanupTagsExclude,omitempty"`
	CleanupRepos         *bool            `yaml:"cleanupRepos,omitempty"`
	CleanupReposExclude  []string         `yaml:"cleanupReposExclude,omitempty"`
	CleanupReposSchedule string           `yaml:"cleanupReposSchedule,omitempty"`
	BlobLimit            int64            `yaml:"blobLimit,omitempty"`
	CacheCount           int              `yaml:"cacheCount,omitempty"`
	CacheTime            Duration         `yaml:"cacheTime,omitempty"`
	SkipDockerConf       bool             `yaml:"skipDockerConfig,omitempty"`
	UserAgent            string           `yaml:"userAgent,omitempty"`

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

// SyncEntry represents a single sync configuration.
type SyncEntry struct {
	Source                string               `yaml:"source"`
	Target                string               `yaml:"target"`
	Type                  string               `yaml:"type"`
	Schedule              string               `yaml:"schedule,omitempty"`
	Interval              Duration             `yaml:"interval,omitempty"`
	Platform              string               `yaml:"platform,omitempty"`
	Platforms             []string             `yaml:"platforms,omitempty"`
	Tags                  *TagFilter           `yaml:"tags,omitempty"`
	TagSets               []TagFilter          `yaml:"tagSets,omitempty"`
	Repos                 RepoFilter           `yaml:"repos,omitempty"`
	DigestTags            *bool                `yaml:"digestTags,omitempty"`
	Referrers             *bool                `yaml:"referrers,omitempty"`
	ReferrerFilters       []ReferrerFilter     `yaml:"referrerFilters,omitempty"`
	ReferrerSrc           string               `yaml:"referrerSource,omitempty"`
	ReferrerTgt           string               `yaml:"referrerTarget,omitempty"`
	ReferrerSlow          *bool                `yaml:"referrerSlow,omitempty"`
	FastCheck             *bool                `yaml:"fastCheck,omitempty"`
	ForceRecursive        *bool                `yaml:"forceRecursive,omitempty"`
	IncludeExternal       *bool                `yaml:"includeExternal,omitempty"`
	Backup                string               `yaml:"backup,omitempty"`
	RateLimit             RateLimit            `yaml:"ratelimit,omitempty"`
	MediaTypes            []string             `yaml:"mediaTypes,omitempty"`
	Hooks                 Hooks                `yaml:"hooks,omitempty"`
	CleanupTags           *bool                `yaml:"cleanupTags,omitempty"`
	CleanupTagsExclude    []string             `yaml:"cleanupTagsExclude,omitempty"`
	VEX                   []types.VEXStatement `yaml:"x-vex,omitempty"`      // CycloneDX VEX statements authored by people
	VEXAuto               []types.VEXStatement `yaml:"x-vex-auto,omitempty"` // Triage-owned statements; never written into x-vex
	RescanInterval        string               `yaml:"x-rescanInterval,omitempty"`
	SCAIValidityExtension string               `yaml:"x-scaiValidityExtension,omitempty"`
	Policy                *PolicyConfig        `yaml:"x-policy,omitempty"`
	VEXRepo               *bool                `yaml:"x-vex-repo,omitempty"`
	Ignore                bool                 `yaml:"-"` // If true, suppline skips scanning this entry. The mirror still copies it.
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

// TagFilter defines tag filtering rules.
// Several SemverRange entries are OR. One entry is an AND range, matching regsync.
type TagFilter struct {
	Allow       []string `yaml:"allow,omitempty"`
	Deny        []string `yaml:"deny,omitempty"`
	SemverRange []string `yaml:"semverRange,omitempty"`
}

// RepoFilter is an allow and deny list of repository names for a registry sync.
type RepoFilter struct {
	Allow []string `yaml:"allow,omitempty"`
	Deny  []string `yaml:"deny,omitempty"`
}

// RateLimit is the regsync per-step rate limit.
type RateLimit struct {
	Min   int      `yaml:"min,omitempty"`
	Retry Duration `yaml:"retry,omitempty"`
}

// ReferrerFilter selects which referrers ImageCopy includes.
type ReferrerFilter struct {
	ArtifactType string            `yaml:"artifactType,omitempty"`
	Annotations  map[string]string `yaml:"annotations,omitempty"`
}

// Hooks are external commands regsync runs around a copy.
type Hooks struct {
	Pre       *Hook `yaml:"pre,omitempty"`
	Post      *Hook `yaml:"post,omitempty"`
	Unchanged *Hook `yaml:"unchanged,omitempty"`
}

// Hook is one script invocation. Type "script" runs Params as a command and arguments.
type Hook struct {
	Type   string   `yaml:"type,omitempty"`
	Params []string `yaml:"params,omitempty"`
}

// PolicyConfig represents a CEL-based security policy
type PolicyConfig struct {
	Expression        string `yaml:"expression"`
	FailureMessage    string `yaml:"failureMessage,omitempty"`
	MinimumReleaseAge string `yaml:"minimumReleaseAge,omitempty"`
}
