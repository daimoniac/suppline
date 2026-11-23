package config

import (
	"log/slog"
	"time"

	"github.com/daimoniac/suppline/internal/types"
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
	// UrgentConcurrency workers take only urgent tasks (CI scan requests),
	// on top of Concurrency.
	UrgentConcurrency int
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

// AttestationConfig configures cosign attestation signing
type AttestationConfig struct {
	Key               string // Base64-encoded cosign private key (ATTESTATION_KEY); its password is read from ATTESTATION_KEY_PASSWORD
	CommandTimeout    time.Duration
	AllowHTTPRegistry bool
	NewBundleFormat   bool
}

// StateStoreConfig configures the state store
type StateStoreConfig struct {
	Type           string // "postgres" when PostgresURL is set, else "sqlite"
	PostgresURL    string
	SQLitePath     string
	RescanInterval time.Duration
}

// APIConfig configures the HTTP API server
type APIConfig struct {
	Port        int
	APIKey      string
	ReadOnly    bool
	AllowNoAuth bool // explicit opt-in; empty API key otherwise refuses to start
	// BasePath is the URL prefix the UI and API are served under, e.g. "/suppline".
	// Empty means the root. Set via server.basePath; normalized by NormalizeBasePath.
	BasePath string
}

// ObservabilityConfig configures logging and the operations port
type ObservabilityConfig struct {
	LogLevel string
	Port     int // serves /metrics, /health and /ready
}

// RegsyncConfig represents the complete regsync configuration
type RegsyncConfig struct {
	Version  int                  `yaml:"version"`
	Creds    []RegistryCredential `yaml:"creds"`
	Defaults Defaults             `yaml:"defaults"`
	Sync     []SyncEntry          `yaml:"sync"`
	// InPlace lists repositories scanned and attested where they live, never
	// copied. ParseRegsync appends them to Sync as entries with InPlace set and
	// clears this list, so every per-repository lookup sees one list.
	InPlace []InPlaceEntry `yaml:"in-place,omitempty"`
	Triage  *TriageConfig  `yaml:"triage,omitempty"`

	// Runtime settings, read once at startup (see runtime.go).
	Server        ServerSettings        `yaml:"server,omitempty"`
	Observability ObservabilitySettings `yaml:"observability,omitempty"`
	Mirror        MirrorSettings        `yaml:"mirror,omitempty"`
	Scanner       ScannerSettings       `yaml:"scanner,omitempty"`
	Store         StoreSettings         `yaml:"store,omitempty"`
	Attestation   AttestationSettings   `yaml:"attestation,omitempty"`
	// MaliciousPackages configures known-malicious package detection.
	MaliciousPackages *MaliciousPackagesConfig `yaml:"malicious-packages,omitempty"`
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
	CleanupKeepRunning   *bool            `yaml:"cleanupKeepRunning,omitempty"`
	CleanupRepos         *bool            `yaml:"cleanupRepos,omitempty"`
	CleanupReposExclude  []string         `yaml:"cleanupReposExclude,omitempty"`
	CleanupReposSchedule string           `yaml:"cleanupReposSchedule,omitempty"`
	BlobLimit            int64            `yaml:"blobLimit,omitempty"`
	CacheCount           int              `yaml:"cacheCount,omitempty"`
	CacheTime            Duration         `yaml:"cacheTime,omitempty"`
	SkipDockerConf       bool             `yaml:"skipDockerConfig,omitempty"`
	UserAgent            string           `yaml:"userAgent,omitempty"`

	RescanInterval string `yaml:"rescanInterval,omitempty"`
	// Cooldown is the default minimum time between suppline first seeing a
	// digest upstream and publishing it on a tag. Empty or "0" disables it.
	Cooldown           string `yaml:"cooldown,omitempty"`
	WorkerPollInterval string `yaml:"worker-poll-interval,omitempty"`
	WorkerConcurrency  int    `yaml:"worker-concurrency,omitempty"`
	// WorkerUrgentConcurrency reserves workers for urgent tasks, on top of
	// worker-concurrency. Nil means DefaultWorkerUrgentConcurrency; 0 reserves none.
	WorkerUrgentConcurrency *int   `yaml:"worker-urgent-concurrency,omitempty"`
	WorkerRetryAttempts     int    `yaml:"worker-retry-attempts,omitempty"`
	WorkerRetryBackoff      string `yaml:"worker-retry-backoff,omitempty"`
	QueueBufferSize         int    `yaml:"queue-buffer-size,omitempty"`
	SCAIValidityExtension   string `yaml:"scaiValidityExtension,omitempty"`
	// CreateVulnerabilityAttestation reports whether a cosign vulnerability attestation is published.
	// Nil means yes. Kyverno loads every referrer while checking SCAI, and vulnerability bundles are
	// the large ones, so production sets this false.
	CreateVulnerabilityAttestation *bool `yaml:"createVulnerabilityAttestation,omitempty"`
	// CreateSBOMAttestation reports whether a cosign SBOM attestation is published.
	// Nil means yes. Kyverno reads these referrers too, so production sets this false.
	CreateSBOMAttestation *bool                `yaml:"createSBOMAttestation,omitempty"`
	Policy                *PolicyConfig        `yaml:"policy,omitempty"`
	VEXRepo               *bool                `yaml:"vex-repo,omitempty"`
	VEX                   []types.VEXStatement `yaml:"vex,omitempty"` // CycloneDX VEX statements merged with sync-specific ones
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
	CleanupKeepRunning    *bool                `yaml:"cleanupKeepRunning,omitempty"` // keep tags a cluster reports running
	VEX                   []types.VEXStatement `yaml:"vex,omitempty"`                // CycloneDX VEX statements authored by people
	VEXAuto               []types.VEXStatement `yaml:"vex-auto,omitempty"`           // Triage-owned statements; never written into vex
	RescanInterval        string               `yaml:"rescanInterval,omitempty"`
	SCAIValidityExtension string               `yaml:"scaiValidityExtension,omitempty"`
	Policy                *PolicyConfig        `yaml:"policy,omitempty"`
	VEXRepo               *bool                `yaml:"vex-repo,omitempty"`
	// Cooldown overrides defaults.cooldown for this entry. "0" disables it.
	Cooldown string `yaml:"cooldown,omitempty"`
	// CooldownReleases skip the rest of the cooldown for single digests.
	CooldownReleases []CooldownRelease `yaml:"cooldown-release,omitempty"`
	Ignore           bool              `yaml:"suppline-ignore,omitempty"` // suppline skips scanning this entry; the mirror still copies it
	// CreateVulnerabilityAttestation and CreateSBOMAttestation override the
	// defaults of the same name for this repository. Nil inherits.
	CreateVulnerabilityAttestation *bool `yaml:"createVulnerabilityAttestation,omitempty"`
	CreateSBOMAttestation          *bool `yaml:"createSBOMAttestation,omitempty"`

	// InPlace marks an entry built from the in-place section: its repository
	// is scanned and attested where it lives and the mirror never touches it.
	InPlace bool `yaml:"-"`
	// ScanRequesters are the CI identities allowed to request scans of an
	// in-place repository.
	ScanRequesters []string `yaml:"-"`
}

// InPlaceEntry is one repository of the in-place section: scanned and
// attested where it lives, never copied. It carries only per-repository
// settings; mirror settings are rejected by strict decoding.
type InPlaceEntry struct {
	Repository                     string               `yaml:"repository"`
	Tags                           *TagFilter           `yaml:"tags,omitempty"`
	TagSets                        []TagFilter          `yaml:"tagSets,omitempty"`
	Policy                         *PolicyConfig        `yaml:"policy,omitempty"`
	VEX                            []types.VEXStatement `yaml:"vex,omitempty"`
	VEXAuto                        []types.VEXStatement `yaml:"vex-auto,omitempty"`
	VEXRepo                        *bool                `yaml:"vex-repo,omitempty"`
	RescanInterval                 string               `yaml:"rescanInterval,omitempty"`
	SCAIValidityExtension          string               `yaml:"scaiValidityExtension,omitempty"`
	ScanRequesters                 []string             `yaml:"scan-requesters,omitempty"`
	CreateVulnerabilityAttestation *bool                `yaml:"createVulnerabilityAttestation,omitempty"`
	CreateSBOMAttestation          *bool                `yaml:"createSBOMAttestation,omitempty"`
}

// syncEntry converts an in-place entry to the internal per-repository record.
func (e InPlaceEntry) syncEntry() SyncEntry {
	disabled := false
	return SyncEntry{
		Source:                         e.Repository,
		Target:                         e.Repository,
		Type:                           "repository",
		Tags:                           e.Tags,
		TagSets:                        e.TagSets,
		Policy:                         e.Policy,
		VEX:                            e.VEX,
		VEXAuto:                        e.VEXAuto,
		VEXRepo:                        e.VEXRepo,
		RescanInterval:                 e.RescanInterval,
		SCAIValidityExtension:          e.SCAIValidityExtension,
		CreateVulnerabilityAttestation: e.CreateVulnerabilityAttestation,
		CreateSBOMAttestation:          e.CreateSBOMAttestation,
		CleanupTags:                    &disabled,
		CleanupKeepRunning:             &disabled,
		InPlace:                        true,
		ScanRequesters:                 append([]string(nil), e.ScanRequesters...),
	}
}

// TagFilter defines tag filtering rules.
// Several SemverRange entries are OR. One entry is an AND range, matching regsync.
type TagFilter struct {
	Allow       []string `yaml:"allow,omitempty"`
	Deny        []string `yaml:"deny,omitempty"`
	SemverRange []string `yaml:"semverRange,omitempty"`
	// Newest keeps only the N tags whose images were built last, after
	// Allow, Deny and SemverRange. Build time is the image config's created
	// field; ties go to the higher tag name. 0 keeps every tag.
	Newest int `yaml:"newest,omitempty"`
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
	Expression     string `yaml:"expression"`
	FailureMessage string `yaml:"failureMessage,omitempty"`
}

// CooldownRelease is a recorded decision to skip the rest of one digest's
// cooldown. It never skips the scan or the attestation.
type CooldownRelease struct {
	Digest string `yaml:"digest"`
	Reason string `yaml:"reason,omitempty"`
	Author string `yaml:"author,omitempty"`
	At     string `yaml:"at,omitempty"`
}
