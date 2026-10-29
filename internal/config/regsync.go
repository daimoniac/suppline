package config

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/daimoniac/suppline/internal/errors"
	"github.com/daimoniac/suppline/internal/types"
	rtemplate "github.com/regclient/regclient/pkg/template"
	"github.com/regclient/regclient/types/mediatype"
	"gopkg.in/yaml.v3"
)

const defaultCleanupReposSchedule = "0 4 * * *"

// rateLimitRetryMin matches regsync: wait at least five minutes after a rate limit.
const rateLimitRetryMin = 5 * time.Minute

var defaultMediaTypes = []string{
	mediatype.Docker2Manifest,
	mediatype.Docker2ManifestList,
	mediatype.OCI1Manifest,
	mediatype.OCI1ManifestList,
}

// ParseRegsync reads and parses a suppline.yml configuration file
func ParseRegsync(path string) (*RegsyncConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, errors.NewTransientf("failed to read regsync file: %w", err)
	}

	var config RegsyncConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, errors.NewPermanentf("failed to parse regsync YAML: %w", err)
	}

	if err := normalizeRegsync(&config); err != nil {
		return nil, errors.NewPermanentf("invalid regsync configuration: %w", err)
	}

	// Expand templates on regsync string fields. x- text is expanded only
	// where ExpandEnvTemplate is called by its own consumers.
	if err := expandConfig(&config); err != nil {
		return nil, errors.NewPermanentf("failed to expand configuration: %w", err)
	}

	// Validate VEX statements
	if err := config.ValidateVEXStatements(); err != nil {
		return nil, errors.NewPermanentf("invalid VEX configuration: %w", err)
	}

	return &config, nil
}

// Active returns sync entries suppline itself processes.
// Ignored entries stay on Sync so the mirror still copies them.
func (c *RegsyncConfig) Active() []SyncEntry {
	if c == nil {
		return nil
	}
	out := make([]SyncEntry, 0, len(c.Sync))
	_ = c.ForEachActive(func(i int) error {
		out = append(out, c.Sync[i])
		return nil
	})
	return out
}

// ForEachActive visits each sync entry suppline itself processes.
// The index is the position in Sync. The mirror does not use this walk.
func (c *RegsyncConfig) ForEachActive(fn func(i int) error) error {
	return c.walk(func(i int, active bool) error {
		if !active {
			return nil
		}
		return fn(i)
	})
}

// KeepActive rebuilds Sync. Ignored entries stay, in order, because the mirror
// still copies them. keep reports whether an active entry is kept.
func (c *RegsyncConfig) KeepActive(keep func(SyncEntry) (bool, error)) (int, error) {
	if c == nil {
		return 0, nil
	}
	next := make([]SyncEntry, 0, len(c.Sync))
	removed := 0
	err := c.walk(func(i int, active bool) error {
		entry := c.Sync[i]
		if !active {
			next = append(next, entry)
			return nil
		}
		kept, err := keep(entry)
		if err != nil {
			return err
		}
		if !kept {
			removed++
			return nil
		}
		next = append(next, entry)
		return nil
	})
	if err != nil {
		return 0, err
	}
	c.Sync = next
	return removed, nil
}

// walk is the only place that distinguishes ignored sync entries from the ones
// suppline processes. The mirror ranges Sync itself and still copies ignored entries.
func (c *RegsyncConfig) walk(fn func(i int, active bool) error) error {
	if c == nil || fn == nil {
		return nil
	}
	for i := range c.Sync {
		if err := fn(i, !c.Sync[i].IsIgnored()); err != nil {
			return err
		}
	}
	return nil
}

func normalizeRegsync(c *RegsyncConfig) error {
	if c.Version == 0 {
		c.Version = 1
	}
	if c.Version > 1 {
		return fmt.Errorf("unsupported config version %d", c.Version)
	}
	if c.Defaults.RateLimit.Retry.Std() < rateLimitRetryMin {
		c.Defaults.RateLimit.Retry = Duration(rateLimitRetryMin)
	}
	if c.Defaults.CleanupRepos == nil {
		disabled := false
		c.Defaults.CleanupRepos = &disabled
	}
	if *c.Defaults.CleanupRepos && c.Defaults.CleanupReposSchedule == "" {
		c.Defaults.CleanupReposSchedule = defaultCleanupReposSchedule
	}
	for i := range c.Sync {
		applySyncDefaults(&c.Sync[i], c.Defaults)
	}
	return nil
}

func applySyncDefaults(s *SyncEntry, d Defaults) {
	if s.Backup == "" && d.Backup != "" {
		s.Backup = d.Backup
	}
	if s.Schedule == "" && s.Interval == 0 {
		if d.Schedule != "" {
			s.Schedule = d.Schedule
		} else if d.Interval != 0 {
			s.Interval = d.Interval
		}
	}
	if s.RateLimit.Min == 0 && d.RateLimit.Min != 0 {
		s.RateLimit.Min = d.RateLimit.Min
	}
	if s.RateLimit.Retry == 0 {
		s.RateLimit.Retry = d.RateLimit.Retry
	} else if s.RateLimit.Retry.Std() < rateLimitRetryMin {
		s.RateLimit.Retry = Duration(rateLimitRetryMin)
	}
	if len(s.MediaTypes) == 0 {
		if len(d.MediaTypes) > 0 {
			s.MediaTypes = d.MediaTypes
		} else {
			s.MediaTypes = append([]string(nil), defaultMediaTypes...)
		}
	}
	s.DigestTags = boolDefault(s.DigestTags, d.DigestTags)
	s.Referrers = boolDefault(s.Referrers, d.Referrers)
	if s.ReferrerFilters == nil {
		s.ReferrerFilters = d.ReferrerFilters
	}
	if s.ReferrerSrc == "" && d.ReferrerSrc != "" {
		s.ReferrerSrc = d.ReferrerSrc
	}
	if s.ReferrerTgt == "" && d.ReferrerTgt != "" {
		s.ReferrerTgt = d.ReferrerTgt
	}
	s.ReferrerSlow = boolDefault(s.ReferrerSlow, d.ReferrerSlow)
	s.FastCheck = boolDefault(s.FastCheck, d.FastCheck)
	s.ForceRecursive = boolDefault(s.ForceRecursive, d.ForceRecursive)
	s.IncludeExternal = boolDefault(s.IncludeExternal, d.IncludeExternal)
	if s.Hooks.Pre == nil && d.Hooks.Pre != nil {
		s.Hooks.Pre = d.Hooks.Pre
	}
	if s.Hooks.Post == nil && d.Hooks.Post != nil {
		s.Hooks.Post = d.Hooks.Post
	}
	if s.Hooks.Unchanged == nil && d.Hooks.Unchanged != nil {
		s.Hooks.Unchanged = d.Hooks.Unchanged
	}
	s.CleanupTags = boolDefault(s.CleanupTags, d.CleanupTags)
	if s.CleanupTagsExclude == nil && d.CleanupTagsExclude != nil {
		s.CleanupTagsExclude = d.CleanupTagsExclude
	}
}

func boolDefault(entry, defaults *bool) *bool {
	if entry != nil {
		return entry
	}
	value := defaults != nil && *defaults
	return &value
}

// expandConfig expands regsync template fields. Backup templates expand at copy time.
func expandConfig(config *RegsyncConfig) error {
	for i := range config.Creds {
		cred := &config.Creds[i]
		expanded, err := expandField("registry", cred.Registry, nil)
		if err != nil {
			return err
		}
		cred.Registry = expanded
		if cred.User, err = expandField("user for registry "+cred.Registry, cred.User, nil); err != nil {
			return err
		}
		if cred.Pass, err = expandField("pass for registry "+cred.Registry, cred.Pass, nil); err != nil {
			return err
		}
		if cred.RegCert, err = expandField("regcert for registry "+cred.Registry, cred.RegCert, nil); err != nil {
			return err
		}
		if cred.ClientCert, err = expandField("clientCert for registry "+cred.Registry, cred.ClientCert, nil); err != nil {
			return err
		}
		if cred.ClientKey, err = expandField("clientKey for registry "+cred.Registry, cred.ClientKey, nil); err != nil {
			return err
		}
	}

	for i := range config.Sync {
		sync := &config.Sync[i]
		data := struct{ Sync SyncEntry }{Sync: *sync}
		var err error
		if sync.Source, err = expandField("source", sync.Source, data); err != nil {
			return err
		}
		data.Sync.Source = sync.Source
		if sync.ReferrerSrc, err = expandField("referrerSource", sync.ReferrerSrc, data); err != nil {
			return err
		}
		data.Sync.ReferrerSrc = sync.ReferrerSrc
		if sync.Target, err = expandField("target", sync.Target, data); err != nil {
			return err
		}
		data.Sync.Target = sync.Target
		if sync.ReferrerTgt, err = expandField("referrerTarget", sync.ReferrerTgt, data); err != nil {
			return err
		}
	}
	return nil
}

func expandField(name, tmpl string, data any) (string, error) {
	expanded, err := expandTemplate(tmpl, data)
	if err != nil {
		return "", errors.NewPermanentf("failed to expand %s: %w", name, err)
	}
	return expanded, nil
}

// ExpandEnvTemplate expands {{ env "VAR" }} using the process environment.
// A string without a template is returned unchanged.
func ExpandEnvTemplate(tmpl string) (string, error) {
	return expandTemplate(tmpl, nil)
}

// expandTemplate expands a regsync template. Strings without "{{" are returned unchanged.
func expandTemplate(tmpl string, data any) (string, error) {
	if !strings.Contains(tmpl, "{{") {
		return tmpl, nil
	}
	return rtemplate.String(tmpl, data)
}

// GetCredentialForRegistry returns the credential for a specific registry
func (c *RegsyncConfig) GetCredentialForRegistry(registry string) *RegistryCredential {
	for i := range c.Creds {
		if c.Creds[i].Registry == registry {
			return &c.Creds[i]
		}
	}
	return nil
}

// IsIgnored returns true if the sync entry has x-suppline-ignore set to true.
func (s *SyncEntry) IsIgnored() bool {
	return s.Ignore
}

// SyncTargetMatches reports whether a sync target names the same repository as wanted.
// Image targets may include a tag. Templates are expanded before the comparison.
func SyncTargetMatches(target, kind, wanted string) (bool, error) {
	expanded, err := ExpandEnvTemplate(target)
	if err != nil {
		return false, fmt.Errorf("expand sync target: %w", err)
	}
	wanted = strings.TrimSpace(wanted)
	if wanted == "" {
		return false, nil
	}
	if expanded == wanted {
		return true, nil
	}
	if kind == "image" {
		if index := strings.LastIndex(expanded, ":"); index != -1 {
			expanded = expanded[:index]
		}
	}
	return expanded == wanted, nil
}

// GetTargetRepositories returns all target repositories from sync entries
// For type=image entries, strips the tag to return just the repository name
// Entries with x-suppline-ignore: true are excluded.
func (c *RegsyncConfig) GetTargetRepositories() []string {
	seen := make(map[string]bool)
	targets := make([]string, 0, len(c.Sync))

	for _, sync := range c.Active() {

		target := sync.Target

		// For type=image, strip the tag from the target
		if sync.Type == "image" {
			// Split on last colon to separate repo from tag
			if idx := strings.LastIndex(target, ":"); idx != -1 {
				target = target[:idx]
			}
		}

		// Deduplicate repositories
		if !seen[target] {
			seen[target] = true
			targets = append(targets, target)
		}
	}

	return targets
}

// GetRescanInterval returns the rescan interval for a specific target repository
// Returns the sync entry's interval if specified, otherwise the default, otherwise 7d
// Handles both type=repository (exact match) and type=image (strips tag for matching)
func (c *RegsyncConfig) GetRescanInterval(target string) (time.Duration, error) {
	// Check sync entry first
	for _, sync := range c.Active() {
		syncTarget := sync.Target

		// For type=image, strip the tag for comparison
		if sync.Type == "image" {
			if idx := strings.LastIndex(syncTarget, ":"); idx != -1 {
				syncTarget = syncTarget[:idx]
			}
		}

		if syncTarget == target && sync.RescanInterval != "" {
			return parseInterval(sync.RescanInterval)
		}
	}

	// Fall back to default
	if c.Defaults.RescanInterval != "" {
		return parseInterval(c.Defaults.RescanInterval)
	}

	// Fall back to hardcoded default
	return 7 * 24 * time.Hour, nil
}

// GetRuntimeInUseWindow returns the in-use runtime observation window.
// Reads defaults.x-runtimeInUseWindow and falls back to 60m.
func (c *RegsyncConfig) GetRuntimeInUseWindow() (time.Duration, error) {
	if c.Defaults.RuntimeInUseWindow != "" {
		return parseInterval(c.Defaults.RuntimeInUseWindow)
	}

	return 60 * time.Minute, nil
}

// GetSCAIValidityExtension returns the SCAI validity extension for a specific target repository
// This is the additional time beyond the next scheduled scan that the SCAI attestation remains valid
// Returns the sync entry's extension if specified, otherwise the default, otherwise 1d
// Handles both type=repository (exact match) and type=image (strips tag for matching)
func (c *RegsyncConfig) GetSCAIValidityExtension(target string) (time.Duration, error) {
	// Check sync entry first
	for _, sync := range c.Active() {
		syncTarget := sync.Target

		// For type=image, strip the tag for comparison
		if sync.Type == "image" {
			if idx := strings.LastIndex(syncTarget, ":"); idx != -1 {
				syncTarget = syncTarget[:idx]
			}
		}

		if syncTarget == target && sync.SCAIValidityExtension != "" {
			return parseInterval(sync.SCAIValidityExtension)
		}
	}

	// Fall back to default
	if c.Defaults.SCAIValidityExtension != "" {
		return parseInterval(c.Defaults.SCAIValidityExtension)
	}

	// Fall back to hardcoded default (1 day)
	return 24 * time.Hour, nil
}

// GetTagsForRepository returns the tags that should be processed for a repository
// For type=repository entries, returns nil (meaning all tags should be listed)
// For type=image entries, returns the specific tag from the target
func (c *RegsyncConfig) GetTagsForRepository(repo string) []string {
	var tags []string

	for _, sync := range c.Active() {
		if sync.Type == "image" {
			// Extract repository from target (strip tag)
			targetRepo := sync.Target
			if idx := strings.LastIndex(targetRepo, ":"); idx != -1 {
				repoWithoutTag := targetRepo[:idx]
				tag := targetRepo[idx+1:]

				if repoWithoutTag == repo {
					tags = append(tags, tag)
				}
			}
		}
	}

	return tags
}

// GetWorkerPollInterval returns the worker poll interval from defaults
// Returns the default if specified, otherwise 5 seconds
func (c *RegsyncConfig) GetWorkerPollInterval() (time.Duration, error) {
	if c.Defaults.WorkerPollInterval != "" {
		return parseInterval(c.Defaults.WorkerPollInterval)
	}

	// Fall back to hardcoded default
	return 5 * time.Second, nil
}

// GetWorkerConcurrency returns the worker concurrency from defaults
// Returns the default if specified, otherwise 3
func (c *RegsyncConfig) GetWorkerConcurrency() int {
	if c.Defaults.WorkerConcurrency > 0 {
		return c.Defaults.WorkerConcurrency
	}
	return 3 // Default concurrency
}

// GetWorkerRetryAttempts returns the worker retry attempts from defaults
// Returns the default if specified, otherwise 3
func (c *RegsyncConfig) GetWorkerRetryAttempts() int {
	if c.Defaults.WorkerRetryAttempts > 0 {
		return c.Defaults.WorkerRetryAttempts
	}
	return 3 // Default retry attempts
}

// GetWorkerRetryBackoff returns the worker retry backoff from defaults
// Returns the default if specified, otherwise 10 seconds
func (c *RegsyncConfig) GetWorkerRetryBackoff() (time.Duration, error) {
	if c.Defaults.WorkerRetryBackoff != "" {
		return parseInterval(c.Defaults.WorkerRetryBackoff)
	}
	return 10 * time.Second, nil // Default backoff
}

// GetQueueBufferSize returns the queue buffer size from defaults
// Returns the default if specified, otherwise 1000
func (c *RegsyncConfig) GetQueueBufferSize() int {
	if c.Defaults.QueueBufferSize > 0 {
		return c.Defaults.QueueBufferSize
	}
	return 1000 // Default buffer size
}

// ValidateVEXStatements validates all VEX statements in the config.
// Returns the first validation error encountered.
func (c *RegsyncConfig) ValidateVEXStatements() error {
	for i, stmt := range c.Defaults.VEX {
		if err := types.ValidateVEXStatement(stmt); err != nil {
			return fmt.Errorf("defaults.x-vex[%d]: %w", i, err)
		}
	}
	for _, sync := range c.Active() {
		for i, stmt := range sync.VEX {
			if err := types.ValidateVEXStatement(stmt); err != nil {
				return fmt.Errorf("sync[%s].x-vex[%d]: %w", sync.Target, i, err)
			}
		}
		for i, stmt := range sync.VEXAuto {
			if err := types.ValidateVEXStatement(stmt); err != nil {
				return fmt.Errorf("sync[%s].x-vex-auto[%d]: %w", sync.Target, i, err)
			}
		}
	}
	if err := c.Triage.Validate(); err != nil {
		return err
	}
	return nil
}
