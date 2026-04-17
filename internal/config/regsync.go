package config

import (
	"bytes"
	"fmt"
	"os"
	"strings"
	"text/template"
	"time"

	"github.com/daimoniac/suppline/internal/errors"
	"github.com/daimoniac/suppline/internal/types"
	"gopkg.in/yaml.v3"
)

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

	filterIgnoredSyncEntries(&config)

	// Expand environment variables throughout the configuration
	if err := expandConfig(&config); err != nil {
		return nil, errors.NewPermanentf("failed to expand configuration: %w", err)
	}

	// Validate VEX statements
	if err := config.ValidateVEXStatements(); err != nil {
		return nil, errors.NewPermanentf("invalid VEX configuration: %w", err)
	}

	return &config, nil
}

func filterIgnoredSyncEntries(config *RegsyncConfig) {
	if len(config.Sync) == 0 {
		return
	}

	filtered := config.Sync[:0]
	for _, sync := range config.Sync {
		if sync.IsIgnored() {
			continue
		}
		filtered = append(filtered, sync)
	}

	config.Sync = filtered
}

// expandConfig processes all configuration fields and expands Go template expressions
// Supports {{ env "VAR_NAME" }} syntax for environment variable expansion
func expandConfig(config *RegsyncConfig) error {
	funcMap := template.FuncMap{
		"env": os.Getenv,
	}

	// Expand credential fields
	for i := range config.Creds {
		cred := &config.Creds[i]

		// Expand registry field
		if expanded, err := expandTemplate(cred.Registry, funcMap); err != nil {
			return errors.NewPermanentf("failed to expand registry field: %w", err)
		} else {
			cred.Registry = expanded
		}

		// Expand user field
		if expanded, err := expandTemplate(cred.User, funcMap); err != nil {
			return errors.NewPermanentf("failed to expand user for registry %s: %w", cred.Registry, err)
		} else {
			cred.User = expanded
		}

		// Expand pass field
		if expanded, err := expandTemplate(cred.Pass, funcMap); err != nil {
			return errors.NewPermanentf("failed to expand pass for registry %s: %w", cred.Registry, err)
		} else {
			cred.Pass = expanded
		}
	}

	// Expand sync entry fields
	for i := range config.Sync {
		sync := &config.Sync[i]

		// Expand source field
		if expanded, err := expandTemplate(sync.Source, funcMap); err != nil {
			return errors.NewPermanentf("failed to expand source field: %w", err)
		} else {
			sync.Source = expanded
		}

		// Expand target field
		if expanded, err := expandTemplate(sync.Target, funcMap); err != nil {
			return errors.NewPermanentf("failed to expand target field: %w", err)
		} else {
			sync.Target = expanded
		}
	}

	return nil
}

// expandTemplate expands a Go template string with the provided function map
func expandTemplate(tmpl string, funcMap template.FuncMap) (string, error) {
	// If the string doesn't contain template syntax, return as-is
	if !strings.Contains(tmpl, "{{") {
		return tmpl, nil
	}

	t, err := template.New("expand").Funcs(funcMap).Parse(tmpl)
	if err != nil {
		return "", err
	}

	var buf bytes.Buffer
	if err := t.Execute(&buf, nil); err != nil {
		return "", err
	}

	return buf.String(), nil
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

// GetTargetRepositories returns all target repositories from sync entries
// For type=image entries, strips the tag to return just the repository name
// Entries with x-suppline-ignore: true are excluded.
func (c *RegsyncConfig) GetTargetRepositories() []string {
	seen := make(map[string]bool)
	targets := make([]string, 0, len(c.Sync))

	for _, sync := range c.Sync {
		// Skip entries that are marked as ignored
		if sync.Ignore {
			continue
		}

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
	for _, sync := range c.Sync {
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
	for _, sync := range c.Sync {
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

	for _, sync := range c.Sync {
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

// GetPolicyForTarget returns the policy configuration for a specific target repository
// Returns the sync entry's policy if specified, otherwise the default, otherwise nil
// Handles both type=repository (exact match) and type=image (strips tag for matching)
func (c *RegsyncConfig) GetPolicyForTarget(target string) *PolicyConfig {
	// Check sync entry first
	for _, sync := range c.Sync {
		syncTarget := sync.Target

		// For type=image, strip the tag for comparison
		if sync.Type == "image" {
			if idx := strings.LastIndex(syncTarget, ":"); idx != -1 {
				syncTarget = syncTarget[:idx]
			}
		}

		if syncTarget == target && sync.Policy != nil {
			return sync.Policy
		}
	}

	// Fall back to default
	if c.Defaults.Policy != nil {
		return c.Defaults.Policy
	}

	// No policy configured, caller should use hardcoded default
	return nil
}

// GetMinimumReleaseAgeForTarget returns the configured minimum release age for a specific target repository.
// Returns (duration, true, nil) when configured, (0, false, nil) when not configured, or an error for invalid formats.
func (c *RegsyncConfig) GetMinimumReleaseAgeForTarget(target string) (time.Duration, bool, error) {
	policy := c.GetPolicyForTarget(target)
	if policy == nil || policy.MinimumReleaseAge == "" {
		return 0, false, nil
	}

	duration, err := parseInterval(policy.MinimumReleaseAge)
	if err != nil {
		return 0, false, fmt.Errorf("invalid minimumReleaseAge for target %s: %w", target, err)
	}

	return duration, true, nil
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

// GetVEXRepoForTarget returns whether the Aqua VEX repository should be used
// for Trivy scans of a specific target. The sync entry's setting takes precedence
// over defaults. Returns false if neither is configured.
func (c *RegsyncConfig) GetVEXRepoForTarget(target string) bool {
	for _, sync := range c.Sync {
		syncTarget := sync.Target
		if sync.Type == "image" {
			if idx := strings.LastIndex(syncTarget, ":"); idx != -1 {
				syncTarget = syncTarget[:idx]
			}
		}
		if syncTarget == target && sync.VEXRepo != nil {
			return *sync.VEXRepo
		}
	}
	if c.Defaults.VEXRepo != nil {
		return *c.Defaults.VEXRepo
	}
	return false
}

// IsVEXRepoEnabledAnywhere returns true if any sync entry or the defaults
// enables the VEX repository. Used at startup to decide whether to pre-download.
func (c *RegsyncConfig) IsVEXRepoEnabledAnywhere() bool {
	if c.Defaults.VEXRepo != nil && *c.Defaults.VEXRepo {
		return true
	}
	for _, sync := range c.Sync {
		if sync.VEXRepo != nil && *sync.VEXRepo {
			return true
		}
	}
	return false
}

// GetVEXStatementsForTarget returns VEX statements for a specific target repository.
// Merges defaults + sync-specific x-vex entries with de-duplication by CVE ID.
func (c *RegsyncConfig) GetVEXStatementsForTarget(target string) []types.VEXStatement {
	seen := make(map[string]bool)
	result := make([]types.VEXStatement, 0)

	// First pass: collect all x-vex entries (these take precedence)
	for _, stmt := range c.Defaults.VEX {
		if !seen[stmt.ID] {
			seen[stmt.ID] = true
			result = append(result, stmt)
		}
	}

	for _, sync := range c.Sync {
		syncTarget := sync.Target
		if sync.Type == "image" {
			if idx := strings.LastIndex(syncTarget, ":"); idx != -1 {
				syncTarget = syncTarget[:idx]
			}
		}
		if syncTarget == target {
			for _, stmt := range sync.VEX {
				if !seen[stmt.ID] {
					seen[stmt.ID] = true
					result = append(result, stmt)
				}
			}
		}
	}

	return result
}

// IsVEXExempted checks if a CVE is exempted by a not_affected VEX statement for a target.
// Returns true if the CVE has a not_affected VEX statement that has not expired.
func (c *RegsyncConfig) IsVEXExempted(target, cveID string) (bool, *types.VEXStatement) {
	statements := c.GetVEXStatementsForTarget(target)
	nowUnix := time.Now().Unix()

	for i := range statements {
		stmt := &statements[i]
		if stmt.ID == cveID {
			if stmt.State != types.VEXStateNotAffected {
				return false, nil
			}
			if stmt.ExpiresAt != nil && *stmt.ExpiresAt < nowUnix {
				return false, nil
			}
			return true, stmt
		}
	}

	return false, nil
}

// GetExpiringVEXStatements returns VEX statements that will expire within the specified duration.
func (c *RegsyncConfig) GetExpiringVEXStatements(within time.Duration) []types.VEXStatement {
	var expiring []types.VEXStatement
	nowUnix := time.Now().Unix()
	thresholdUnix := time.Now().Add(within).Unix()

	// Collect all unique VEX statements
	seen := make(map[string]bool)

	checkAndAdd := func(stmt types.VEXStatement) {
		if seen[stmt.ID] {
			return
		}
		seen[stmt.ID] = true
		if stmt.ExpiresAt != nil {
			if *stmt.ExpiresAt > nowUnix && *stmt.ExpiresAt < thresholdUnix {
				expiring = append(expiring, stmt)
			}
		}
	}

	// Check x-vex entries
	for _, stmt := range c.Defaults.VEX {
		checkAndAdd(stmt)
	}
	for _, sync := range c.Sync {
		for _, stmt := range sync.VEX {
			checkAndAdd(stmt)
		}
	}

	return expiring
}

// ValidateVEXStatements validates all VEX statements in the config.
// Returns the first validation error encountered.
func (c *RegsyncConfig) ValidateVEXStatements() error {
	for i, stmt := range c.Defaults.VEX {
		if err := types.ValidateVEXStatement(stmt); err != nil {
			return fmt.Errorf("defaults.x-vex[%d]: %w", i, err)
		}
	}
	for _, sync := range c.Sync {
		for i, stmt := range sync.VEX {
			if err := types.ValidateVEXStatement(stmt); err != nil {
				return fmt.Errorf("sync[%s].x-vex[%d]: %w", sync.Target, i, err)
			}
		}
	}
	return nil
}
