package regsync

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Config represents the complete regsync configuration
type Config struct {
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
	Parallel              int    `yaml:"parallel"`
	RescanInterval        string `yaml:"x-rescanInterval,omitempty"`
	SCAIValidityExtension string `yaml:"x-scaiValidityExtension,omitempty"`
}

// SyncEntry represents a single sync configuration
type SyncEntry struct {
	Source                string          `yaml:"source"`
	Target                string          `yaml:"target"`
	Type                  string          `yaml:"type"`
	Schedule              string          `yaml:"schedule,omitempty"`
	Platform              string          `yaml:"platform,omitempty"`
	Tags                  *TagFilter      `yaml:"tags,omitempty"`
	Tolerate              []CVEToleration `yaml:"x-tolerate,omitempty"`
	RescanInterval        string          `yaml:"x-rescanInterval,omitempty"`
	SCAIValidityExtension string          `yaml:"x-scaiValidityExtension,omitempty"`
}

// TagFilter defines tag filtering rules
type TagFilter struct {
	SemverRange []string `yaml:"semverRange,omitempty"`
	Deny        []string `yaml:"deny,omitempty"`
}

// CVEToleration represents a tolerated CVE with optional expiry
type CVEToleration struct {
	ID        string     `yaml:"id"`
	Statement string     `yaml:"statement"`
	ExpiresAt *time.Time `yaml:"expires_at,omitempty"`
}

// Parse reads and parses a regsync.yml configuration file
func Parse(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read regsync file: %w", err)
	}

	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse regsync YAML: %w", err)
	}

	return &config, nil
}

// GetCredentialForRegistry returns the credential for a specific registry
func (c *Config) GetCredentialForRegistry(registry string) *RegistryCredential {
	for i := range c.Creds {
		if c.Creds[i].Registry == registry {
			return &c.Creds[i]
		}
	}
	return nil
}

// GetTolerationsForTarget returns CVE tolerations for a specific target repository
func (c *Config) GetTolerationsForTarget(target string) []CVEToleration {
	for _, sync := range c.Sync {
		if sync.Target == target {
			return sync.Tolerate
		}
	}
	return nil
}

// GetTargetRepositories returns all target repositories from sync entries
func (c *Config) GetTargetRepositories() []string {
	targets := make([]string, 0, len(c.Sync))
	for _, sync := range c.Sync {
		targets = append(targets, sync.Target)
	}
	return targets
}

// IsToleratedCVE checks if a CVE is tolerated for a specific target repository
// Returns true if the CVE is tolerated and not expired
func (c *Config) IsToleratedCVE(target, cveID string) (bool, *CVEToleration) {
	tolerations := c.GetTolerationsForTarget(target)
	now := time.Now()

	for i := range tolerations {
		toleration := &tolerations[i]
		if toleration.ID == cveID {
			// Check if toleration has expired
			if toleration.ExpiresAt != nil && toleration.ExpiresAt.Before(now) {
				return false, nil
			}
			return true, toleration
		}
	}

	return false, nil
}

// GetExpiringTolerations returns tolerations that will expire within the specified duration
func (c *Config) GetExpiringTolerations(within time.Duration) []CVEToleration {
	var expiring []CVEToleration
	now := time.Now()
	threshold := now.Add(within)

	for _, sync := range c.Sync {
		for _, toleration := range sync.Tolerate {
			if toleration.ExpiresAt != nil {
				if toleration.ExpiresAt.After(now) && toleration.ExpiresAt.Before(threshold) {
					expiring = append(expiring, toleration)
				}
			}
		}
	}

	return expiring
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

// GetRescanInterval returns the rescan interval for a specific target repository
// Returns the sync entry's interval if specified, otherwise the default, otherwise 7d
func (c *Config) GetRescanInterval(target string) (time.Duration, error) {
	// Check sync entry first
	for _, sync := range c.Sync {
		if sync.Target == target && sync.RescanInterval != "" {
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

// GetSCAIValidityExtension returns the SCAI validity extension for a specific target repository
// This is the additional time beyond the next scheduled scan that the SCAI attestation remains valid
// Returns the sync entry's extension if specified, otherwise the default, otherwise 1d
func (c *Config) GetSCAIValidityExtension(target string) (time.Duration, error) {
	// Check sync entry first
	for _, sync := range c.Sync {
		if sync.Target == target && sync.SCAIValidityExtension != "" {
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
