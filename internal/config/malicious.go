package config

import (
	"fmt"
	"strings"
	"time"
)

// Defaults for malicious-packages.
const (
	DefaultMaliciousRepoURL      = "https://github.com/ossf/malicious-packages.git"
	DefaultMaliciousRepoRef      = "main"
	DefaultMaliciousCheckoutDir  = "/data/malicious-packages"
	DefaultMaliciousSyncInterval = time.Hour
	DefaultMaliciousStaleAfter   = 6 * time.Hour
)

// MaliciousPackagesConfig is the malicious-packages block. It is read at
// startup only. A missing block means enabled with every default.
type MaliciousPackagesConfig struct {
	Enabled      *bool             `yaml:"enabled,omitempty"`
	Block        *bool             `yaml:"block,omitempty"`
	Repo         MaliciousRepoConf `yaml:"repo,omitempty"`
	CheckoutDir  string            `yaml:"checkout_dir,omitempty"`
	SyncInterval string            `yaml:"sync_interval,omitempty"`
	StaleAfter   string            `yaml:"stale_after,omitempty"`
	Ecosystems   []string          `yaml:"ecosystems,omitempty"`
}

// MaliciousRepoConf points at ossf/malicious-packages or a mirror of it.
// Auth is optional; an empty auth type is anonymous.
type MaliciousRepoConf struct {
	URL  string        `yaml:"url,omitempty"`
	Ref  string        `yaml:"ref,omitempty"`
	Auth GitAuthConfig `yaml:"auth,omitempty"`
}

// IsEnabled reports whether malicious-package detection runs. Unset means yes.
func (m *MaliciousPackagesConfig) IsEnabled() bool {
	return m == nil || m.Enabled == nil || *m.Enabled
}

// BlockEnabled reports whether a malicious finding fails policy regardless of
// the policy expression. Unset means yes.
func (m *MaliciousPackagesConfig) BlockEnabled() bool {
	return m == nil || m.Block == nil || *m.Block
}

// RepoURL returns the configured repository URL or the upstream default.
func (m *MaliciousPackagesConfig) RepoURL() string {
	if m == nil || strings.TrimSpace(m.Repo.URL) == "" {
		return DefaultMaliciousRepoURL
	}
	return strings.TrimSpace(m.Repo.URL)
}

// RepoRef returns the configured branch or main.
func (m *MaliciousPackagesConfig) RepoRef() string {
	if m == nil || strings.TrimSpace(m.Repo.Ref) == "" {
		return DefaultMaliciousRepoRef
	}
	return strings.TrimSpace(m.Repo.Ref)
}

// RepoAuth returns the configured git auth; the zero value is anonymous.
func (m *MaliciousPackagesConfig) RepoAuth() GitAuthConfig {
	if m == nil {
		return GitAuthConfig{}
	}
	return m.Repo.Auth
}

// Dir returns where the clone is kept.
func (m *MaliciousPackagesConfig) Dir() string {
	if m == nil || strings.TrimSpace(m.CheckoutDir) == "" {
		return DefaultMaliciousCheckoutDir
	}
	return strings.TrimSpace(m.CheckoutDir)
}

// Interval returns how often the repository is fetched.
func (m *MaliciousPackagesConfig) Interval() time.Duration {
	if m == nil {
		return DefaultMaliciousSyncInterval
	}
	return durationOr(m.SyncInterval, DefaultMaliciousSyncInterval)
}

// Staleness returns how old the data may get before scans report it as stale.
func (m *MaliciousPackagesConfig) Staleness() time.Duration {
	if m == nil {
		return DefaultMaliciousStaleAfter
	}
	return durationOr(m.StaleAfter, DefaultMaliciousStaleAfter)
}

// EcosystemList returns the configured OSV ecosystems; nil means all supported.
func (m *MaliciousPackagesConfig) EcosystemList() []string {
	if m == nil {
		return nil
	}
	return m.Ecosystems
}

func durationOr(value string, fallback time.Duration) time.Duration {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	parsed, err := ParseFlexibleDuration(value)
	if err != nil || parsed <= 0 {
		return fallback
	}
	return parsed
}

// Validate reports configuration errors. Ecosystem names are checked when
// the service starts, against the matcher's own list.
func (m *MaliciousPackagesConfig) Validate() error {
	if m == nil || !m.IsEnabled() {
		return nil
	}
	if m.Repo.Auth.Type != "" {
		if err := validateGitAuth("malicious-packages.repo", m.RepoURL(), m.Repo.Auth); err != nil {
			return err
		}
	}
	for _, field := range []struct{ name, value string }{
		{"sync_interval", m.SyncInterval},
		{"stale_after", m.StaleAfter},
	} {
		if strings.TrimSpace(field.value) == "" {
			continue
		}
		parsed, err := ParseFlexibleDuration(field.value)
		if err != nil {
			return fmt.Errorf("malicious-packages.%s: %w", field.name, err)
		}
		if parsed <= 0 {
			return fmt.Errorf("malicious-packages.%s must be positive", field.name)
		}
	}
	if m.Staleness() < m.Interval() {
		return fmt.Errorf("malicious-packages.stale_after must be at least sync_interval")
	}
	return nil
}
