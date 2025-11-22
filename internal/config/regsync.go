package config

import (
	"bytes"
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

	// Expand environment variables in credentials
	if err := expandCredentials(&config); err != nil {
		return nil, errors.NewPermanentf("failed to expand credentials: %w", err)
	}

	return &config, nil
}

// expandCredentials processes credential fields and expands Go template expressions
// Supports {{ env "VAR_NAME" }} syntax for environment variable expansion
func expandCredentials(config *RegsyncConfig) error {
	funcMap := template.FuncMap{
		"env": os.Getenv,
	}

	for i := range config.Creds {
		cred := &config.Creds[i]

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

// GetTolerationsForTarget returns CVE tolerations for a specific target repository
// Handles both type=repository (exact match) and type=image (strips tag for matching)
func (c *RegsyncConfig) GetTolerationsForTarget(target string) []types.CVEToleration {
	var allTolerations []types.CVEToleration
	
	for _, sync := range c.Sync {
		syncTarget := sync.Target
		
		// For type=image, strip the tag for comparison
		if sync.Type == "image" {
			if idx := strings.LastIndex(syncTarget, ":"); idx != -1 {
				syncTarget = syncTarget[:idx]
			}
		}
		
		if syncTarget == target {
			allTolerations = append(allTolerations, sync.Tolerate...)
		}
	}
	
	return allTolerations
}

// GetTargetRepositories returns all target repositories from sync entries
// For type=image entries, strips the tag to return just the repository name
func (c *RegsyncConfig) GetTargetRepositories() []string {
	seen := make(map[string]bool)
	targets := make([]string, 0, len(c.Sync))
	
	for _, sync := range c.Sync {
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

// IsToleratedCVE checks if a CVE is tolerated for a specific target repository
// Returns true if the CVE is tolerated and not expired
func (c *RegsyncConfig) IsToleratedCVE(target, cveID string) (bool, *types.CVEToleration) {
	tolerations := c.GetTolerationsForTarget(target)
	nowUnix := time.Now().Unix()

	for i := range tolerations {
		toleration := &tolerations[i]
		if toleration.ID == cveID {
			// Check if toleration has expired
			if toleration.ExpiresAt != nil && *toleration.ExpiresAt < nowUnix {
				return false, nil
			}
			return true, toleration
		}
	}

	return false, nil
}

// GetExpiringTolerations returns tolerations that will expire within the specified duration
func (c *RegsyncConfig) GetExpiringTolerations(within time.Duration) []types.CVEToleration {
	var expiring []types.CVEToleration
	nowUnix := time.Now().Unix()
	thresholdUnix := time.Now().Add(within).Unix()

	for _, sync := range c.Sync {
		for _, toleration := range sync.Tolerate {
			if toleration.ExpiresAt != nil {
				if *toleration.ExpiresAt > nowUnix && *toleration.ExpiresAt < thresholdUnix {
					expiring = append(expiring, toleration)
				}
			}
		}
	}

	return expiring
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

// GetWorkerPollInterval returns the worker poll interval from defaults
// Returns the default if specified, otherwise 5 seconds
func (c *RegsyncConfig) GetWorkerPollInterval() (time.Duration, error) {
	if c.Defaults.WorkerPollInterval != "" {
		return parseInterval(c.Defaults.WorkerPollInterval)
	}

	// Fall back to hardcoded default
	return 5 * time.Second, nil
}
