package catalog

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/daimoniac/suppline/internal/config"
	"github.com/daimoniac/suppline/internal/policy"
	"github.com/daimoniac/suppline/internal/types"
)

// ConfigCatalog adapts parsed suppline YAML configuration to Catalog.
type ConfigCatalog struct {
	config *config.RegsyncConfig
}

// NewConfigCatalog creates a production catalog over parsed configuration.
func NewConfigCatalog(cfg *config.RegsyncConfig) *ConfigCatalog {
	return &ConfigCatalog{config: cfg}
}

func (c *ConfigCatalog) ResolvePolicy(repository string) (policy.PolicyConfig, error) {
	configured, _ := c.effective(repository)
	if configured == nil {
		return policy.PolicyConfig{}, nil
	}

	resolved := policy.PolicyConfig{
		Expression:     configured.Expression,
		FailureMessage: configured.FailureMessage,
	}
	if configured.MinimumReleaseAge == "" {
		return resolved, nil
	}

	minimumReleaseAge, err := parseInterval(configured.MinimumReleaseAge)
	if err != nil {
		return policy.PolicyConfig{}, fmt.Errorf("invalid minimumReleaseAge for target %s: %w", repository, err)
	}
	resolved.MinimumReleaseAge = minimumReleaseAge
	return resolved, nil
}

func (c *ConfigCatalog) ResolveExpression(repository string) string {
	configured, _ := c.effective(repository)
	if configured == nil {
		return ""
	}
	return configured.Expression
}

func (c *ConfigCatalog) ResolveEvidence(repository string) Evidence {
	_, evidence := c.effective(repository)
	return evidence
}

// effective merges defaults with the repository's sync entries. The policy is
// returned unparsed so that evidence lookups stay independent of policy syntax.
func (c *ConfigCatalog) effective(repository string) (*config.PolicyConfig, Evidence) {
	if c == nil || c.config == nil {
		return nil, Evidence{}
	}

	configured := c.config.Defaults.Policy
	var evidence Evidence
	if c.config.Defaults.VEXRepo != nil {
		evidence.UseVEXRepo = *c.config.Defaults.VEXRepo
	}

	seen := make(map[string]struct{})
	for _, statement := range c.config.Defaults.VEX {
		if _, exists := seen[statement.ID]; exists {
			continue
		}
		seen[statement.ID] = struct{}{}
		evidence.VEXStatements = append(evidence.VEXStatements, statement)
	}

	policyOverridden := false
	vexRepoOverridden := false
	for _, sync := range c.config.Sync {
		if targetRepository(sync) != repository {
			continue
		}
		if sync.Policy != nil && !policyOverridden {
			configured = sync.Policy
			policyOverridden = true
		}
		if sync.VEXRepo != nil && !vexRepoOverridden {
			evidence.UseVEXRepo = *sync.VEXRepo
			vexRepoOverridden = true
		}
		for _, statement := range sync.VEX {
			if _, exists := seen[statement.ID]; exists {
				continue
			}
			seen[statement.ID] = struct{}{}
			evidence.VEXStatements = append(evidence.VEXStatements, statement)
		}
	}

	return configured, evidence
}

func (c *ConfigCatalog) Repositories() []string {
	if c == nil || c.config == nil {
		return nil
	}
	return append([]string(nil), c.config.GetTargetRepositories()...)
}

func (c *ConfigCatalog) ListPolicies() PolicyListing {
	listing := PolicyListing{}
	if c == nil || c.config == nil {
		return listing
	}

	if cfg := c.config.Defaults.Policy; cfg != nil && cfg.Expression != "" {
		defaultPolicy := policy.PolicyConfig{
			Expression:     cfg.Expression,
			FailureMessage: cfg.FailureMessage,
		}
		listing.Default = &defaultPolicy
	}

	for _, sync := range c.config.Sync {
		if sync.Policy == nil || sync.Policy.Expression == "" {
			continue
		}
		repository := targetRepository(sync)
		if repository == "" {
			continue
		}
		if listing.Overrides == nil {
			listing.Overrides = make(map[string]policy.PolicyConfig)
		}
		listing.Overrides[repository] = policy.PolicyConfig{
			Expression:     sync.Policy.Expression,
			FailureMessage: sync.Policy.FailureMessage,
		}
	}
	return clonePolicyListing(listing)
}

func (c *ConfigCatalog) IsExempted(repository, statementID string, at time.Time) (bool, *types.VEXStatement) {
	return findExemption(c.ResolveEvidence(repository).VEXStatements, statementID, at)
}

func (c *ConfigCatalog) StatementIDs() []string {
	if c == nil || c.config == nil {
		return nil
	}
	ids := make(map[string]struct{})
	for _, statement := range c.config.Defaults.VEX {
		ids[statement.ID] = struct{}{}
	}
	for _, sync := range c.config.Sync {
		for _, statement := range sync.VEX {
			ids[statement.ID] = struct{}{}
		}
	}
	return sortedKeys(ids)
}

func (c *ConfigCatalog) UsesVEXRepo() bool {
	if c == nil || c.config == nil {
		return false
	}
	if c.config.Defaults.VEXRepo != nil && *c.config.Defaults.VEXRepo {
		return true
	}
	for _, sync := range c.config.Sync {
		if sync.VEXRepo != nil && *sync.VEXRepo {
			return true
		}
	}
	return false
}

func parseInterval(value string) (time.Duration, error) {
	if strings.HasSuffix(value, "d") {
		days := strings.TrimSuffix(value, "d")
		var count int
		if _, err := fmt.Sscanf(days, "%d", &count); err != nil {
			return 0, fmt.Errorf("invalid duration format: %s", value)
		}
		return time.Duration(count) * 24 * time.Hour, nil
	}
	return time.ParseDuration(value)
}

func targetRepository(sync config.SyncEntry) string {
	target := sync.Target
	if sync.Type == "image" {
		if index := strings.LastIndex(target, ":"); index != -1 {
			target = target[:index]
		}
	}
	return target
}

func sortedKeys(values map[string]struct{}) []string {
	result := make([]string, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}
