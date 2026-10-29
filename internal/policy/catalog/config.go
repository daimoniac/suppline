package catalog

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/daimoniac/suppline/internal/config"
	"github.com/daimoniac/suppline/internal/policy"
	"github.com/daimoniac/suppline/internal/types"
)

// ConfigCatalog adapts parsed suppline YAML configuration to Catalog.
// Auto-VEX hot-swap is safe for concurrent readers.
type ConfigCatalog struct {
	mu     sync.RWMutex
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
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.effectiveLocked(repository)
}

func (c *ConfigCatalog) effectiveLocked(repository string) (*config.PolicyConfig, Evidence) {

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
		statement.Source = types.VEXSourceManual
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
			statement.Source = types.VEXSourceManual
			evidence.VEXStatements = append(evidence.VEXStatements, statement)
		}
		for _, statement := range sync.VEXAuto {
			if _, exists := seen[statement.ID]; exists {
				continue
			}
			seen[statement.ID] = struct{}{}
			statement.Source = types.VEXSourceAuto
			evidence.VEXStatements = append(evidence.VEXStatements, statement)
		}
	}

	return configured, evidence
}

// ReplaceAutoVEX replaces x-vex-auto on every sync entry for repository.
// Hand-written x-vex statements are left untouched. x-vex wins on the same id
// at read time, so an auto statement with a duplicate id stays stored but is
// not effective.
func (c *ConfigCatalog) ReplaceAutoVEX(repository string, statements []types.VEXStatement) error {
	if c == nil || c.config == nil {
		return fmt.Errorf("no configuration catalog")
	}
	copied := make([]types.VEXStatement, len(statements))
	for i, statement := range statements {
		statement.Source = types.VEXSourceAuto
		copied[i] = statement
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	matched := false
	for i := range c.config.Sync {
		if targetRepository(c.config.Sync[i]) != repository {
			continue
		}
		matched = true
		c.config.Sync[i].VEXAuto = append([]types.VEXStatement(nil), copied...)
	}
	if !matched {
		return fmt.Errorf("no sync entry for repository %s", repository)
	}
	return nil
}

// UpsertManualVEX inserts or replaces one hand-written x-vex statement on every
// sync entry for repository. x-vex-auto is left untouched. The manual statement
// wins over an auto statement with the same id.
func (c *ConfigCatalog) UpsertManualVEX(repository string, statement types.VEXStatement) error {
	if c == nil || c.config == nil {
		return fmt.Errorf("no configuration catalog")
	}
	statement.Source = types.VEXSourceManual
	c.mu.Lock()
	defer c.mu.Unlock()
	matched := false
	for i := range c.config.Sync {
		if targetRepository(c.config.Sync[i]) != repository {
			continue
		}
		matched = true
		replaced := false
		for j := range c.config.Sync[i].VEX {
			if c.config.Sync[i].VEX[j].ID == statement.ID {
				c.config.Sync[i].VEX[j] = statement
				replaced = true
				break
			}
		}
		if !replaced {
			c.config.Sync[i].VEX = append(c.config.Sync[i].VEX, statement)
		}
	}
	if !matched {
		return fmt.Errorf("no sync entry for repository %s", repository)
	}
	return nil
}

// AutoVEX returns the triage-owned statements stored for a repository.
func (c *ConfigCatalog) AutoVEX(repository string) []types.VEXStatement {
	if c == nil || c.config == nil {
		return nil
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	var out []types.VEXStatement
	seen := make(map[string]struct{})
	for _, sync := range c.config.Sync {
		if targetRepository(sync) != repository {
			continue
		}
		for _, statement := range sync.VEXAuto {
			if _, exists := seen[statement.ID]; exists {
				continue
			}
			seen[statement.ID] = struct{}{}
			statement.Source = types.VEXSourceAuto
			out = append(out, statement)
		}
	}
	return out
}

func (c *ConfigCatalog) Repositories() []string {
	if c == nil || c.config == nil {
		return nil
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return append([]string(nil), c.config.GetTargetRepositories()...)
}

func (c *ConfigCatalog) ListPolicies() PolicyListing {
	listing := PolicyListing{}
	if c == nil || c.config == nil {
		return listing
	}
	c.mu.RLock()
	defer c.mu.RUnlock()

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
	c.mu.RLock()
	defer c.mu.RUnlock()
	ids := make(map[string]struct{})
	for _, statement := range c.config.Defaults.VEX {
		ids[statement.ID] = struct{}{}
	}
	for _, sync := range c.config.Sync {
		for _, statement := range sync.VEX {
			ids[statement.ID] = struct{}{}
		}
		for _, statement := range sync.VEXAuto {
			ids[statement.ID] = struct{}{}
		}
	}
	return sortedKeys(ids)
}

func (c *ConfigCatalog) UsesVEXRepo() bool {
	if c == nil || c.config == nil {
		return false
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
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

// Upstream returns the catalog source image and platform for a mirrored repository.
func (c *ConfigCatalog) Upstream(repository string) (source, platform string, ok bool) {
	if c == nil || c.config == nil {
		return "", "", false
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	for _, sync := range c.config.Sync {
		if targetRepository(sync) != repository {
			continue
		}
		if strings.TrimSpace(sync.Source) == "" {
			continue
		}
		return strings.TrimSpace(sync.Source), strings.TrimSpace(sync.Platform), true
	}
	return "", "", false
}

// SetSemverRanges replaces tags.semverRange on sync entries that match target.
func (c *ConfigCatalog) SetSemverRanges(target string, ranges []string) (int, error) {
	if c == nil || c.config == nil {
		return 0, fmt.Errorf("no configuration catalog")
	}
	if strings.TrimSpace(target) == "" || len(ranges) == 0 {
		return 0, fmt.Errorf("semver update needs a target and at least one range")
	}
	copied := append([]string(nil), ranges...)
	c.mu.Lock()
	defer c.mu.Unlock()
	updated := 0
	for i := range c.config.Sync {
		ok, err := config.SyncTargetMatches(c.config.Sync[i].Target, c.config.Sync[i].Type, target)
		if err != nil {
			return 0, err
		}
		if !ok || c.config.Sync[i].Tags == nil {
			continue
		}
		c.config.Sync[i].Tags.SemverRange = append([]string(nil), copied...)
		updated++
	}
	return updated, nil
}

// RemoveSyncTargets drops sync entries whose target matches one of targets.
func (c *ConfigCatalog) RemoveSyncTargets(targets []string) (int, error) {
	if c == nil || c.config == nil {
		return 0, fmt.Errorf("no configuration catalog")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	next := make([]config.SyncEntry, 0, len(c.config.Sync))
	removed := 0
	for _, entry := range c.config.Sync {
		drop := false
		for _, target := range targets {
			ok, err := config.SyncTargetMatches(entry.Target, entry.Type, target)
			if err != nil {
				return 0, err
			}
			if ok {
				drop = true
				break
			}
		}
		if drop {
			removed++
			continue
		}
		next = append(next, entry)
	}
	c.config.Sync = next
	return removed, nil
}

// RemoveVEXIDs drops hand-written and auto statements with these ids.
func (c *ConfigCatalog) RemoveVEXIDs(ids []string) (int, error) {
	if c == nil || c.config == nil {
		return 0, fmt.Errorf("no configuration catalog")
	}
	wanted := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		wanted[id] = struct{}{}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	removed := 0
	c.config.Defaults.VEX, removed = dropVEXIDs(c.config.Defaults.VEX, wanted, removed)
	for i := range c.config.Sync {
		var n int
		c.config.Sync[i].VEX, n = dropVEXIDs(c.config.Sync[i].VEX, wanted, 0)
		removed += n
		c.config.Sync[i].VEXAuto, n = dropVEXIDs(c.config.Sync[i].VEXAuto, wanted, 0)
		removed += n
	}
	return removed, nil
}

func dropVEXIDs(list []types.VEXStatement, wanted map[string]struct{}, removed int) ([]types.VEXStatement, int) {
	if len(list) == 0 || len(wanted) == 0 {
		return list, removed
	}
	next := make([]types.VEXStatement, 0, len(list))
	for _, statement := range list {
		if _, ok := wanted[statement.ID]; ok {
			removed++
			continue
		}
		next = append(next, statement)
	}
	return next, removed
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
