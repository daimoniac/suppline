package catalog

import (
	"fmt"
	"sort"
	"strconv"
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

// Replace swaps in a newly parsed configuration. It returns the repositories
// whose policy or VEX decision changed, so the caller can rescan those images.
// A repository that was added or removed is included. Identical decisions are not.
func (c *ConfigCatalog) Replace(next *config.RegsyncConfig) []string {
	if c == nil || next == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	before := c.decisionFingerprintsLocked()
	c.config = next
	return changedRepositories(before, c.decisionFingerprintsLocked())
}

func (c *ConfigCatalog) decisionFingerprintsLocked() map[string]string {
	out := map[string]string{}
	if c == nil || c.config == nil {
		return out
	}
	for _, repository := range c.config.GetTargetRepositories() {
		policy, evidence := c.effectiveLocked(repository)
		out[repository] = fingerprintDecision(policy, evidence)
	}
	return out
}

func fingerprintDecision(policy *config.PolicyConfig, evidence Evidence) string {
	var b strings.Builder
	if policy != nil {
		fmt.Fprintf(&b, "%s\n%s\n%s\n", policy.Expression, policy.FailureMessage, policy.MinimumReleaseAge)
	}
	fmt.Fprintf(&b, "vexrepo=%t\n", evidence.UseVEXRepo)
	for _, statement := range evidence.VEXStatements {
		expires := ""
		if statement.ExpiresAt != nil {
			expires = strconv.FormatInt(*statement.ExpiresAt, 10)
		}
		fmt.Fprintf(&b, "%s\t%s\t%s\t%s\t%s\n", statement.ID, statement.State, statement.Justification, expires, statement.Detail)
	}
	return b.String()
}

func changedRepositories(before, after map[string]string) []string {
	seen := map[string]struct{}{}
	for repository := range before {
		seen[repository] = struct{}{}
	}
	for repository := range after {
		seen[repository] = struct{}{}
	}
	changed := make([]string, 0)
	for repository := range seen {
		if before[repository] != after[repository] {
			changed = append(changed, repository)
		}
	}
	sort.Strings(changed)
	return changed
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
	_ = c.config.ForEachActive(func(i int) error {
		sync := c.config.Sync[i]
		if targetRepository(sync) != repository {
			return nil
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
		return nil
	})

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
	_ = c.config.ForEachActive(func(i int) error {
		if targetRepository(c.config.Sync[i]) != repository {
			return nil
		}
		matched = true
		c.config.Sync[i].VEXAuto = append([]types.VEXStatement(nil), copied...)
		return nil
	})
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
	_ = c.config.ForEachActive(func(i int) error {
		if targetRepository(c.config.Sync[i]) != repository {
			return nil
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
		return nil
	})
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
	_ = c.config.ForEachActive(func(i int) error {
		sync := c.config.Sync[i]
		if targetRepository(sync) != repository {
			return nil
		}
		for _, statement := range sync.VEXAuto {
			if _, exists := seen[statement.ID]; exists {
				continue
			}
			seen[statement.ID] = struct{}{}
			statement.Source = types.VEXSourceAuto
			out = append(out, statement)
		}
		return nil
	})
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

	_ = c.config.ForEachActive(func(i int) error {
		sync := c.config.Sync[i]
		if sync.Policy == nil || sync.Policy.Expression == "" {
			return nil
		}
		repository := targetRepository(sync)
		if repository == "" {
			return nil
		}
		if listing.Overrides == nil {
			listing.Overrides = make(map[string]policy.PolicyConfig)
		}
		listing.Overrides[repository] = policy.PolicyConfig{
			Expression:     sync.Policy.Expression,
			FailureMessage: sync.Policy.FailureMessage,
		}
		return nil
	})
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
	_ = c.config.ForEachActive(func(i int) error {
		sync := c.config.Sync[i]
		for _, statement := range sync.VEX {
			ids[statement.ID] = struct{}{}
		}
		for _, statement := range sync.VEXAuto {
			ids[statement.ID] = struct{}{}
		}
		return nil
	})
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
	uses := false
	_ = c.config.ForEachActive(func(i int) error {
		sync := c.config.Sync[i]
		if sync.VEXRepo != nil && *sync.VEXRepo {
			uses = true
		}
		return nil
	})
	return uses
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
	_ = c.config.ForEachActive(func(i int) error {
		sync := c.config.Sync[i]
		if ok || targetRepository(sync) != repository {
			return nil
		}
		if strings.TrimSpace(sync.Source) == "" {
			return nil
		}
		source = strings.TrimSpace(sync.Source)
		platform = strings.TrimSpace(sync.Platform)
		ok = true
		return nil
	})
	return source, platform, ok
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
	err := c.config.ForEachActive(func(i int) error {
		ok, err := config.SyncTargetMatches(c.config.Sync[i].Target, c.config.Sync[i].Type, target)
		if err != nil {
			return err
		}
		if !ok || c.config.Sync[i].Tags == nil {
			return nil
		}
		c.config.Sync[i].Tags.SemverRange = append([]string(nil), copied...)
		updated++
		return nil
	})
	if err != nil {
		return 0, err
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
	return c.config.KeepActive(func(entry config.SyncEntry) (bool, error) {
		for _, target := range targets {
			ok, err := config.SyncTargetMatches(entry.Target, entry.Type, target)
			if err != nil {
				return false, err
			}
			if ok {
				return false, nil
			}
		}
		return true, nil
	})
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
	_ = c.config.ForEachActive(func(i int) error {
		var n int
		c.config.Sync[i].VEX, n = dropVEXIDs(c.config.Sync[i].VEX, wanted, 0)
		removed += n
		c.config.Sync[i].VEXAuto, n = dropVEXIDs(c.config.Sync[i].VEXAuto, wanted, 0)
		removed += n
		return nil
	})
	return removed, nil
}

// SyncVEX returns the statements written on the sync entries for repository,
// without defaults. Source is the key each statement is stored under. An id is
// left out when defaults also define it or when more than one entry stores it:
// the effective statement is then not one copy the entry alone decides, so it
// cannot be judged or removed one copy at a time.
func (c *ConfigCatalog) SyncVEX(repository string) []types.VEXStatement {
	if c == nil || c.config == nil {
		return nil
	}
	c.mu.RLock()
	defer c.mu.RUnlock()

	defaults := make(map[string]struct{}, len(c.config.Defaults.VEX))
	for _, statement := range c.config.Defaults.VEX {
		defaults[statement.ID] = struct{}{}
	}
	var all []types.VEXStatement
	_ = c.config.ForEachActive(func(i int) error {
		sync := c.config.Sync[i]
		if targetRepository(sync) != repository {
			return nil
		}
		for _, statement := range sync.VEX {
			statement.Source = types.VEXSourceManual
			all = append(all, statement)
		}
		for _, statement := range sync.VEXAuto {
			statement.Source = types.VEXSourceAuto
			all = append(all, statement)
		}
		return nil
	})

	counts := make(map[string]int, len(all))
	for _, statement := range all {
		counts[statement.ID]++
	}
	out := make([]types.VEXStatement, 0, len(all))
	for _, statement := range all {
		if counts[statement.ID] > 1 {
			continue
		}
		if _, shadowed := defaults[statement.ID]; shadowed {
			continue
		}
		out = append(out, statement)
	}
	return out
}

// EntryVEXRef names one statement stored on the sync entries of a repository.
// Source is types.VEXSourceManual or types.VEXSourceAuto.
type EntryVEXRef struct {
	Repository string
	ID         string
	Source     string
}

// RemoveEntryVEX drops the referenced statements from the sync entries of their
// repositories. Each ref only removes the copy stored under its own source
// key. defaults and other repositories are not changed.
func (c *ConfigCatalog) RemoveEntryVEX(refs []EntryVEXRef) (int, error) {
	if c == nil || c.config == nil {
		return 0, fmt.Errorf("no configuration catalog")
	}
	wanted := make(map[string]map[string]map[string]struct{})
	for _, ref := range refs {
		id := strings.TrimSpace(ref.ID)
		if id == "" || strings.TrimSpace(ref.Repository) == "" {
			continue
		}
		if wanted[ref.Repository] == nil {
			wanted[ref.Repository] = make(map[string]map[string]struct{})
		}
		if wanted[ref.Repository][ref.Source] == nil {
			wanted[ref.Repository][ref.Source] = make(map[string]struct{})
		}
		wanted[ref.Repository][ref.Source][id] = struct{}{}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	removed := 0
	_ = c.config.ForEachActive(func(i int) error {
		byRepo, ok := wanted[targetRepository(c.config.Sync[i])]
		if !ok {
			return nil
		}
		var n int
		c.config.Sync[i].VEX, n = dropVEXIDs(c.config.Sync[i].VEX, byRepo[types.VEXSourceManual], 0)
		removed += n
		c.config.Sync[i].VEXAuto, n = dropVEXIDs(c.config.Sync[i].VEXAuto, byRepo[types.VEXSourceAuto], 0)
		removed += n
		return nil
	})
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
