package catalog

import (
	"sort"
	"time"

	"github.com/daimoniac/suppline/internal/policy"
	"github.com/daimoniac/suppline/internal/types"
)

// MemoryEntry is the effective catalog state for one repository.
type MemoryEntry struct {
	Policy   policy.PolicyConfig
	Evidence Evidence

	// PolicyError makes ResolvePolicy fail the way an unparseable
	// minimumReleaseAge does, while the expression and the evidence for this
	// repository stay available.
	PolicyError error

	// PolicyOverride marks repositories that configure their own policy
	// instead of inheriting the default.
	PolicyOverride bool
}

// MemoryCatalog is an in-memory Catalog adapter for tests and local composition.
type MemoryCatalog struct {
	defaults MemoryEntry
	entries  map[string]MemoryEntry
}

// NewMemoryCatalog creates an in-memory catalog. Entries hold effective values;
// defaults apply to repositories without an entry.
func NewMemoryCatalog(defaults MemoryEntry, entries map[string]MemoryEntry) *MemoryCatalog {
	copied := make(map[string]MemoryEntry, len(entries))
	for repository, entry := range entries {
		entry.Evidence = cloneEvidence(entry.Evidence)
		copied[repository] = entry
	}
	defaults.Evidence = cloneEvidence(defaults.Evidence)
	return &MemoryCatalog{defaults: defaults, entries: copied}
}

func (c *MemoryCatalog) ResolvePolicy(repository string) (policy.PolicyConfig, error) {
	entry := c.entry(repository)
	if entry.PolicyError != nil {
		return policy.PolicyConfig{}, entry.PolicyError
	}
	return entry.Policy, nil
}

func (c *MemoryCatalog) ResolveExpression(repository string) string {
	return c.entry(repository).Policy.Expression
}

func (c *MemoryCatalog) ResolveEvidence(repository string) Evidence {
	return cloneEvidence(c.entry(repository).Evidence)
}

func (c *MemoryCatalog) entry(repository string) MemoryEntry {
	if c == nil {
		return MemoryEntry{}
	}
	if entry, exists := c.entries[repository]; exists {
		return entry
	}
	return c.defaults
}

func (c *MemoryCatalog) Repositories() []string {
	if c == nil {
		return nil
	}
	repositories := make([]string, 0, len(c.entries))
	for repository := range c.entries {
		repositories = append(repositories, repository)
	}
	sort.Strings(repositories)
	return repositories
}

func (c *MemoryCatalog) ListPolicies() PolicyListing {
	listing := PolicyListing{}
	if c == nil {
		return listing
	}
	if c.defaults.Policy.Expression != "" {
		defaultPolicy := c.defaults.Policy
		listing.Default = &defaultPolicy
	}
	for repository, entry := range c.entries {
		if !entry.PolicyOverride || entry.Policy.Expression == "" {
			continue
		}
		if listing.Overrides == nil {
			listing.Overrides = make(map[string]policy.PolicyConfig)
		}
		listing.Overrides[repository] = entry.Policy
	}
	return clonePolicyListing(listing)
}

func (c *MemoryCatalog) IsExempted(repository, statementID string, at time.Time) (bool, *types.VEXStatement) {
	return findExemption(c.entry(repository).Evidence.VEXStatements, statementID, at)
}

func (c *MemoryCatalog) StatementIDs() []string {
	if c == nil {
		return nil
	}
	ids := make(map[string]struct{})
	for _, statement := range c.defaults.Evidence.VEXStatements {
		ids[statement.ID] = struct{}{}
	}
	for _, entry := range c.entries {
		for _, statement := range entry.Evidence.VEXStatements {
			ids[statement.ID] = struct{}{}
		}
	}
	return sortedKeys(ids)
}

func (c *MemoryCatalog) UsesVEXRepo() bool {
	if c == nil {
		return false
	}
	if c.defaults.Evidence.UseVEXRepo {
		return true
	}
	for _, entry := range c.entries {
		if entry.Evidence.UseVEXRepo {
			return true
		}
	}
	return false
}

func findExemption(statements []types.VEXStatement, statementID string, at time.Time) (bool, *types.VEXStatement) {
	for index := range statements {
		statement := statements[index]
		if statement.ID != statementID || statement.State != types.VEXStateNotAffected {
			continue
		}
		if statement.ExpiresAt != nil && *statement.ExpiresAt < at.Unix() {
			return false, nil
		}
		return true, &statement
	}
	return false, nil
}

func cloneEvidence(evidence Evidence) Evidence {
	evidence.VEXStatements = append([]types.VEXStatement(nil), evidence.VEXStatements...)
	return evidence
}

func clonePolicyListing(listing PolicyListing) PolicyListing {
	result := PolicyListing{}
	if listing.Default != nil {
		defaultPolicy := *listing.Default
		result.Default = &defaultPolicy
	}
	if len(listing.Overrides) > 0 {
		result.Overrides = make(map[string]policy.PolicyConfig, len(listing.Overrides))
		for repository, configuredPolicy := range listing.Overrides {
			result.Overrides[repository] = configuredPolicy
		}
	}
	return result
}
