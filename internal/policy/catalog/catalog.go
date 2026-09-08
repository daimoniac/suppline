// Package catalog resolves repository-scoped security policy and exemption evidence.
package catalog

import (
	"time"

	"github.com/daimoniac/suppline/internal/policy"
	"github.com/daimoniac/suppline/internal/types"
)

// Evidence is the effective vulnerability-exemption evidence for one repository.
type Evidence struct {
	VEXStatements []types.VEXStatement
	UseVEXRepo    bool
}

// PolicyListing preserves the distinction between configured policy overrides
// and policies inherited through effective resolution.
type PolicyListing struct {
	Default   *policy.PolicyConfig
	Overrides map[string]policy.PolicyConfig
}

// Catalog is the repository-policy seam used by policy consumers.
//
// Exemption evidence is resolved separately from the CEL policy configuration:
// a repository whose minimumReleaseAge cannot be parsed must fail policy
// evaluation for that repository only, while its VEX statements stay available
// to scan enqueueing, discovery, the API, and metrics.
type Catalog interface {
	// ResolvePolicy returns the effective CEL policy configuration for building
	// a policy engine. It fails only when the effective minimumReleaseAge for
	// the repository cannot be parsed.
	ResolvePolicy(repository string) (policy.PolicyConfig, error)

	// ResolveExpression returns the effective CEL expression for a repository.
	// Reporting a configured expression never depends on unrelated policy
	// fields, so this operation cannot fail.
	ResolveExpression(repository string) string

	// ResolveEvidence returns the effective exemption evidence for a repository.
	ResolveEvidence(repository string) Evidence

	// Repositories lists every configured repository.
	Repositories() []string

	// ListPolicies reports the configured default policy and the repositories
	// that explicitly override it.
	ListPolicies() PolicyListing

	// IsExempted reports whether a statement exempts a finding at a given time.
	IsExempted(repository, statementID string, at time.Time) (bool, *types.VEXStatement)

	// StatementIDs lists every configured statement ID across repositories.
	StatementIDs() []string

	// UsesVEXRepo reports whether any repository enables the VEX repository.
	UsesVEXRepo() bool
}
