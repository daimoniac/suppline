package api

import (
	"net/http"

	"github.com/daimoniac/suppline/internal/policy"
)

// PolicyInfo is a CEL policy expression with a human-readable description.
type PolicyInfo struct {
	Expression  string `json:"Expression"`
	Description string `json:"Description"`
}

// PoliciesResponse is the payload for GET /api/v1/policies.
type PoliciesResponse struct {
	// Default is defaults.policy, or the built-in default policy when none is configured.
	Default *PolicyInfo `json:"Default,omitempty"`
	// Repositories maps sync targets that have their own policy override.
	Repositories map[string]PolicyInfo `json:"Repositories,omitempty"`
}

// handleListPolicies returns the default CEL policy (configured or built-in) and per-target overrides.
// @Summary List configured policies
// @Description Return the default policy and per-repository policy overrides from suppline.yml. Without defaults.policy the default is the built-in policy (no critical, and no known-exploited high, vulnerabilities).
// @Tags Policies
// @Produce json
// @Success 200 {object} PoliciesResponse
// @Failure 401 {object} map[string]string "Unauthorized"
// @Security BearerAuth
// @Router /policies [get]
func (s *APIServer) handleListPolicies(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	s.respondJSON(w, http.StatusOK, s.buildPoliciesResponse())
}

func (s *APIServer) buildPoliciesResponse() PoliciesResponse {
	resp := PoliciesResponse{}
	if s.policyCatalog == nil {
		return resp
	}

	listing := s.policyCatalog.ListPolicies()
	if listing.Default != nil && listing.Default.Expression != "" {
		expr := listing.Default.Expression
		resp.Default = &PolicyInfo{
			Expression:  expr,
			Description: policy.DescribeExpression(expr),
		}
	}

	overrides := make(map[string]PolicyInfo)
	for repository, configuredPolicy := range listing.Overrides {
		overrides[repository] = PolicyInfo{
			Expression:  configuredPolicy.Expression,
			Description: policy.DescribeExpression(configuredPolicy.Expression),
		}
	}
	if len(overrides) > 0 {
		resp.Repositories = overrides
	}
	return resp
}

// enrichRepositoryPolicy attaches the resolved CEL policy description for a repository.
func (s *APIServer) enrichRepositoryPolicy(name string) (expression, description string) {
	if s.policyCatalog == nil || name == "" {
		return "", ""
	}
	expr := s.policyCatalog.ResolveExpression(name)
	if expr == "" {
		return "", ""
	}
	return expr, policy.DescribeExpression(expr)
}
