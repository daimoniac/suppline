package api

import (
	"net/http"
	"strings"

	"github.com/daimoniac/suppline/internal/config"
	"github.com/daimoniac/suppline/internal/policy"
)

// PolicyInfo is a CEL policy expression with a human-readable description.
type PolicyInfo struct {
	Expression  string `json:"Expression"`
	Description string `json:"Description"`
}

// PoliciesResponse is the payload for GET /api/v1/policies.
type PoliciesResponse struct {
	// Default is set only when defaults.x-policy is configured.
	Default *PolicyInfo `json:"Default,omitempty"`
	// Repositories maps sync targets that have their own x-policy override.
	Repositories map[string]PolicyInfo `json:"Repositories,omitempty"`
}

// handleListPolicies returns configured CEL policies (default + per-target overrides).
// @Summary List configured policies
// @Description Return the default x-policy (if set) and per-repository policy overrides from suppline.yml
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
	if s.regsyncConfig == nil {
		return resp
	}

	if s.regsyncConfig.Defaults.Policy != nil && s.regsyncConfig.Defaults.Policy.Expression != "" {
		expr := s.regsyncConfig.Defaults.Policy.Expression
		resp.Default = &PolicyInfo{
			Expression:  expr,
			Description: policy.DescribeExpression(expr),
		}
	}

	overrides := make(map[string]PolicyInfo)
	for _, sync := range s.regsyncConfig.Sync {
		if sync.Policy == nil || sync.Policy.Expression == "" {
			continue
		}
		target := syncTargetRepository(sync)
		if target == "" {
			continue
		}
		overrides[target] = PolicyInfo{
			Expression:  sync.Policy.Expression,
			Description: policy.DescribeExpression(sync.Policy.Expression),
		}
	}
	if len(overrides) > 0 {
		resp.Repositories = overrides
	}
	return resp
}

func syncTargetRepository(sync config.SyncEntry) string {
	target := sync.Target
	if sync.Type == "image" {
		if idx := strings.LastIndex(target, ":"); idx != -1 {
			target = target[:idx]
		}
	}
	return target
}

// enrichRepositoryPolicy attaches the resolved CEL policy description for a repository.
func (s *APIServer) enrichRepositoryPolicy(name string) (expression, description string) {
	if s.regsyncConfig == nil || name == "" {
		return "", ""
	}
	cfg := s.regsyncConfig.GetPolicyForTarget(name)
	if cfg == nil || cfg.Expression == "" {
		return "", ""
	}
	return cfg.Expression, policy.DescribeExpression(cfg.Expression)
}
