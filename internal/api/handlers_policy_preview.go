package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	supplineerrors "github.com/daimoniac/suppline/internal/errors"
	"github.com/daimoniac/suppline/internal/policy"
	"github.com/daimoniac/suppline/internal/vexaudit"
)

// PolicyPreviewRequest is the body of POST /api/v1/policies/preview.
type PolicyPreviewRequest struct {
	// Expression is the CEL expression to try. Empty means the built-in default policy.
	Expression string `json:"expression"`
	// InUseOnly limits the replay to images a cluster runs. It defaults to true.
	InUseOnly *bool `json:"in_use_only,omitempty"`
}

// PolicyPreviewResponse says what a candidate policy would decide.
type PolicyPreviewResponse struct {
	Expression string `json:"Expression"`
	// Description puts the expression into words.
	Description string `json:"Description"`
	InUseOnly   bool   `json:"InUseOnly"`
	vexaudit.PreviewResult
}

// handlePolicyPreview replays the latest scans against a candidate expression.
// @Summary Preview a policy
// @Description Replay the latest scan of every image (by default only the images running in a cluster) against a candidate CEL expression, with each repository's VEX statements applied, and report which images it would fail that the policies in force admit. Nothing is stored and no scan is queued. A malicious-package finding fails an image whatever the expression says, so it is left out of the comparison.
// @Tags Policies
// @Accept json
// @Produce json
// @Param request body PolicyPreviewRequest true "Candidate policy"
// @Success 200 {object} PolicyPreviewResponse
// @Failure 400 {object} map[string]string "Invalid request or expression"
// @Failure 401 {object} map[string]string "Unauthorized"
// @Failure 501 {object} map[string]string "Policy preview is not available"
// @Failure 500 {object} map[string]string "Internal server error"
// @Security BearerAuth
// @Router /policies/preview [post]
func (s *APIServer) handlePolicyPreview(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	if s.vexAudit == nil {
		s.respondError(w, http.StatusNotImplemented, "policy preview is not available")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	var req PolicyPreviewRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.respondError(w, http.StatusBadRequest, "invalid JSON payload")
		return
	}
	inUseOnly := req.InUseOnly == nil || *req.InUseOnly

	expression := strings.TrimSpace(req.Expression)
	if expression == "" {
		expression = policy.DefaultExpression
	}

	result, err := s.vexAudit.Preview(r.Context(), expression, inUseOnly)
	if err != nil {
		// A compile error in the expression is the caller's mistake.
		var permanent *supplineerrors.PermanentError
		if errors.As(err, &permanent) {
			s.respondError(w, http.StatusBadRequest, err.Error())
			return
		}
		s.respondStoreError(w, err, "Failed to preview policy")
		return
	}

	s.respondJSON(w, http.StatusOK, PolicyPreviewResponse{
		Expression:    expression,
		Description:   policy.DescribeExpression(expression),
		InUseOnly:     inUseOnly,
		PreviewResult: *result,
	})
}
