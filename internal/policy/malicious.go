package policy

import (
	"fmt"
	"strings"

	"github.com/daimoniac/suppline/internal/scanner"
	"github.com/daimoniac/suppline/internal/types"
)

func maliciousFindingsOf(result *scanner.ScanResult) []types.MaliciousFinding {
	if result == nil || result.Malicious == nil {
		return nil
	}
	return result.Malicious.Findings
}

// splitMalicious separates findings covered by an active false_positive VEX
// statement from the rest. Only false_positive exempts a malicious finding:
// the image does not contain the malicious package, only one with the same
// name and version. It returns the active findings and the exempted ids.
func splitMalicious(findings []types.MaliciousFinding, statements []types.VEXStatement, nowUnix int64) ([]types.MaliciousFinding, []string) {
	if len(findings) == 0 {
		return nil, nil
	}
	falsePositive := make(map[string]bool)
	for _, stmt := range statements {
		if stmt.State != types.VEXStateFalsePositive || !types.IsMaliciousID(stmt.ID) {
			continue
		}
		if stmt.ExpiresAt != nil && *stmt.ExpiresAt < nowUnix {
			continue
		}
		falsePositive[stmt.ID] = true
	}
	var active []types.MaliciousFinding
	var exempted []string
	seen := make(map[string]bool)
	for _, finding := range findings {
		if !falsePositive[finding.ID] {
			active = append(active, finding)
			continue
		}
		if !seen[finding.ID] {
			seen[finding.ID] = true
			exempted = append(exempted, finding.ID)
		}
	}
	return active, exempted
}

// MarkExemptedMalicious returns a copy of check whose findings named in
// exemptedIDs are flagged Exempted. It is nil-safe.
func MarkExemptedMalicious(check *types.MaliciousCheck, exemptedIDs []string) *types.MaliciousCheck {
	if check == nil {
		return nil
	}
	exempted := make(map[string]bool, len(exemptedIDs))
	for _, id := range exemptedIDs {
		exempted[id] = true
	}
	out := *check
	out.Findings = make([]types.MaliciousFinding, len(check.Findings))
	for i, finding := range check.Findings {
		finding.Exempted = exempted[finding.ID]
		out.Findings[i] = finding
	}
	if check.Findings == nil {
		out.Findings = nil
	}
	return &out
}

// maliciousCELInput exposes malicious findings to CEL, exempted ones included
// with exempted set, like the vulnerabilities list.
func maliciousCELInput(findings []types.MaliciousFinding, exemptedIDs []string) []map[string]interface{} {
	exempted := make(map[string]bool, len(exemptedIDs))
	for _, id := range exemptedIDs {
		exempted[id] = true
	}
	input := make([]map[string]interface{}, 0, len(findings))
	for _, finding := range findings {
		input = append(input, map[string]interface{}{
			"id":          finding.ID,
			"ecosystem":   finding.Ecosystem,
			"packageName": finding.PackageName,
			"version":     finding.Version,
			"purl":        finding.PURL,
			"summary":     finding.Summary,
			"url":         finding.URL,
			"exempted":    exempted[finding.ID],
		})
	}
	return input
}

func activeMaliciousCount(input []map[string]interface{}) int {
	count := 0
	for _, item := range input {
		if exempted, _ := item["exempted"].(bool); !exempted {
			count++
		}
	}
	return count
}

func maliciousFailureFindings(findings []types.MaliciousFinding) []types.PolicyFailureFinding {
	out := make([]types.PolicyFailureFinding, 0, len(findings))
	seen := make(map[string]bool, len(findings))
	for _, finding := range findings {
		key := finding.ID + "|" + finding.PackageName
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, types.PolicyFailureFinding{
			CVEID:       finding.ID,
			PackageName: finding.PackageName,
			Kind:        types.PolicyFailureKindMalicious,
		})
	}
	return out
}

// passesWithoutMalicious reports whether the expression would pass if the
// image had no active malicious findings, i.e. whether they caused the failure.
func (e *Engine) passesWithoutMalicious(celInput map[string]interface{}) bool {
	counterfactual := make(map[string]interface{}, len(celInput))
	for key, value := range celInput {
		counterfactual[key] = value
	}
	var exemptedOnly []map[string]interface{}
	if items, ok := celInput["malicious"].([]map[string]interface{}); ok {
		for _, item := range items {
			if exempted, _ := item["exempted"].(bool); exempted {
				exemptedOnly = append(exemptedOnly, item)
			}
		}
	}
	if exemptedOnly == nil {
		exemptedOnly = []map[string]interface{}{}
	}
	counterfactual["malicious"] = exemptedOnly
	counterfactual["maliciousCount"] = 0
	out, _, err := e.celProgram.Eval(counterfactual)
	if err != nil {
		return false
	}
	passed, ok := out.Value().(bool)
	return ok && passed
}

// applyMaliciousGate fails the decision for malicious findings, keeping any
// vulnerability findings the expression produced.
func (e *Engine) applyMaliciousGate(decision *PolicyDecision, imageRef string, celPassed bool, findings []types.MaliciousFinding) {
	ids := make([]string, 0, len(findings))
	seen := make(map[string]bool, len(findings))
	for _, finding := range findings {
		if !seen[finding.ID] {
			seen[finding.ID] = true
			ids = append(ids, finding.ID)
		}
	}
	gateReason := fmt.Sprintf("malicious packages found: %s", strings.Join(ids, ", "))

	decision.Passed = false
	decision.Status = PolicyStatusFailed
	decision.PolicyFailureFindings = append(decision.PolicyFailureFindings, maliciousFailureFindings(findings)...)
	if celPassed {
		decision.Reason = gateReason
	} else {
		decision.Reason = gateReason + "; " + decision.Reason
	}

	e.logger.Warn("policy failed: malicious packages found",
		"image", imageRef,
		"ids", strings.Join(ids, ","))
}
