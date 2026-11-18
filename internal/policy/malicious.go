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

// maliciousCELInput exposes malicious findings to CEL. They are never
// VEX-exempted: a published malicious package is not a vulnerability to triage.
func maliciousCELInput(findings []types.MaliciousFinding) []map[string]interface{} {
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
		})
	}
	return input
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
// image had no malicious findings, i.e. whether they caused the failure.
func (e *Engine) passesWithoutMalicious(celInput map[string]interface{}) bool {
	counterfactual := make(map[string]interface{}, len(celInput))
	for key, value := range celInput {
		counterfactual[key] = value
	}
	counterfactual["malicious"] = []map[string]interface{}{}
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
