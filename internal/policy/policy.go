package policy

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"cel.dev/cel-go/cel"
	"github.com/daimoniac/suppline/internal/errors"
	"github.com/daimoniac/suppline/internal/scanner"
	"github.com/daimoniac/suppline/internal/types"
)

// PolicyEngine defines the interface for policy evaluation
type PolicyEngine interface {
	// Evaluate determines if an image passes security policy
	// Applies VEX statements from regsync config for the target repository;
	// only not_affected (and not expired) statements exempt CVEs from counts.
	Evaluate(ctx context.Context, imageRef string, result *scanner.ScanResult, vexStatements []types.VEXStatement) (*PolicyDecision, error)
}

// PolicyConfig defines a CEL-based policy configuration
type PolicyConfig struct {
	// Expression is the CEL expression that must evaluate to true for the policy to pass
	// Available variables:
	//   - vulnerabilities: list of enriched vulnerabilities with fields:
	//       id, severity, packageName, version, fixedVersion, description, exempted, vexState, vexJustification, vexDetail
	//   - imageRef: string reference to the image
	//   - criticalCount: number of critical vulnerabilities (not exempted)
	//   - highCount: number of high vulnerabilities (not exempted)
	//   - mediumCount: number of medium vulnerabilities (not exempted)
	//   - exemptedCount: number of exempted vulnerabilities
	Expression string `yaml:"expression" json:"expression"`

	// FailureMessage is the message to return when the policy fails (optional)
	FailureMessage string `yaml:"failureMessage" json:"failureMessage"`

	// MinimumReleaseAge blocks policy pass/fail evaluation until the image age reaches this duration.
	MinimumReleaseAge time.Duration `yaml:"-" json:"-"`
}

const (
	PolicyStatusPassed  = "passed"
	PolicyStatusFailed  = "failed"
	PolicyStatusPending = "pending"
)

// PolicyDecision represents the result of policy evaluation
type PolicyDecision struct {
	Passed                   bool
	Status                   string
	Reason                   string
	ShouldAttest             bool
	CriticalVulnCount        int
	ExemptedVulnCount        int
	UnfixedVulnCount         int
	ExemptedCVEs             []string
	PolicyFailureFindings    []types.PolicyFailureFinding
	ExpiringVEXStatements    []ExpiringVEXStatement
	ReleaseAgeSeconds        int64
	MinimumReleaseAgeSeconds int64
	ReleaseAgeSource         string
}

// ExpiringVEXStatement represents a VEX statement that is expiring soon
type ExpiringVEXStatement struct {
	CVEID         string
	State         types.VEXAnalysisState
	Justification types.VEXJustification
	Detail        string
	ExpiresAt     int64 // Unix timestamp in seconds
	DaysUntil     int
}

// Engine implements the PolicyEngine interface using CEL expressions
type Engine struct {
	logger              *slog.Logger
	expiryWarningWindow time.Duration
	config              PolicyConfig
	celEnv              *cel.Env
	celProgram          cel.Program
}

// NewEngine creates a new policy engine with a CEL-based policy
func NewEngine(logger *slog.Logger, config PolicyConfig) (*Engine, error) {
	if logger == nil {
		logger = slog.Default()
	}

	if config.Expression == "" {
		config.Expression = `criticalCount == 0`
		config.FailureMessage = "critical vulnerabilities found"
	}

	env, err := cel.NewEnv(
		cel.Variable("vulnerabilities", cel.ListType(cel.MapType(cel.StringType, cel.AnyType))),
		cel.Variable("imageRef", cel.StringType),
		cel.Variable("criticalCount", cel.IntType),
		cel.Variable("highCount", cel.IntType),
		cel.Variable("mediumCount", cel.IntType),
		cel.Variable("lowCount", cel.IntType),
		cel.Variable("exemptedCount", cel.IntType),
	)
	if err != nil {
		return nil, errors.NewPermanentf("failed to create CEL environment: %w", err)
	}

	ast, issues := env.Compile(config.Expression)
	if issues != nil && issues.Err() != nil {
		return nil, errors.NewPermanentf("failed to compile policy expression: %w", issues.Err())
	}

	if ast.OutputType() != cel.BoolType {
		return nil, errors.NewPermanentf("policy expression must return a boolean, got %v", ast.OutputType())
	}

	program, err := env.Program(ast)
	if err != nil {
		return nil, errors.NewPermanentf("failed to create CEL program: %w", err)
	}

	return &Engine{
		logger:              logger,
		expiryWarningWindow: 7 * 24 * time.Hour,
		config:              config,
		celEnv:              env,
		celProgram:          program,
	}, nil
}

// Evaluate determines if an image passes security policy using CEL expression
func (e *Engine) Evaluate(ctx context.Context, imageRef string, result *scanner.ScanResult, vexStatements []types.VEXStatement) (*PolicyDecision, error) {
	if result == nil {
		return nil, errors.NewPermanentf("scan result is nil")
	}

	decision := &PolicyDecision{
		ShouldAttest:          true, // Always create attestations
		Status:                PolicyStatusPassed,
		ExemptedCVEs:          make([]string, 0),
		PolicyFailureFindings: make([]types.PolicyFailureFinding, 0),
		ExpiringVEXStatements: make([]ExpiringVEXStatement, 0),
	}

	if result.ScannedAt.IsZero() {
		result.ScannedAt = time.Now().UTC()
	}

	if e.config.MinimumReleaseAge > 0 {
		var ageBase *time.Time
		ageSource := ""

		if result.ImageCreatedAt != nil {
			ageBase = result.ImageCreatedAt
			ageSource = "image_created_at"
		} else if result.FirstSeenAt != nil {
			ageBase = result.FirstSeenAt
			ageSource = "first_seen"
		}

		decision.MinimumReleaseAgeSeconds = int64(e.config.MinimumReleaseAge.Seconds())
		decision.ReleaseAgeSource = ageSource

		if ageBase == nil {
			decision.Passed = false
			decision.Status = PolicyStatusPending
			decision.ShouldAttest = false
			decision.Reason = fmt.Sprintf("policy pending: minimum release age is configured (%s) but no age source is available", e.config.MinimumReleaseAge)
			return decision, nil
		}

		releaseAge := result.ScannedAt.Sub(*ageBase)
		if releaseAge < 0 {
			releaseAge = 0
		}
		decision.ReleaseAgeSeconds = int64(releaseAge.Seconds())

		if releaseAge < e.config.MinimumReleaseAge {
			decision.Passed = false
			decision.Status = PolicyStatusPending
			decision.ShouldAttest = false
			remaining := e.config.MinimumReleaseAge - releaseAge
			decision.Reason = fmt.Sprintf(
				"policy pending: image age %s is below minimum release age %s (remaining %s, source=%s)",
				releaseAge.Truncate(time.Second),
				e.config.MinimumReleaseAge,
				remaining.Truncate(time.Second),
				ageSource,
			)
			return decision, nil
		}
	}

	nowUnix := time.Now().Unix()
	activeVEX := make(map[string]types.VEXStatement)

	for _, stmt := range vexStatements {
		// Only not_affected statements can exempt CVEs from severity counts
		if stmt.State != types.VEXStateNotAffected {
			continue
		}

		if stmt.ExpiresAt != nil && *stmt.ExpiresAt < nowUnix {
			e.logger.Debug("VEX statement expired",
				"cve_id", stmt.ID,
				"state", stmt.State,
				"expired_at", *stmt.ExpiresAt,
				"image", imageRef)
			continue
		}

		activeVEX[stmt.ID] = stmt

		if stmt.ExpiresAt != nil {
			secondsUntilExpiry := *stmt.ExpiresAt - nowUnix
			if secondsUntilExpiry > 0 && time.Duration(secondsUntilExpiry)*time.Second <= e.expiryWarningWindow {
				daysUntil := int(secondsUntilExpiry / (24 * 3600))
				decision.ExpiringVEXStatements = append(decision.ExpiringVEXStatements, ExpiringVEXStatement{
					CVEID:         stmt.ID,
					State:         stmt.State,
					Justification: stmt.Justification,
					Detail:        stmt.Detail,
					ExpiresAt:     *stmt.ExpiresAt,
					DaysUntil:     daysUntil,
				})

				e.logger.Warn("VEX statement expiring soon",
					"cve_id", stmt.ID,
					"state", stmt.State,
					"detail", stmt.Detail,
					"expires_at", *stmt.ExpiresAt,
					"days_until_expiry", daysUntil,
					"image", imageRef)
			}
		}
	}

	enrichedVulns := make([]map[string]interface{}, 0, len(result.Vulnerabilities))
	nonExemptedIndexes := make([]int, 0, len(result.Vulnerabilities))
	nonExemptedVulns := make([]types.Vulnerability, 0, len(result.Vulnerabilities))
	criticalCount := 0
	highCount := 0
	mediumCount := 0
	lowCount := 0
	exemptedCount := 0
	unfixedCriticalCount := 0
	failingVulns := make([]types.Vulnerability, 0)

	for _, vuln := range result.Vulnerabilities {
		stmt, isExempted := activeVEX[vuln.ID]

		enriched := map[string]interface{}{
			"id":           vuln.ID,
			"severity":     vuln.Severity,
			"packageName":  vuln.PackageName,
			"version":      vuln.Version,
			"fixedVersion": vuln.FixedVersion,
			"description":  vuln.Description,
			"exempted":     isExempted,
		}

		if isExempted {
			enriched["vexState"] = string(stmt.State)
			enriched["vexJustification"] = string(stmt.Justification)
			enriched["vexDetail"] = stmt.Detail
			exemptedCount++
			decision.ExemptedCVEs = append(decision.ExemptedCVEs, vuln.ID)

			e.logger.Debug("vulnerability exempted by VEX",
				"cve_id", vuln.ID,
				"severity", vuln.Severity,
				"vex_state", stmt.State,
				"vex_justification", stmt.Justification,
				"detail", stmt.Detail,
				"package", vuln.PackageName,
				"image", imageRef)
		} else {
			nonExemptedIndexes = append(nonExemptedIndexes, len(enrichedVulns))
			nonExemptedVulns = append(nonExemptedVulns, vuln)
			switch vuln.Severity {
			case "CRITICAL":
				criticalCount++
				failingVulns = append(failingVulns, vuln)
				if vuln.FixedVersion == "" {
					unfixedCriticalCount++
				}
			case "HIGH":
				highCount++
			case "MEDIUM":
				mediumCount++
			case "LOW":
				lowCount++
			}
		}

		enrichedVulns = append(enrichedVulns, enriched)
	}

	decision.CriticalVulnCount = criticalCount
	decision.ExemptedVulnCount = exemptedCount
	decision.UnfixedVulnCount = unfixedCriticalCount

	celInput := map[string]interface{}{
		"vulnerabilities": enrichedVulns,
		"imageRef":        imageRef,
		"criticalCount":   criticalCount,
		"highCount":       highCount,
		"mediumCount":     mediumCount,
		"lowCount":        lowCount,
		"exemptedCount":   exemptedCount,
	}

	out, _, err := e.celProgram.Eval(celInput)
	if err != nil {
		return nil, errors.NewPermanentf("failed to evaluate policy: %w", err)
	}

	passed, ok := out.Value().(bool)
	if !ok {
		return nil, errors.NewPermanentf("policy expression did not return a boolean: %v", out.Value())
	}

	decision.Passed = passed
	if passed {
		decision.Status = PolicyStatusPassed
	} else {
		decision.Status = PolicyStatusFailed
		decision.PolicyFailureFindings = e.findPolicyFailureFindings(imageRef, enrichedVulns, nonExemptedIndexes, nonExemptedVulns)
	}

	if passed {
		if unfixedCriticalCount > 0 {
			decision.Reason = fmt.Sprintf("policy passed: critical=%d, high=%d, medium=%d, low=%d (exempted=%d, unfixed=%d)",
				criticalCount, highCount, mediumCount, lowCount, exemptedCount, unfixedCriticalCount)
		} else {
			decision.Reason = fmt.Sprintf("policy passed: critical=%d, high=%d, medium=%d, low=%d (exempted=%d)",
				criticalCount, highCount, mediumCount, lowCount, exemptedCount)
		}

		e.logger.Info("policy evaluation passed",
			"image", imageRef,
			"critical", criticalCount,
			"high", highCount,
			"medium", mediumCount,
			"low", lowCount,
			"exempted", exemptedCount)
	} else {
		if e.config.FailureMessage != "" {
			decision.Reason = e.config.FailureMessage
		} else {
			if unfixedCriticalCount > 0 {
				decision.Reason = fmt.Sprintf("policy failed: critical=%d, high=%d, medium=%d, low=%d (exempted=%d, unfixed=%d)",
					criticalCount, highCount, mediumCount, lowCount, exemptedCount, unfixedCriticalCount)
			} else {
				decision.Reason = fmt.Sprintf("policy failed: critical=%d, high=%d, medium=%d, low=%d (exempted=%d)",
					criticalCount, highCount, mediumCount, lowCount, exemptedCount)
			}
		}

		e.logger.Warn("policy evaluation failed",
			"image", imageRef,
			"critical", criticalCount,
			"high", highCount,
			"medium", mediumCount,
			"low", lowCount,
			"exempted", exemptedCount,
			"expression", e.config.Expression)

		for _, vuln := range failingVulns {
			e.logger.Warn("vulnerability details",
				"cve_id", vuln.ID,
				"severity", vuln.Severity,
				"description", vuln.Description,
				"package", vuln.PackageName,
				"installed_version", vuln.Version,
				"fixed_version", vuln.FixedVersion,
				"image", imageRef)
		}
	}

	return decision, nil
}

func (e *Engine) findPolicyFailureFindings(imageRef string, enrichedVulns []map[string]interface{}, candidateIndexes []int, candidateVulns []types.Vulnerability) []types.PolicyFailureFinding {
	if len(enrichedVulns) == 0 || len(candidateIndexes) == 0 || len(candidateVulns) == 0 {
		return nil
	}

	candidatePosByIndex := make(map[int]int, len(candidateIndexes))
	for pos, idx := range candidateIndexes {
		candidatePosByIndex[idx] = pos
	}

	evaluate := func(included []bool) (bool, error) {
		return e.evaluateSubset(imageRef, enrichedVulns, candidatePosByIndex, included)
	}

	// If the fixed baseline (for example exempted vulnerabilities and imageRef)
	// already fails, no non-exempted vulnerability can be attributed to the failure.
	included := make([]bool, len(candidateIndexes))
	baselinePassed, err := evaluate(included)
	if err != nil {
		e.logger.Warn("failed to evaluate CEL attribution baseline",
			"image", imageRef,
			"error", err)
		return nil
	}
	if !baselinePassed {
		return nil
	}

	contributor := make([]bool, len(candidateIndexes))

	// Sufficient contributors fail the policy by themselves. This exactly and
	// cheaply handles the common "no matching vulnerabilities" policy shape.
	for pos, idx := range candidateIndexes {
		included[pos] = true
		passed, evalErr := evaluate(included)
		included[pos] = false
		if evalErr != nil {
			e.logger.Warn("failed to evaluate sufficient CEL contributor",
				"image", imageRef,
				"index", idx,
				"error", evalErr)
			continue
		}
		if !passed {
			contributor[pos] = true
		}
	}

	// Necessary contributors make the full input pass when removed.
	for pos := range included {
		included[pos] = true
	}
	for pos, idx := range candidateIndexes {
		included[pos] = false
		passed, evalErr := evaluate(included)
		included[pos] = true
		if evalErr != nil {
			e.logger.Warn("failed to evaluate necessary CEL contributor",
				"image", imageRef,
				"index", idx,
				"error", evalErr)
			continue
		}
		if passed {
			contributor[pos] = true
		}
	}

	// Isolate any remaining cooperative failure mechanisms deterministically.
	// Each iteration removes already-attributed vulnerabilities, shrinks the
	// remaining failing set to a one-minimal witness, then finds candidates that
	// can substitute for a witness member. This preserves threshold attribution
	// without repeatedly evaluating random full-size permutations.
	for {
		active := make([]bool, len(candidateIndexes))
		for pos := range active {
			active[pos] = !contributor[pos]
		}

		passed, evalErr := evaluate(active)
		if evalErr != nil {
			e.logger.Warn("failed to evaluate cooperative CEL contributors",
				"image", imageRef,
				"error", evalErr)
			break
		}
		if passed {
			break
		}

		witness := append([]bool(nil), active...)
		for pos, isIncluded := range witness {
			if !isIncluded {
				continue
			}
			witness[pos] = false
			passed, evalErr = evaluate(witness)
			if evalErr != nil || passed {
				witness[pos] = true
			}
		}

		witnessPositions := make([]int, 0)
		for pos, isIncluded := range witness {
			if isIncluded {
				witnessPositions = append(witnessPositions, pos)
				contributor[pos] = true
			}
		}
		if len(witnessPositions) == 0 {
			break
		}

		for candidatePos, isActive := range active {
			if !isActive || witness[candidatePos] {
				continue
			}

			witness[candidatePos] = true
			for _, witnessPos := range witnessPositions {
				witness[witnessPos] = false
				passed, evalErr = evaluate(witness)
				witness[witnessPos] = true
				if evalErr == nil && !passed {
					contributor[candidatePos] = true
					break
				}
			}
			witness[candidatePos] = false
		}
	}

	findings := make([]types.PolicyFailureFinding, 0, len(candidateIndexes))
	seen := make(map[string]struct{})
	for i, isContributor := range contributor {
		if !isContributor {
			continue
		}
		key := candidateVulns[i].ID + "|" + candidateVulns[i].PackageName
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		findings = append(findings, types.PolicyFailureFinding{
			CVEID:       candidateVulns[i].ID,
			PackageName: candidateVulns[i].PackageName,
		})
	}

	return findings
}

func (e *Engine) evaluateSubset(imageRef string, enrichedVulns []map[string]interface{}, candidatePosByIndex map[int]int, included []bool) (bool, error) {
	counterfactual := make([]map[string]interface{}, 0, len(enrichedVulns))
	for idx, vuln := range enrichedVulns {
		pos, isCandidate := candidatePosByIndex[idx]
		if isCandidate && !included[pos] {
			continue
		}
		counterfactual = append(counterfactual, vuln)
	}

	criticalCount := 0
	highCount := 0
	mediumCount := 0
	lowCount := 0
	exemptedCount := 0

	for _, vuln := range counterfactual {
		exempted, _ := vuln["exempted"].(bool)
		if exempted {
			exemptedCount++
			continue
		}

		severity, _ := vuln["severity"].(string)
		switch severity {
		case "CRITICAL":
			criticalCount++
		case "HIGH":
			highCount++
		case "MEDIUM":
			mediumCount++
		case "LOW":
			lowCount++
		}
	}

	celInput := map[string]interface{}{
		"vulnerabilities": counterfactual,
		"imageRef":        imageRef,
		"criticalCount":   criticalCount,
		"highCount":       highCount,
		"mediumCount":     mediumCount,
		"lowCount":        lowCount,
		"exemptedCount":   exemptedCount,
	}

	out, _, err := e.celProgram.Eval(celInput)
	if err != nil {
		return false, errors.NewTransientf("failed to evaluate subset policy: %w", err)
	}

	passed, ok := out.Value().(bool)
	if !ok {
		return false, errors.NewTransientf("subset policy expression did not return bool: %v", out.Value())
	}

	return passed, nil
}

// SetExpiryWarningWindow sets the duration before expiry to trigger warnings
func (e *Engine) SetExpiryWarningWindow(duration time.Duration) {
	e.expiryWarningWindow = duration
}
