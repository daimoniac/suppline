package policy

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/daimoniac/suppline/internal/errors"
	"github.com/daimoniac/suppline/internal/scanner"
	"github.com/daimoniac/suppline/internal/types"
	"github.com/google/cel-go/cel"
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

			e.logger.Info("vulnerability exempted by VEX",
				"cve_id", vuln.ID,
				"severity", vuln.Severity,
				"vex_state", stmt.State,
				"vex_justification", stmt.Justification,
				"detail", stmt.Detail,
				"package", vuln.PackageName,
				"image", imageRef)
		} else {
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

// SetExpiryWarningWindow sets the duration before expiry to trigger warnings
func (e *Engine) SetExpiryWarningWindow(duration time.Duration) {
	e.expiryWarningWindow = duration
}
