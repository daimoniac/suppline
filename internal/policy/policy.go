package policy

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/cel-go/cel"
	"github.com/daimoniac/suppline/internal/errors"
	"github.com/daimoniac/suppline/internal/scanner"
	"github.com/daimoniac/suppline/internal/types"
)

// PolicyEngine defines the interface for policy evaluation
type PolicyEngine interface {
	// Evaluate determines if an image passes security policy
	// Applies CVE tolerations from regsync config for the target repository
	Evaluate(ctx context.Context, imageRef string, result *scanner.ScanResult, tolerations []types.CVEToleration) (*PolicyDecision, error)
}

// PolicyConfig defines a CEL-based policy configuration
type PolicyConfig struct {
	// Expression is the CEL expression that must evaluate to true for the policy to pass
	// Available variables:
	//   - vulnerabilities: list of enriched vulnerabilities with fields:
	//       id, severity, packageName, version, fixedVersion, description, tolerated, tolerationStatement, tolerationExpiry
	//   - imageRef: string reference to the image
	//   - criticalCount: number of critical vulnerabilities (not tolerated)
	//   - highCount: number of high vulnerabilities (not tolerated)
	//   - mediumCount: number of medium vulnerabilities (not tolerated)
	//   - toleratedCount: number of tolerated vulnerabilities
	Expression string `yaml:"expression" json:"expression"`
	
	// FailureMessage is the message to return when the policy fails (optional)
	FailureMessage string `yaml:"failureMessage" json:"failureMessage"`
}

// PolicyDecision represents the result of policy evaluation
type PolicyDecision struct {
	Passed             bool
	Reason             string
	ShouldAttest       bool
	CriticalVulnCount  int
	ToleratedVulnCount int
	UnfixedVulnCount   int
	ToleratedCVEs      []string
	ExpiringTolerations []ExpiringToleration
}

// ExpiringToleration represents a toleration that is expiring soon
type ExpiringToleration struct {
	CVEID     string
	Statement string
	ExpiresAt int64 // Unix timestamp in seconds
	DaysUntil int
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
		cel.Variable("toleratedCount", cel.IntType),
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
func (e *Engine) Evaluate(ctx context.Context, imageRef string, result *scanner.ScanResult, tolerations []types.CVEToleration) (*PolicyDecision, error) {
	if result == nil {
		return nil, errors.NewPermanentf("scan result is nil")
	}

	decision := &PolicyDecision{
		ShouldAttest:        true, // Always create attestations
		ToleratedCVEs:       make([]string, 0),
		ExpiringTolerations: make([]ExpiringToleration, 0),
	}

	nowUnix := time.Now().Unix()
	activeTolerations := make(map[string]types.CVEToleration)
	
	for _, toleration := range tolerations {
		if toleration.ExpiresAt != nil && *toleration.ExpiresAt < nowUnix {
			e.logger.Debug("toleration expired",
				"cve_id", toleration.ID,
				"expired_at", *toleration.ExpiresAt,
				"image", imageRef)
			continue
		}
		
		activeTolerations[toleration.ID] = toleration
		
		if toleration.ExpiresAt != nil {
			secondsUntilExpiry := *toleration.ExpiresAt - nowUnix
			if secondsUntilExpiry > 0 && time.Duration(secondsUntilExpiry)*time.Second <= e.expiryWarningWindow {
				daysUntil := int(secondsUntilExpiry / (24 * 3600))
				decision.ExpiringTolerations = append(decision.ExpiringTolerations, ExpiringToleration{
					CVEID:     toleration.ID,
					Statement: toleration.Statement,
					ExpiresAt: *toleration.ExpiresAt,
					DaysUntil: daysUntil,
				})
				
				e.logger.Warn("toleration expiring soon",
					"cve_id", toleration.ID,
					"statement", toleration.Statement,
					"expires_at", *toleration.ExpiresAt,
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
	toleratedCount := 0
	unfixedCriticalCount := 0
	failingVulns := make([]types.Vulnerability, 0)
	
	for _, vuln := range result.Vulnerabilities {
		toleration, isTolerated := activeTolerations[vuln.ID]
		
		enriched := map[string]interface{}{
			"id":          vuln.ID,
			"severity":    vuln.Severity,
			"packageName": vuln.PackageName,
			"version":     vuln.Version,
			"fixedVersion": vuln.FixedVersion,
			"description": vuln.Description,
			"tolerated":   isTolerated,
		}
		
		if isTolerated {
			enriched["tolerationStatement"] = toleration.Statement
			if toleration.ExpiresAt != nil {
				enriched["tolerationExpiry"] = time.Unix(*toleration.ExpiresAt, 0).UTC().Format(time.RFC3339)
			}
			toleratedCount++
			decision.ToleratedCVEs = append(decision.ToleratedCVEs, vuln.ID)
			
			e.logger.Info("vulnerability tolerated",
				"cve_id", vuln.ID,
				"severity", vuln.Severity,
				"statement", toleration.Statement,
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
	decision.ToleratedVulnCount = toleratedCount
	decision.UnfixedVulnCount = unfixedCriticalCount

	celInput := map[string]interface{}{
		"vulnerabilities": enrichedVulns,
		"imageRef":        imageRef,
		"criticalCount":   criticalCount,
		"highCount":       highCount,
		"mediumCount":     mediumCount,
		"lowCount":        lowCount,
		"toleratedCount":  toleratedCount,
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
		if unfixedCriticalCount > 0 {
			decision.Reason = fmt.Sprintf("policy passed: critical=%d, high=%d, medium=%d, low=%d (tolerated=%d, unfixed=%d)",
				criticalCount, highCount, mediumCount, lowCount, toleratedCount, unfixedCriticalCount)
		} else {
			decision.Reason = fmt.Sprintf("policy passed: critical=%d, high=%d, medium=%d, low=%d (tolerated=%d)",
				criticalCount, highCount, mediumCount, lowCount, toleratedCount)
		}
		
		e.logger.Info("policy evaluation passed",
			"image", imageRef,
			"critical", criticalCount,
			"high", highCount,
			"medium", mediumCount,
			"low", lowCount,
			"tolerated", toleratedCount)
	} else {
		if e.config.FailureMessage != "" {
			decision.Reason = e.config.FailureMessage
		} else {
			if unfixedCriticalCount > 0 {
				decision.Reason = fmt.Sprintf("policy failed: critical=%d, high=%d, medium=%d, low=%d (tolerated=%d, unfixed=%d)",
					criticalCount, highCount, mediumCount, lowCount, toleratedCount, unfixedCriticalCount)
			} else {
				decision.Reason = fmt.Sprintf("policy failed: critical=%d, high=%d, medium=%d, low=%d (tolerated=%d)",
					criticalCount, highCount, mediumCount, lowCount, toleratedCount)
			}
		}
		
		e.logger.Warn("policy evaluation failed",
			"image", imageRef,
			"critical", criticalCount,
			"high", highCount,
			"medium", mediumCount,
			"low", lowCount,
			"tolerated", toleratedCount,
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
