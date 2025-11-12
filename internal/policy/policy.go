package policy

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/suppline/suppline/internal/regsync"
	"github.com/suppline/suppline/internal/scanner"
)

// PolicyEngine defines the interface for policy evaluation
type PolicyEngine interface {
	// Evaluate determines if an image passes security policy
	// Applies CVE tolerations from regsync config for the target repository
	Evaluate(ctx context.Context, imageRef string, result *scanner.ScanResult, tolerations []regsync.CVEToleration) (*PolicyDecision, error)
}

// PolicyDecision represents the result of policy evaluation
type PolicyDecision struct {
	Passed             bool
	Reason             string
	ShouldSign         bool
	ShouldAttest       bool
	CriticalVulnCount  int
	ToleratedVulnCount int
	ToleratedCVEs      []string
	ExpiringTolerations []ExpiringToleration
}

// ExpiringToleration represents a toleration that is expiring soon
type ExpiringToleration struct {
	CVEID     string
	Statement string
	ExpiresAt time.Time
	DaysUntil int
}

// Engine implements the PolicyEngine interface
type Engine struct {
	logger              *slog.Logger
	expiryWarningWindow time.Duration
}

// NewEngine creates a new policy engine
func NewEngine(logger *slog.Logger) *Engine {
	if logger == nil {
		logger = slog.Default()
	}
	return &Engine{
		logger:              logger,
		expiryWarningWindow: 7 * 24 * time.Hour, // 7 days
	}
}

// Evaluate determines if an image passes security policy
func (e *Engine) Evaluate(ctx context.Context, imageRef string, result *scanner.ScanResult, tolerations []regsync.CVEToleration) (*PolicyDecision, error) {
	if result == nil {
		return nil, fmt.Errorf("scan result is nil")
	}

	decision := &PolicyDecision{
		ShouldAttest:        true, // Always create attestations
		ToleratedCVEs:       make([]string, 0),
		ExpiringTolerations: make([]ExpiringToleration, 0),
	}

	// Build a map of active tolerations (not expired)
	now := time.Now()
	activeTolerations := make(map[string]regsync.CVEToleration)
	
	for _, toleration := range tolerations {
		// Check if toleration has expired
		if toleration.ExpiresAt != nil && toleration.ExpiresAt.Before(now) {
			e.logger.Debug("toleration expired",
				"cve_id", toleration.ID,
				"expired_at", toleration.ExpiresAt,
				"image", imageRef)
			continue
		}
		
		activeTolerations[toleration.ID] = toleration
		
		// Check if toleration is expiring soon
		if toleration.ExpiresAt != nil {
			timeUntilExpiry := toleration.ExpiresAt.Sub(now)
			if timeUntilExpiry > 0 && timeUntilExpiry <= e.expiryWarningWindow {
				daysUntil := int(timeUntilExpiry.Hours() / 24)
				decision.ExpiringTolerations = append(decision.ExpiringTolerations, ExpiringToleration{
					CVEID:     toleration.ID,
					Statement: toleration.Statement,
					ExpiresAt: *toleration.ExpiresAt,
					DaysUntil: daysUntil,
				})
				
				e.logger.Warn("toleration expiring soon",
					"cve_id", toleration.ID,
					"statement", toleration.Statement,
					"expires_at", toleration.ExpiresAt,
					"days_until_expiry", daysUntil,
					"image", imageRef)
			}
		}
	}

	// Count critical vulnerabilities, excluding tolerated ones
	criticalCount := 0
	toleratedCount := 0
	criticalVulns := make([]scanner.Vulnerability, 0)
	
	for _, vuln := range result.Vulnerabilities {
		if vuln.Severity == "CRITICAL" {
			if toleration, isTolerated := activeTolerations[vuln.ID]; isTolerated {
				toleratedCount++
				decision.ToleratedCVEs = append(decision.ToleratedCVEs, vuln.ID)
				
				e.logger.Info("critical vulnerability tolerated",
					"cve_id", vuln.ID,
					"statement", toleration.Statement,
					"package", vuln.PackageName,
					"image", imageRef)
			} else {
				criticalCount++
				criticalVulns = append(criticalVulns, vuln)
			}
		}
	}

	decision.CriticalVulnCount = criticalCount
	decision.ToleratedVulnCount = toleratedCount

	// Determine if policy passes
	if criticalCount == 0 {
		decision.Passed = true
		decision.ShouldSign = true
		decision.Reason = fmt.Sprintf("no critical vulnerabilities (%d tolerated)", toleratedCount)
		
		e.logger.Info("policy evaluation passed",
			"image", imageRef,
			"critical_vulns", criticalCount,
			"tolerated_vulns", toleratedCount)
	} else {
		decision.Passed = false
		decision.ShouldSign = false
		decision.Reason = fmt.Sprintf("%d critical vulnerabilities found (%d tolerated)", criticalCount, toleratedCount)
		
		e.logger.Warn("policy evaluation failed",
			"image", imageRef,
			"critical_vulns", criticalCount,
			"tolerated_vulns", toleratedCount)
		
		// Log details about each critical vulnerability that caused the failure
		for _, vuln := range criticalVulns {
			e.logger.Warn("critical vulnerability details",
				"cve_id", vuln.ID,
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
