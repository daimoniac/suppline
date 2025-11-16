package policy

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/daimoniac/suppline/daimoniac/suppline/internal/scanner"
	"github.com/daimoniac/suppline/daimoniac/suppline/internal/types"
)

func TestEngine_Evaluate_NoCriticalVulnerabilities(t *testing.T) {
	engine, err := NewEngine(slog.Default(), PolicyConfig{
		Expression: "criticalCount == 0",
	})
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}
	ctx := context.Background()

	result := &scanner.ScanResult{
		ImageRef: "test/image:v1",
		Vulnerabilities: []types.Vulnerability{
			{ID: "CVE-2024-0001", Severity: "HIGH", PackageName: "pkg1"},
			{ID: "CVE-2024-0002", Severity: "MEDIUM", PackageName: "pkg2"},
			{ID: "CVE-2024-0003", Severity: "LOW", PackageName: "pkg3"},
		},
	}

	decision, err := engine.Evaluate(ctx, "test/image:v1", result, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !decision.Passed {
		t.Errorf("expected policy to pass, got failed")
	}

	if !decision.ShouldSign {
		t.Errorf("expected ShouldSign to be true")
	}

	if !decision.ShouldAttest {
		t.Errorf("expected ShouldAttest to be true")
	}

	if decision.CriticalVulnCount != 0 {
		t.Errorf("expected 0 critical vulnerabilities, got %d", decision.CriticalVulnCount)
	}
}

func TestEngine_Evaluate_CriticalVulnerabilitiesPresent(t *testing.T) {
	engine, err := NewEngine(slog.Default(), PolicyConfig{
		Expression: "criticalCount == 0",
	})
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}
	ctx := context.Background()

	result := &scanner.ScanResult{
		ImageRef: "test/image:v1",
		Vulnerabilities: []types.Vulnerability{
			{ID: "CVE-2024-0001", Severity: "CRITICAL", PackageName: "pkg1"},
			{ID: "CVE-2024-0002", Severity: "CRITICAL", PackageName: "pkg2"},
			{ID: "CVE-2024-0003", Severity: "HIGH", PackageName: "pkg3"},
		},
	}

	decision, err := engine.Evaluate(ctx, "test/image:v1", result, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if decision.Passed {
		t.Errorf("expected policy to fail, got passed")
	}

	if decision.ShouldSign {
		t.Errorf("expected ShouldSign to be false")
	}

	if !decision.ShouldAttest {
		t.Errorf("expected ShouldAttest to be true")
	}

	if decision.CriticalVulnCount != 2 {
		t.Errorf("expected 2 critical vulnerabilities, got %d", decision.CriticalVulnCount)
	}
}

func TestEngine_Evaluate_ToleratedCVEs(t *testing.T) {
	engine, err := NewEngine(slog.Default(), PolicyConfig{
		Expression: "criticalCount == 0",
	})
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}
	ctx := context.Background()

	result := &scanner.ScanResult{
		ImageRef: "test/image:v1",
		Vulnerabilities: []types.Vulnerability{
			{ID: "CVE-2024-0001", Severity: "CRITICAL", PackageName: "pkg1"},
			{ID: "CVE-2024-0002", Severity: "CRITICAL", PackageName: "pkg2"},
			{ID: "CVE-2024-0003", Severity: "CRITICAL", PackageName: "pkg3"},
		},
	}

	tolerations := []types.CVEToleration{
		{
			ID:        "CVE-2024-0001",
			Statement: "accepted risk, no fix available",
		},
		{
			ID:        "CVE-2024-0002",
			Statement: "temporary toleration",
		},
	}

	decision, err := engine.Evaluate(ctx, "test/image:v1", result, tolerations)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if decision.Passed {
		t.Errorf("expected policy to fail (1 critical remaining), got passed")
	}

	if decision.CriticalVulnCount != 1 {
		t.Errorf("expected 1 critical vulnerability, got %d", decision.CriticalVulnCount)
	}

	if decision.ToleratedVulnCount != 2 {
		t.Errorf("expected 2 tolerated vulnerabilities, got %d", decision.ToleratedVulnCount)
	}

	if len(decision.ToleratedCVEs) != 2 {
		t.Errorf("expected 2 tolerated CVE IDs, got %d", len(decision.ToleratedCVEs))
	}
}

func TestEngine_Evaluate_AllCriticalVulnerabilitiesTolerated(t *testing.T) {
	engine, err := NewEngine(slog.Default(), PolicyConfig{
		Expression: "criticalCount == 0",
	})
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}
	ctx := context.Background()

	result := &scanner.ScanResult{
		ImageRef: "test/image:v1",
		Vulnerabilities: []types.Vulnerability{
			{ID: "CVE-2024-0001", Severity: "CRITICAL", PackageName: "pkg1"},
			{ID: "CVE-2024-0002", Severity: "CRITICAL", PackageName: "pkg2"},
		},
	}

	tolerations := []types.CVEToleration{
		{
			ID:        "CVE-2024-0001",
			Statement: "accepted risk",
		},
		{
			ID:        "CVE-2024-0002",
			Statement: "no fix available",
		},
	}

	decision, err := engine.Evaluate(ctx, "test/image:v1", result, tolerations)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !decision.Passed {
		t.Errorf("expected policy to pass (all critical tolerated), got failed")
	}

	if !decision.ShouldSign {
		t.Errorf("expected ShouldSign to be true")
	}

	if decision.CriticalVulnCount != 0 {
		t.Errorf("expected 0 critical vulnerabilities, got %d", decision.CriticalVulnCount)
	}

	if decision.ToleratedVulnCount != 2 {
		t.Errorf("expected 2 tolerated vulnerabilities, got %d", decision.ToleratedVulnCount)
	}
}

func TestEngine_Evaluate_ExpiredToleration(t *testing.T) {
	engine, err := NewEngine(slog.Default(), PolicyConfig{
		Expression: "criticalCount == 0",
	})
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}
	ctx := context.Background()

	result := &scanner.ScanResult{
		ImageRef: "test/image:v1",
		Vulnerabilities: []types.Vulnerability{
			{ID: "CVE-2024-0001", Severity: "CRITICAL", PackageName: "pkg1"},
		},
	}

	expiredTime := time.Now().Add(-24 * time.Hour)
	tolerations := []types.CVEToleration{
		{
			ID:        "CVE-2024-0001",
			Statement: "temporary toleration",
			ExpiresAt: &expiredTime,
		},
	}

	decision, err := engine.Evaluate(ctx, "test/image:v1", result, tolerations)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if decision.Passed {
		t.Errorf("expected policy to fail (toleration expired), got passed")
	}

	if decision.CriticalVulnCount != 1 {
		t.Errorf("expected 1 critical vulnerability, got %d", decision.CriticalVulnCount)
	}

	if decision.ToleratedVulnCount != 0 {
		t.Errorf("expected 0 tolerated vulnerabilities (expired), got %d", decision.ToleratedVulnCount)
	}
}

func TestEngine_Evaluate_ActiveToleration(t *testing.T) {
	engine, err := NewEngine(slog.Default(), PolicyConfig{
		Expression: "criticalCount == 0",
	})
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}
	ctx := context.Background()

	result := &scanner.ScanResult{
		ImageRef: "test/image:v1",
		Vulnerabilities: []types.Vulnerability{
			{ID: "CVE-2024-0001", Severity: "CRITICAL", PackageName: "pkg1"},
		},
	}

	futureTime := time.Now().Add(30 * 24 * time.Hour)
	tolerations := []types.CVEToleration{
		{
			ID:        "CVE-2024-0001",
			Statement: "temporary toleration",
			ExpiresAt: &futureTime,
		},
	}

	decision, err := engine.Evaluate(ctx, "test/image:v1", result, tolerations)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !decision.Passed {
		t.Errorf("expected policy to pass (toleration active), got failed")
	}

	if decision.CriticalVulnCount != 0 {
		t.Errorf("expected 0 critical vulnerabilities, got %d", decision.CriticalVulnCount)
	}

	if decision.ToleratedVulnCount != 1 {
		t.Errorf("expected 1 tolerated vulnerability, got %d", decision.ToleratedVulnCount)
	}
}

func TestEngine_Evaluate_ExpiringTolerationWarning(t *testing.T) {
	engine, err := NewEngine(slog.Default(), PolicyConfig{
		Expression: "criticalCount == 0",
	})
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}
	ctx := context.Background()

	result := &scanner.ScanResult{
		ImageRef: "test/image:v1",
		Vulnerabilities: []types.Vulnerability{
			{ID: "CVE-2024-0001", Severity: "CRITICAL", PackageName: "pkg1"},
		},
	}

	// Toleration expires in 3 days (within 7-day warning window)
	expiringTime := time.Now().Add(3 * 24 * time.Hour)
	tolerations := []types.CVEToleration{
		{
			ID:        "CVE-2024-0001",
			Statement: "expiring soon",
			ExpiresAt: &expiringTime,
		},
	}

	decision, err := engine.Evaluate(ctx, "test/image:v1", result, tolerations)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !decision.Passed {
		t.Errorf("expected policy to pass (toleration still active), got failed")
	}

	if len(decision.ExpiringTolerations) != 1 {
		t.Errorf("expected 1 expiring toleration warning, got %d", len(decision.ExpiringTolerations))
	}

	if len(decision.ExpiringTolerations) > 0 {
		expiring := decision.ExpiringTolerations[0]
		if expiring.CVEID != "CVE-2024-0001" {
			t.Errorf("expected CVE-2024-0001, got %s", expiring.CVEID)
		}
		if expiring.DaysUntil != 2 { // 3 days = 72 hours, integer division gives 2
			t.Errorf("expected 2 days until expiry, got %d", expiring.DaysUntil)
		}
	}
}

func TestEngine_Evaluate_NoExpiringTolerationWarning(t *testing.T) {
	engine, err := NewEngine(slog.Default(), PolicyConfig{
		Expression: "criticalCount == 0",
	})
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}
	ctx := context.Background()

	result := &scanner.ScanResult{
		ImageRef: "test/image:v1",
		Vulnerabilities: []types.Vulnerability{
			{ID: "CVE-2024-0001", Severity: "CRITICAL", PackageName: "pkg1"},
		},
	}

	// Toleration expires in 30 days (outside 7-day warning window)
	futureTime := time.Now().Add(30 * 24 * time.Hour)
	tolerations := []types.CVEToleration{
		{
			ID:        "CVE-2024-0001",
			Statement: "not expiring soon",
			ExpiresAt: &futureTime,
		},
	}

	decision, err := engine.Evaluate(ctx, "test/image:v1", result, tolerations)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(decision.ExpiringTolerations) != 0 {
		t.Errorf("expected 0 expiring toleration warnings, got %d", len(decision.ExpiringTolerations))
	}
}

func TestEngine_Evaluate_PermanentToleration(t *testing.T) {
	engine, err := NewEngine(slog.Default(), PolicyConfig{
		Expression: "criticalCount == 0",
	})
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}
	ctx := context.Background()

	result := &scanner.ScanResult{
		ImageRef: "test/image:v1",
		Vulnerabilities: []types.Vulnerability{
			{ID: "CVE-2024-0001", Severity: "CRITICAL", PackageName: "pkg1"},
		},
	}

	// Toleration with no expiry date (permanent)
	tolerations := []types.CVEToleration{
		{
			ID:        "CVE-2024-0001",
			Statement: "permanent toleration",
			ExpiresAt: nil,
		},
	}

	decision, err := engine.Evaluate(ctx, "test/image:v1", result, tolerations)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !decision.Passed {
		t.Errorf("expected policy to pass (permanent toleration), got failed")
	}

	if len(decision.ExpiringTolerations) != 0 {
		t.Errorf("expected 0 expiring toleration warnings for permanent toleration, got %d", len(decision.ExpiringTolerations))
	}
}

func TestEngine_Evaluate_NilScanResult(t *testing.T) {
	engine, err := NewEngine(slog.Default(), PolicyConfig{
		Expression: "criticalCount == 0",
	})
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}
	ctx := context.Background()

	_, err = engine.Evaluate(ctx, "test/image:v1", nil, nil)
	if err == nil {
		t.Errorf("expected error for nil scan result, got nil")
	}
}

func TestEngine_Evaluate_EmptyVulnerabilities(t *testing.T) {
	engine, err := NewEngine(slog.Default(), PolicyConfig{
		Expression: "criticalCount == 0",
	})
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}
	ctx := context.Background()

	result := &scanner.ScanResult{
		ImageRef:        "test/image:v1",
		Vulnerabilities: []types.Vulnerability{},
	}

	decision, err := engine.Evaluate(ctx, "test/image:v1", result, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !decision.Passed {
		t.Errorf("expected policy to pass (no vulnerabilities), got failed")
	}

	if decision.CriticalVulnCount != 0 {
		t.Errorf("expected 0 critical vulnerabilities, got %d", decision.CriticalVulnCount)
	}
}

func TestEngine_SetExpiryWarningWindow(t *testing.T) {
	engine, err := NewEngine(slog.Default(), PolicyConfig{
		Expression: "criticalCount == 0",
	})
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}
	
	// Set custom warning window to 14 days
	engine.SetExpiryWarningWindow(14 * 24 * time.Hour)

	ctx := context.Background()
	result := &scanner.ScanResult{
		ImageRef: "test/image:v1",
		Vulnerabilities: []types.Vulnerability{
			{ID: "CVE-2024-0001", Severity: "CRITICAL", PackageName: "pkg1"},
		},
	}

	// Toleration expires in 10 days (within 14-day window)
	expiringTime := time.Now().Add(10 * 24 * time.Hour)
	tolerations := []types.CVEToleration{
		{
			ID:        "CVE-2024-0001",
			Statement: "expiring within custom window",
			ExpiresAt: &expiringTime,
		},
	}

	decision, err := engine.Evaluate(ctx, "test/image:v1", result, tolerations)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(decision.ExpiringTolerations) != 1 {
		t.Errorf("expected 1 expiring toleration warning with custom window, got %d", len(decision.ExpiringTolerations))
	}
}

// CEL-specific tests

func TestEngine_CEL_BlockHighAndCritical(t *testing.T) {
	engine, err := NewEngine(slog.Default(), PolicyConfig{
		Expression:     "criticalCount == 0 && highCount == 0",
		FailureMessage: "critical or high vulnerabilities found",
	})
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}
	ctx := context.Background()

	result := &scanner.ScanResult{
		ImageRef: "test/image:v1",
		Vulnerabilities: []types.Vulnerability{
			{ID: "CVE-2024-0001", Severity: "HIGH", PackageName: "pkg1"},
			{ID: "CVE-2024-0002", Severity: "MEDIUM", PackageName: "pkg2"},
		},
	}

	decision, err := engine.Evaluate(ctx, "test/image:v1", result, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if decision.Passed {
		t.Errorf("expected policy to fail (high vulnerability present), got passed")
	}

	if decision.Reason != "critical or high vulnerabilities found" {
		t.Errorf("expected custom failure message, got: %s", decision.Reason)
	}
}

func TestEngine_CEL_BlockMediumAndAbove(t *testing.T) {
	engine, err := NewEngine(slog.Default(), PolicyConfig{
		Expression: "criticalCount == 0 && highCount == 0 && mediumCount == 0",
	})
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}
	ctx := context.Background()

	result := &scanner.ScanResult{
		ImageRef: "test/image:v1",
		Vulnerabilities: []types.Vulnerability{
			{ID: "CVE-2024-0001", Severity: "MEDIUM", PackageName: "pkg1"},
			{ID: "CVE-2024-0002", Severity: "LOW", PackageName: "pkg2"},
		},
	}

	decision, err := engine.Evaluate(ctx, "test/image:v1", result, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if decision.Passed {
		t.Errorf("expected policy to fail (medium vulnerability present), got passed")
	}
}

func TestEngine_CEL_AllowVulnsWithoutFix(t *testing.T) {
	engine, err := NewEngine(slog.Default(), PolicyConfig{
		Expression: `vulnerabilities.filter(v, v.severity == "CRITICAL" && v.fixedVersion != "" && !v.tolerated).size() == 0`,
	})
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}
	ctx := context.Background()

	result := &scanner.ScanResult{
		ImageRef: "test/image:v1",
		Vulnerabilities: []types.Vulnerability{
			{ID: "CVE-2024-0001", Severity: "CRITICAL", PackageName: "pkg1", FixedVersion: ""},     // No fix - should pass
			{ID: "CVE-2024-0002", Severity: "CRITICAL", PackageName: "pkg2", FixedVersion: "1.2.3"}, // Has fix - should fail
		},
	}

	decision, err := engine.Evaluate(ctx, "test/image:v1", result, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if decision.Passed {
		t.Errorf("expected policy to fail (critical with fix available), got passed")
	}
}

func TestEngine_CEL_ComplexExpression(t *testing.T) {
	engine, err := NewEngine(slog.Default(), PolicyConfig{
		Expression: `(criticalCount == 0 && highCount <= 2) || toleratedCount >= 5`,
	})
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}
	ctx := context.Background()

	result := &scanner.ScanResult{
		ImageRef: "test/image:v1",
		Vulnerabilities: []types.Vulnerability{
			{ID: "CVE-2024-0001", Severity: "HIGH", PackageName: "pkg1"},
			{ID: "CVE-2024-0002", Severity: "HIGH", PackageName: "pkg2"},
		},
	}

	decision, err := engine.Evaluate(ctx, "test/image:v1", result, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !decision.Passed {
		t.Errorf("expected policy to pass (2 high vulns allowed), got failed")
	}
}

func TestEngine_CEL_InvalidExpression(t *testing.T) {
	_, err := NewEngine(slog.Default(), PolicyConfig{
		Expression: "invalid syntax here!",
	})
	if err == nil {
		t.Errorf("expected error for invalid CEL expression, got nil")
	}
}

func TestEngine_CEL_NonBooleanExpression(t *testing.T) {
	_, err := NewEngine(slog.Default(), PolicyConfig{
		Expression: "criticalCount + highCount", // Returns int, not bool
	})
	if err == nil {
		t.Errorf("expected error for non-boolean expression, got nil")
	}
}

func TestEngine_CEL_DefaultPolicy(t *testing.T) {
	// Test that empty config gets default policy
	engine, err := NewEngine(slog.Default(), PolicyConfig{})
	if err != nil {
		t.Fatalf("failed to create engine with default policy: %v", err)
	}

	ctx := context.Background()
	result := &scanner.ScanResult{
		ImageRef: "test/image:v1",
		Vulnerabilities: []types.Vulnerability{
			{ID: "CVE-2024-0001", Severity: "HIGH", PackageName: "pkg1"},
		},
	}

	decision, err := engine.Evaluate(ctx, "test/image:v1", result, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Default policy should only block critical
	if !decision.Passed {
		t.Errorf("expected default policy to pass (only high vuln), got failed")
	}
}

func TestEngine_Evaluate_MixedExpiredAndActiveTolerations(t *testing.T) {
	engine, err := NewEngine(slog.Default(), PolicyConfig{
		Expression: "criticalCount == 0",
	})
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}
	ctx := context.Background()

	result := &scanner.ScanResult{
		ImageRef: "test/image:v1",
		Vulnerabilities: []types.Vulnerability{
			{ID: "CVE-2024-0001", Severity: "CRITICAL", PackageName: "pkg1"},
			{ID: "CVE-2024-0002", Severity: "CRITICAL", PackageName: "pkg2"},
			{ID: "CVE-2024-0003", Severity: "CRITICAL", PackageName: "pkg3"},
			{ID: "CVE-2024-0004", Severity: "HIGH", PackageName: "pkg4"},
		},
	}

	expiredTime := time.Now().Add(-24 * time.Hour)
	futureTime := time.Now().Add(30 * 24 * time.Hour)
	
	tolerations := []types.CVEToleration{
		{
			ID:        "CVE-2024-0001",
			Statement: "expired toleration",
			ExpiresAt: &expiredTime,
		},
		{
			ID:        "CVE-2024-0002",
			Statement: "active toleration",
			ExpiresAt: &futureTime,
		},
		{
			ID:        "CVE-2024-0003",
			Statement: "permanent toleration",
			ExpiresAt: nil,
		},
	}

	decision, err := engine.Evaluate(ctx, "test/image:v1", result, tolerations)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should fail because CVE-2024-0001 toleration is expired (1 critical remains)
	if decision.Passed {
		t.Errorf("expected policy to fail (1 critical with expired toleration), got passed")
	}

	// Should have 1 critical (CVE-2024-0001 with expired toleration)
	if decision.CriticalVulnCount != 1 {
		t.Errorf("expected 1 critical vulnerability, got %d", decision.CriticalVulnCount)
	}

	// Should have 2 tolerated (CVE-2024-0002 and CVE-2024-0003)
	if decision.ToleratedVulnCount != 2 {
		t.Errorf("expected 2 tolerated vulnerabilities, got %d", decision.ToleratedVulnCount)
	}

	// Check that only active tolerations are in the list
	if len(decision.ToleratedCVEs) != 2 {
		t.Errorf("expected 2 tolerated CVE IDs, got %d", len(decision.ToleratedCVEs))
	}

	// Verify the expired CVE is not in the tolerated list
	for _, cveID := range decision.ToleratedCVEs {
		if cveID == "CVE-2024-0001" {
			t.Errorf("expired CVE-2024-0001 should not be in tolerated list")
		}
	}
}

func TestEngine_Evaluate_AllTolerationsExpired(t *testing.T) {
	engine, err := NewEngine(slog.Default(), PolicyConfig{
		Expression: "criticalCount == 0 && highCount == 0",
	})
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}
	ctx := context.Background()

	result := &scanner.ScanResult{
		ImageRef: "test/image:v1",
		Vulnerabilities: []types.Vulnerability{
			{ID: "CVE-2024-0001", Severity: "CRITICAL", PackageName: "pkg1"},
			{ID: "CVE-2024-0002", Severity: "HIGH", PackageName: "pkg2"},
		},
	}

	expiredTime1 := time.Now().Add(-48 * time.Hour)
	expiredTime2 := time.Now().Add(-1 * time.Hour)
	
	tolerations := []types.CVEToleration{
		{
			ID:        "CVE-2024-0001",
			Statement: "expired 2 days ago",
			ExpiresAt: &expiredTime1,
		},
		{
			ID:        "CVE-2024-0002",
			Statement: "expired 1 hour ago",
			ExpiresAt: &expiredTime2,
		},
	}

	decision, err := engine.Evaluate(ctx, "test/image:v1", result, tolerations)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should fail because all tolerations are expired
	if decision.Passed {
		t.Errorf("expected policy to fail (all tolerations expired), got passed")
	}

	// Should have 1 critical and 1 high (no active tolerations)
	if decision.CriticalVulnCount != 1 {
		t.Errorf("expected 1 critical vulnerability, got %d", decision.CriticalVulnCount)
	}

	// Should have 0 tolerated (all expired)
	if decision.ToleratedVulnCount != 0 {
		t.Errorf("expected 0 tolerated vulnerabilities, got %d", decision.ToleratedVulnCount)
	}

	if len(decision.ToleratedCVEs) != 0 {
		t.Errorf("expected 0 tolerated CVE IDs, got %d", len(decision.ToleratedCVEs))
	}
}

func TestEngine_Evaluate_ExpiredTolerationWithCELFilter(t *testing.T) {
	// Test that expired tolerations work correctly with CEL expressions that reference tolerated field
	engine, err := NewEngine(slog.Default(), PolicyConfig{
		Expression: `vulnerabilities.filter(v, v.severity == "CRITICAL" && !v.tolerated).size() == 0`,
	})
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}
	ctx := context.Background()

	result := &scanner.ScanResult{
		ImageRef: "test/image:v1",
		Vulnerabilities: []types.Vulnerability{
			{ID: "CVE-2024-0001", Severity: "CRITICAL", PackageName: "pkg1"},
			{ID: "CVE-2024-0002", Severity: "CRITICAL", PackageName: "pkg2"},
		},
	}

	expiredTime := time.Now().Add(-24 * time.Hour)
	futureTime := time.Now().Add(30 * 24 * time.Hour)
	
	tolerations := []types.CVEToleration{
		{
			ID:        "CVE-2024-0001",
			Statement: "expired toleration",
			ExpiresAt: &expiredTime,
		},
		{
			ID:        "CVE-2024-0002",
			Statement: "active toleration",
			ExpiresAt: &futureTime,
		},
	}

	decision, err := engine.Evaluate(ctx, "test/image:v1", result, tolerations)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should fail because CVE-2024-0001 has expired toleration and is not marked as tolerated
	if decision.Passed {
		t.Errorf("expected policy to fail (1 critical not tolerated due to expiry), got passed")
	}

	// Only CVE-2024-0002 should be tolerated
	if decision.ToleratedVulnCount != 1 {
		t.Errorf("expected 1 tolerated vulnerability, got %d", decision.ToleratedVulnCount)
	}
}
