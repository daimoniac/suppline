package policy

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/daimoniac/suppline/internal/scanner"
	"github.com/daimoniac/suppline/internal/types"
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

	if !decision.ShouldAttest {
		t.Errorf("expected ShouldAttest to be true")
	}

	if decision.CriticalVulnCount != 2 {
		t.Errorf("expected 2 critical vulnerabilities, got %d", decision.CriticalVulnCount)
	}
}

func TestEngine_Evaluate_ExemptedCVEs(t *testing.T) {
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

	vexStatements := []types.VEXStatement{
		{
			ID:     "CVE-2024-0001",
			State:  types.VEXStateNotAffected,
			Detail: "accepted risk, no fix available",
		},
		{
			ID:     "CVE-2024-0002",
			State:  types.VEXStateNotAffected,
			Detail: "temporary VEX statement",
		},
	}

	decision, err := engine.Evaluate(ctx, "test/image:v1", result, vexStatements)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if decision.Passed {
		t.Errorf("expected policy to fail (1 critical remaining), got passed")
	}

	if decision.CriticalVulnCount != 1 {
		t.Errorf("expected 1 critical vulnerability, got %d", decision.CriticalVulnCount)
	}

	if decision.ExemptedVulnCount != 2 {
		t.Errorf("expected 2 exempted vulnerabilities, got %d", decision.ExemptedVulnCount)
	}

	if len(decision.ExemptedCVEs) != 2 {
		t.Errorf("expected 2 exempted CVE IDs, got %d", len(decision.ExemptedCVEs))
	}
}

func TestEngine_Evaluate_AllCriticalVulnerabilitiesExempted(t *testing.T) {
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

	vexStatements := []types.VEXStatement{
		{
			ID:     "CVE-2024-0001",
			State:  types.VEXStateNotAffected,
			Detail: "accepted risk",
		},
		{
			ID:     "CVE-2024-0002",
			State:  types.VEXStateNotAffected,
			Detail: "no fix available",
		},
	}

	decision, err := engine.Evaluate(ctx, "test/image:v1", result, vexStatements)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !decision.Passed {
		t.Errorf("expected policy to pass (all critical exempted), got failed")
	}

	if decision.CriticalVulnCount != 0 {
		t.Errorf("expected 0 critical vulnerabilities, got %d", decision.CriticalVulnCount)
	}

	if decision.ExemptedVulnCount != 2 {
		t.Errorf("expected 2 exempted vulnerabilities, got %d", decision.ExemptedVulnCount)
	}
}

func TestEngine_Evaluate_ExpiredVEXStatement(t *testing.T) {
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

	expiredTime := time.Now().Add(-24 * time.Hour).Unix()
	vexStatements := []types.VEXStatement{
		{
			ID:        "CVE-2024-0001",
			State:     types.VEXStateNotAffected,
			Detail:    "temporary VEX statement",
			ExpiresAt: &expiredTime,
		},
	}

	decision, err := engine.Evaluate(ctx, "test/image:v1", result, vexStatements)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if decision.Passed {
		t.Errorf("expected policy to fail (VEX statement expired), got passed")
	}

	if decision.CriticalVulnCount != 1 {
		t.Errorf("expected 1 critical vulnerability, got %d", decision.CriticalVulnCount)
	}

	if decision.ExemptedVulnCount != 0 {
		t.Errorf("expected 0 exempted vulnerabilities (expired), got %d", decision.ExemptedVulnCount)
	}
}

func TestEngine_Evaluate_ActiveVEXStatement(t *testing.T) {
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

	futureTime := time.Now().Add(30 * 24 * time.Hour).Unix()
	vexStatements := []types.VEXStatement{
		{
			ID:        "CVE-2024-0001",
			State:     types.VEXStateNotAffected,
			Detail:    "temporary VEX statement",
			ExpiresAt: &futureTime,
		},
	}

	decision, err := engine.Evaluate(ctx, "test/image:v1", result, vexStatements)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !decision.Passed {
		t.Errorf("expected policy to pass (VEX statement active), got failed")
	}

	if decision.CriticalVulnCount != 0 {
		t.Errorf("expected 0 critical vulnerabilities, got %d", decision.CriticalVulnCount)
	}

	if decision.ExemptedVulnCount != 1 {
		t.Errorf("expected 1 exempted vulnerability, got %d", decision.ExemptedVulnCount)
	}
}

func TestEngine_Evaluate_ExpiringVEXStatementWarning(t *testing.T) {
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

	// VEX statement expires in 3 days (within 7-day warning window)
	expiringTime := time.Now().Add(3 * 24 * time.Hour).Unix()
	vexStatements := []types.VEXStatement{
		{
			ID:        "CVE-2024-0001",
			State:     types.VEXStateNotAffected,
			Detail:    "expiring soon",
			ExpiresAt: &expiringTime,
		},
	}

	decision, err := engine.Evaluate(ctx, "test/image:v1", result, vexStatements)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !decision.Passed {
		t.Errorf("expected policy to pass (VEX statement still active), got failed")
	}

	if len(decision.ExpiringVEXStatements) != 1 {
		t.Errorf("expected 1 expiring VEX statement warning, got %d", len(decision.ExpiringVEXStatements))
	}

	if len(decision.ExpiringVEXStatements) > 0 {
		expiring := decision.ExpiringVEXStatements[0]
		if expiring.CVEID != "CVE-2024-0001" {
			t.Errorf("expected CVE-2024-0001, got %s", expiring.CVEID)
		}
		if expiring.DaysUntil != 3 { // 3 days = 72 hours, integer division gives 3
			t.Errorf("expected 3 days until expiry, got %d", expiring.DaysUntil)
		}
	}
}

func TestEngine_Evaluate_NoExpiringVEXStatementWarning(t *testing.T) {
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

	// VEX statement expires in 30 days (outside 7-day warning window)
	futureTime := time.Now().Add(30 * 24 * time.Hour).Unix()
	vexStatements := []types.VEXStatement{
		{
			ID:        "CVE-2024-0001",
			State:     types.VEXStateNotAffected,
			Detail:    "not expiring soon",
			ExpiresAt: &futureTime,
		},
	}

	decision, err := engine.Evaluate(ctx, "test/image:v1", result, vexStatements)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(decision.ExpiringVEXStatements) != 0 {
		t.Errorf("expected 0 expiring VEX statement warnings, got %d", len(decision.ExpiringVEXStatements))
	}
}

func TestEngine_Evaluate_PermanentVEXStatement(t *testing.T) {
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

	// VEX statement with no expiry date (permanent)
	vexStatements := []types.VEXStatement{
		{
			ID:        "CVE-2024-0001",
			State:     types.VEXStateNotAffected,
			Detail:    "permanent VEX statement",
			ExpiresAt: nil,
		},
	}

	decision, err := engine.Evaluate(ctx, "test/image:v1", result, vexStatements)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !decision.Passed {
		t.Errorf("expected policy to pass (permanent VEX statement), got failed")
	}

	if len(decision.ExpiringVEXStatements) != 0 {
		t.Errorf("expected 0 expiring VEX statement warnings for permanent VEX statement, got %d", len(decision.ExpiringVEXStatements))
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

	// VEX statement expires in 10 days (within 14-day window)
	expiringTime := time.Now().Add(10 * 24 * time.Hour).Unix()
	vexStatements := []types.VEXStatement{
		{
			ID:        "CVE-2024-0001",
			State:     types.VEXStateNotAffected,
			Detail:    "expiring within custom window",
			ExpiresAt: &expiringTime,
		},
	}

	decision, err := engine.Evaluate(ctx, "test/image:v1", result, vexStatements)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(decision.ExpiringVEXStatements) != 1 {
		t.Errorf("expected 1 expiring VEX statement warning with custom window, got %d", len(decision.ExpiringVEXStatements))
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
		Expression: `vulnerabilities.filter(v, v.severity == "CRITICAL" && v.fixedVersion != "" && !v.exempted).size() == 0`,
	})
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}
	ctx := context.Background()

	result := &scanner.ScanResult{
		ImageRef: "test/image:v1",
		Vulnerabilities: []types.Vulnerability{
			{ID: "CVE-2024-0001", Severity: "CRITICAL", PackageName: "pkg1", FixedVersion: ""},      // No fix - should pass
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
		Expression: `(criticalCount == 0 && highCount <= 2) || exemptedCount >= 5`,
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

func TestEngine_Evaluate_MixedExpiredAndActiveVEXStatements(t *testing.T) {
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

	expiredTime := time.Now().Add(-24 * time.Hour).Unix()
	futureTime := time.Now().Add(30 * 24 * time.Hour).Unix()

	vexStatements := []types.VEXStatement{
		{
			ID:        "CVE-2024-0001",
			State:     types.VEXStateNotAffected,
			Detail:    "expired VEX statement",
			ExpiresAt: &expiredTime,
		},
		{
			ID:        "CVE-2024-0002",
			State:     types.VEXStateNotAffected,
			Detail:    "active VEX statement",
			ExpiresAt: &futureTime,
		},
		{
			ID:        "CVE-2024-0003",
			State:     types.VEXStateNotAffected,
			Detail:    "permanent VEX statement",
			ExpiresAt: nil,
		},
	}

	decision, err := engine.Evaluate(ctx, "test/image:v1", result, vexStatements)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should fail because CVE-2024-0001 VEX statement is expired (1 critical remains)
	if decision.Passed {
		t.Errorf("expected policy to fail (1 critical with expired VEX statement), got passed")
	}

	// Should have 1 critical (CVE-2024-0001 with expired VEX statement)
	if decision.CriticalVulnCount != 1 {
		t.Errorf("expected 1 critical vulnerability, got %d", decision.CriticalVulnCount)
	}

	// Should have 2 exempted (CVE-2024-0002 and CVE-2024-0003)
	if decision.ExemptedVulnCount != 2 {
		t.Errorf("expected 2 exempted vulnerabilities, got %d", decision.ExemptedVulnCount)
	}

	// Check that only active VEX statements are in the list
	if len(decision.ExemptedCVEs) != 2 {
		t.Errorf("expected 2 exempted CVE IDs, got %d", len(decision.ExemptedCVEs))
	}

	// Verify the expired CVE is not in the exempted list
	for _, cveID := range decision.ExemptedCVEs {
		if cveID == "CVE-2024-0001" {
			t.Errorf("expired CVE-2024-0001 should not be in exempted list")
		}
	}
}

func TestEngine_Evaluate_AllVEXStatementsExpired(t *testing.T) {
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

	expiredTime1 := time.Now().Add(-48 * time.Hour).Unix()
	expiredTime2 := time.Now().Add(-1 * time.Hour).Unix()

	vexStatements := []types.VEXStatement{
		{
			ID:        "CVE-2024-0001",
			State:     types.VEXStateNotAffected,
			Detail:    "expired 2 days ago",
			ExpiresAt: &expiredTime1,
		},
		{
			ID:        "CVE-2024-0002",
			State:     types.VEXStateNotAffected,
			Detail:    "expired 1 hour ago",
			ExpiresAt: &expiredTime2,
		},
	}

	decision, err := engine.Evaluate(ctx, "test/image:v1", result, vexStatements)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should fail because all VEX statements are expired
	if decision.Passed {
		t.Errorf("expected policy to fail (all VEX statements expired), got passed")
	}

	// Should have 1 critical and 1 high (no active VEX statements)
	if decision.CriticalVulnCount != 1 {
		t.Errorf("expected 1 critical vulnerability, got %d", decision.CriticalVulnCount)
	}

	// Should have 0 exempted (all expired)
	if decision.ExemptedVulnCount != 0 {
		t.Errorf("expected 0 exempted vulnerabilities, got %d", decision.ExemptedVulnCount)
	}

	if len(decision.ExemptedCVEs) != 0 {
		t.Errorf("expected 0 exempted CVE IDs, got %d", len(decision.ExemptedCVEs))
	}
}

func TestEngine_Evaluate_ExpiredVEXStatementWithCELFilter(t *testing.T) {
	// Test that expired VEX statements work correctly with CEL expressions that reference exempted field.
	engine, err := NewEngine(slog.Default(), PolicyConfig{
		Expression: `vulnerabilities.filter(v, v.severity == "CRITICAL" && !v.exempted).size() == 0`,
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

	expiredTime := time.Now().Add(-24 * time.Hour).Unix()
	futureTime := time.Now().Add(30 * 24 * time.Hour).Unix()

	vexStatements := []types.VEXStatement{
		{
			ID:        "CVE-2024-0001",
			State:     types.VEXStateNotAffected,
			Detail:    "expired VEX statement",
			ExpiresAt: &expiredTime,
		},
		{
			ID:        "CVE-2024-0002",
			State:     types.VEXStateNotAffected,
			Detail:    "active VEX statement",
			ExpiresAt: &futureTime,
		},
	}

	decision, err := engine.Evaluate(ctx, "test/image:v1", result, vexStatements)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should fail because CVE-2024-0001 has expired VEX statement and is not marked as exempted
	if decision.Passed {
		t.Errorf("expected policy to fail (1 critical not exempted due to expiry), got passed")
	}

	// Only CVE-2024-0002 should be exempted
	if decision.ExemptedVulnCount != 1 {
		t.Errorf("expected 1 exempted vulnerability, got %d", decision.ExemptedVulnCount)
	}
}

func TestEngine_Evaluate_MinimumReleaseAgePendingFromImageCreatedAt(t *testing.T) {
	engine, err := NewEngine(slog.Default(), PolicyConfig{
		Expression:        "criticalCount == 0",
		MinimumReleaseAge: 7 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}

	now := time.Now().UTC()
	createdAt := now.Add(-48 * time.Hour)

	result := &scanner.ScanResult{
		ImageRef:        "test/image:v1",
		Vulnerabilities: []types.Vulnerability{},
		ScannedAt:       now,
		ImageCreatedAt:  &createdAt,
	}

	decision, err := engine.Evaluate(context.Background(), "test/image:v1", result, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if decision.Status != PolicyStatusPending {
		t.Fatalf("expected pending status, got %s", decision.Status)
	}

	if decision.Passed {
		t.Fatalf("expected pending decision to be non-passing")
	}

	if decision.ShouldAttest {
		t.Fatalf("expected pending decision to disable attestation")
	}

	if decision.ReleaseAgeSource != "image_created_at" {
		t.Fatalf("expected release age source image_created_at, got %s", decision.ReleaseAgeSource)
	}

	if decision.ReleaseAgeSeconds <= 0 {
		t.Fatalf("expected release age seconds to be populated")
	}

	if decision.MinimumReleaseAgeSeconds != int64((7 * 24 * time.Hour).Seconds()) {
		t.Fatalf("expected minimum release age seconds to match config")
	}
}

func TestEngine_Evaluate_MinimumReleaseAgeUsesFirstSeenFallback(t *testing.T) {
	engine, err := NewEngine(slog.Default(), PolicyConfig{
		Expression:        "criticalCount == 0",
		MinimumReleaseAge: 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}

	now := time.Now().UTC()
	firstSeen := now.Add(-48 * time.Hour)

	result := &scanner.ScanResult{
		ImageRef:        "test/image:v1",
		Vulnerabilities: []types.Vulnerability{},
		ScannedAt:       now,
		FirstSeenAt:     &firstSeen,
	}

	decision, err := engine.Evaluate(context.Background(), "test/image:v1", result, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if decision.Status != PolicyStatusPassed {
		t.Fatalf("expected passed status from first_seen fallback, got %s", decision.Status)
	}

	if !decision.Passed {
		t.Fatalf("expected policy pass with adequate first_seen age")
	}

	if decision.ReleaseAgeSource != "first_seen" {
		t.Fatalf("expected first_seen source, got %s", decision.ReleaseAgeSource)
	}
}
