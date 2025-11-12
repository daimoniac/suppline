package policy

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/suppline/suppline/internal/regsync"
	"github.com/suppline/suppline/internal/scanner"
)

func TestEngine_Evaluate_NoCriticalVulnerabilities(t *testing.T) {
	engine := NewEngine(slog.Default())
	ctx := context.Background()

	result := &scanner.ScanResult{
		ImageRef: "test/image:v1",
		Vulnerabilities: []scanner.Vulnerability{
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
	engine := NewEngine(slog.Default())
	ctx := context.Background()

	result := &scanner.ScanResult{
		ImageRef: "test/image:v1",
		Vulnerabilities: []scanner.Vulnerability{
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
	engine := NewEngine(slog.Default())
	ctx := context.Background()

	result := &scanner.ScanResult{
		ImageRef: "test/image:v1",
		Vulnerabilities: []scanner.Vulnerability{
			{ID: "CVE-2024-0001", Severity: "CRITICAL", PackageName: "pkg1"},
			{ID: "CVE-2024-0002", Severity: "CRITICAL", PackageName: "pkg2"},
			{ID: "CVE-2024-0003", Severity: "CRITICAL", PackageName: "pkg3"},
		},
	}

	tolerations := []regsync.CVEToleration{
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
	engine := NewEngine(slog.Default())
	ctx := context.Background()

	result := &scanner.ScanResult{
		ImageRef: "test/image:v1",
		Vulnerabilities: []scanner.Vulnerability{
			{ID: "CVE-2024-0001", Severity: "CRITICAL", PackageName: "pkg1"},
			{ID: "CVE-2024-0002", Severity: "CRITICAL", PackageName: "pkg2"},
		},
	}

	tolerations := []regsync.CVEToleration{
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
	engine := NewEngine(slog.Default())
	ctx := context.Background()

	result := &scanner.ScanResult{
		ImageRef: "test/image:v1",
		Vulnerabilities: []scanner.Vulnerability{
			{ID: "CVE-2024-0001", Severity: "CRITICAL", PackageName: "pkg1"},
		},
	}

	expiredTime := time.Now().Add(-24 * time.Hour)
	tolerations := []regsync.CVEToleration{
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
	engine := NewEngine(slog.Default())
	ctx := context.Background()

	result := &scanner.ScanResult{
		ImageRef: "test/image:v1",
		Vulnerabilities: []scanner.Vulnerability{
			{ID: "CVE-2024-0001", Severity: "CRITICAL", PackageName: "pkg1"},
		},
	}

	futureTime := time.Now().Add(30 * 24 * time.Hour)
	tolerations := []regsync.CVEToleration{
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
	engine := NewEngine(slog.Default())
	ctx := context.Background()

	result := &scanner.ScanResult{
		ImageRef: "test/image:v1",
		Vulnerabilities: []scanner.Vulnerability{
			{ID: "CVE-2024-0001", Severity: "CRITICAL", PackageName: "pkg1"},
		},
	}

	// Toleration expires in 3 days (within 7-day warning window)
	expiringTime := time.Now().Add(3 * 24 * time.Hour)
	tolerations := []regsync.CVEToleration{
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
	engine := NewEngine(slog.Default())
	ctx := context.Background()

	result := &scanner.ScanResult{
		ImageRef: "test/image:v1",
		Vulnerabilities: []scanner.Vulnerability{
			{ID: "CVE-2024-0001", Severity: "CRITICAL", PackageName: "pkg1"},
		},
	}

	// Toleration expires in 30 days (outside 7-day warning window)
	futureTime := time.Now().Add(30 * 24 * time.Hour)
	tolerations := []regsync.CVEToleration{
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
	engine := NewEngine(slog.Default())
	ctx := context.Background()

	result := &scanner.ScanResult{
		ImageRef: "test/image:v1",
		Vulnerabilities: []scanner.Vulnerability{
			{ID: "CVE-2024-0001", Severity: "CRITICAL", PackageName: "pkg1"},
		},
	}

	// Toleration with no expiry date (permanent)
	tolerations := []regsync.CVEToleration{
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
	engine := NewEngine(slog.Default())
	ctx := context.Background()

	_, err := engine.Evaluate(ctx, "test/image:v1", nil, nil)
	if err == nil {
		t.Errorf("expected error for nil scan result, got nil")
	}
}

func TestEngine_Evaluate_EmptyVulnerabilities(t *testing.T) {
	engine := NewEngine(slog.Default())
	ctx := context.Background()

	result := &scanner.ScanResult{
		ImageRef:        "test/image:v1",
		Vulnerabilities: []scanner.Vulnerability{},
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
	engine := NewEngine(slog.Default())
	
	// Set custom warning window to 14 days
	engine.SetExpiryWarningWindow(14 * 24 * time.Hour)

	ctx := context.Background()
	result := &scanner.ScanResult{
		ImageRef: "test/image:v1",
		Vulnerabilities: []scanner.Vulnerability{
			{ID: "CVE-2024-0001", Severity: "CRITICAL", PackageName: "pkg1"},
		},
	}

	// Toleration expires in 10 days (within 14-day window)
	expiringTime := time.Now().Add(10 * 24 * time.Hour)
	tolerations := []regsync.CVEToleration{
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
