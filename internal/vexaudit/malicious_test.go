package vexaudit

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/daimoniac/suppline/internal/policy"
	"github.com/daimoniac/suppline/internal/statestore"
	"github.com/daimoniac/suppline/internal/types"
)

func auditMalicious(t *testing.T, statements []types.VEXStatement, check *types.MaliciousCheck) []Finding {
	t.Helper()
	auditor := New(slog.New(slog.NewTextHandler(io.Discard, nil)),
		fakeCatalog{statements: statements, policy: policy.PolicyConfig{Expression: "criticalCount == 0"}},
		fakeScans{
			records: []*statestore.ScanRecord{{ID: 7, Repository: testRepository, Digest: "sha256:one", Tag: "v1", CreatedAt: time.Now().Unix(), PolicyStatus: "passed", Malicious: check}},
			vulns:   map[int64][]types.VulnerabilityRecord{},
		},
		engineFor,
	)
	findings, err := auditor.Audit(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return findings
}

func TestAuditMaliciousStatementsByPresence(t *testing.T) {
	statements := []types.VEXStatement{
		{ID: "MAL-PRESENT", State: types.VEXStateFalsePositive, Source: types.VEXSourceManual},
		{ID: "MAL-GONE", State: types.VEXStateFalsePositive, Source: types.VEXSourceManual, Detail: "workspace package"},
		{ID: "MAL-EXPIRED", State: types.VEXStateFalsePositive, Source: types.VEXSourceManual, ExpiresAt: expiredAt(time.Now())},
	}
	check := &types.MaliciousCheck{Status: types.MaliciousCheckOK, Findings: []types.MaliciousFinding{{ID: "MAL-PRESENT", Exempted: true}}}

	findings := auditMalicious(t, statements, check)
	if len(findings) != 1 || findings[0].CVEID != "MAL-GONE" || findings[0].State != "false_positive" || findings[0].Detail != "workspace package" {
		t.Fatalf("want only MAL-GONE as unused, got %+v", findings)
	}
}

func TestAuditMaliciousStatementsNeedACheckedScan(t *testing.T) {
	statements := []types.VEXStatement{{ID: "MAL-GONE", State: types.VEXStateFalsePositive, Source: types.VEXSourceManual}}
	for _, check := range []*types.MaliciousCheck{nil, {Status: types.MaliciousCheckUnavailable}} {
		if findings := auditMalicious(t, statements, check); len(findings) != 0 {
			t.Fatalf("no checked scan is no evidence, got %+v", findings)
		}
	}
}
