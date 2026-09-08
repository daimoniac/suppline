package worker

import (
	"strings"
	"testing"
	"time"

	"github.com/daimoniac/suppline/internal/config"
	supperrors "github.com/daimoniac/suppline/internal/errors"
	"github.com/daimoniac/suppline/internal/observability"
	"github.com/daimoniac/suppline/internal/policy"
	"github.com/daimoniac/suppline/internal/types"
)

// Repository policy resolution is the one place where an unparseable
// minimumReleaseAge must surface, and it must stay a permanent error so the
// task is not retried.
func TestGetPolicyEngineForRepository_InvalidMinimumReleaseAge(t *testing.T) {
	logger := observability.NewLogger("error")
	defaultEngine, err := policy.NewEngine(logger, policy.PolicyConfig{Expression: "criticalCount == 0"})
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	regsyncCfg := &config.RegsyncConfig{
		Sync: []config.SyncEntry{{
			Target: "myorg/app",
			Type:   "repository",
			Policy: &config.PolicyConfig{Expression: "criticalCount == 0", MinimumReleaseAge: "not-a-duration"},
			VEX:    []types.VEXStatement{{ID: "CVE-2024-1234", State: types.VEXStateNotAffected}},
		}},
	}
	worker := NewImageWorker(newMockQueue(1), nil, defaultEngine, nil, nil, nil, DefaultConfig(), logger, regsyncCfg)

	engine, err := worker.pipeline.getPolicyEngineForRepository("myorg/app")
	if err == nil {
		t.Fatalf("getPolicyEngineForRepository() error = nil, want invalid minimumReleaseAge error (engine %+v)", engine)
	}
	if !strings.Contains(err.Error(), "failed to resolve minimum release age for myorg/app") {
		t.Errorf("error = %v, want target-specific minimum release age failure", err)
	}
	if !strings.Contains(err.Error(), "invalid minimumReleaseAge for target myorg/app") {
		t.Errorf("error = %v, want wrapped catalog parse error", err)
	}
	if !supperrors.IsPermanent(err) {
		t.Errorf("error = %v, want permanent classification", err)
	}

	// The same repository's exemption evidence stays usable for SCAI.
	exempted, statement := worker.policyCatalog.IsExempted("myorg/app", "CVE-2024-1234", time.Now())
	if !exempted || statement == nil {
		t.Errorf("IsExempted() = %t (%+v), want exempted statement", exempted, statement)
	}
	if got := strings.Join(worker.policyCatalog.StatementIDs(), ","); got != "CVE-2024-1234" {
		t.Errorf("StatementIDs() = %q, want CVE-2024-1234", got)
	}
}
