package catalog

import (
	"strings"
	"testing"
	"time"

	"github.com/daimoniac/suppline/internal/config"
	"github.com/daimoniac/suppline/internal/policy"
	"github.com/daimoniac/suppline/internal/types"
)

func boolPointer(value bool) *bool { return &value }

func TestConfigCatalogResolve(t *testing.T) {
	cfg := &config.RegsyncConfig{
		Defaults: config.Defaults{
			Policy: &config.PolicyConfig{
				Expression:     "criticalCount == 0",
				FailureMessage: "default failure",
			},
			Cooldown: "24h",
			VEXRepo:  boolPointer(true),
			VEX: []types.VEXStatement{
				{ID: "CVE-shared", Detail: "default wins"},
				{ID: "CVE-default"},
			},
		},
		Sync: []config.SyncEntry{
			{
				Target:   "registry.example/team/app:1.2.3",
				Type:     "image",
				Policy:   &config.PolicyConfig{Expression: "highCount == 0", FailureMessage: "override failure"},
				Cooldown: "2d",
				VEXRepo:  boolPointer(false),
				VEX: []types.VEXStatement{
					{ID: "CVE-shared", Detail: "repository duplicate"},
					{ID: "CVE-app"},
				},
			},
			{Target: "registry.example/team/other", Type: "repository"},
		},
	}
	subject := NewConfigCatalog(cfg)

	tests := []struct {
		name           string
		repository     string
		wantExpression string
		wantFailure    string
		wantCooldown   time.Duration
		wantVEXRepo    bool
		wantStatements []string
	}{
		{
			name:           "image target is normalized and override replaces policy",
			repository:     "registry.example/team/app",
			wantExpression: "highCount == 0",
			wantFailure:    "override failure",
			wantCooldown:   48 * time.Hour,
			wantStatements: []string{"CVE-shared", "CVE-default", "CVE-app"},
		},
		{
			name:           "repository inherits defaults",
			repository:     "registry.example/team/other",
			wantExpression: "criticalCount == 0",
			wantFailure:    "default failure",
			wantCooldown:   24 * time.Hour,
			wantVEXRepo:    true,
			wantStatements: []string{"CVE-shared", "CVE-default"},
		},
		{
			name:           "unknown repository gets defaults",
			repository:     "registry.example/team/unknown",
			wantExpression: "criticalCount == 0",
			wantFailure:    "default failure",
			wantCooldown:   24 * time.Hour,
			wantVEXRepo:    true,
			wantStatements: []string{"CVE-shared", "CVE-default"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			gotPolicy, err := subject.ResolvePolicy(test.repository)
			if err != nil {
				t.Fatalf("ResolvePolicy() error = %v", err)
			}
			if gotPolicy.Expression != test.wantExpression || gotPolicy.FailureMessage != test.wantFailure {
				t.Errorf("policy = %+v, want expression %q and failure %q", gotPolicy, test.wantExpression, test.wantFailure)
			}
			if gotPolicy.Cooldown != test.wantCooldown {
				t.Errorf("cooldown = %v, want %v", gotPolicy.Cooldown, test.wantCooldown)
			}
			if got := subject.ResolveExpression(test.repository); got != test.wantExpression {
				t.Errorf("ResolveExpression() = %q, want %q", got, test.wantExpression)
			}

			gotEvidence := subject.ResolveEvidence(test.repository)
			if gotEvidence.UseVEXRepo != test.wantVEXRepo {
				t.Errorf("UseVEXRepo = %t, want %t", gotEvidence.UseVEXRepo, test.wantVEXRepo)
			}
			var statementIDs []string
			for _, statement := range gotEvidence.VEXStatements {
				statementIDs = append(statementIDs, statement.ID)
			}
			if strings.Join(statementIDs, ",") != strings.Join(test.wantStatements, ",") {
				t.Errorf("statement IDs = %v, want %v", statementIDs, test.wantStatements)
			}
			if test.repository == "registry.example/team/app" && gotEvidence.VEXStatements[0].Detail != "default wins" {
				t.Errorf("duplicate statement detail = %q, want default precedence", gotEvidence.VEXStatements[0].Detail)
			}
		})
	}
}

// Before the catalog existed, only minimum release age resolution could fail.
// Exemption evidence and the configured expression must stay available so that
// one repository's unparseable duration cannot disable VEX everywhere.
func TestConfigCatalogAutoVEXLosesToManual(t *testing.T) {
	cfg := &config.RegsyncConfig{
		Sync: []config.SyncEntry{{
			Target: "registry.example/app",
			Type:   "repository",
			VEX: []types.VEXStatement{{
				ID:     "CVE-shared",
				State:  types.VEXStateNotAffected,
				Detail: "human",
			}},
			VEXAuto: []types.VEXStatement{{
				ID:     "CVE-shared",
				State:  types.VEXStateNotAffected,
				Detail: "auto",
			}, {
				ID:     "CVE-auto",
				State:  types.VEXStateAffected,
				Detail: "generated",
			}},
		}},
	}
	subject := NewConfigCatalog(cfg)
	evidence := subject.ResolveEvidence("registry.example/app")
	if len(evidence.VEXStatements) != 2 {
		t.Fatalf("statements: %+v", evidence.VEXStatements)
	}
	if evidence.VEXStatements[0].Detail != "human" || evidence.VEXStatements[0].Source != types.VEXSourceManual {
		t.Fatalf("manual statement = %+v", evidence.VEXStatements[0])
	}
	if evidence.VEXStatements[1].ID != "CVE-auto" || evidence.VEXStatements[1].Source != types.VEXSourceAuto {
		t.Fatalf("auto statement = %+v", evidence.VEXStatements[1])
	}
	expires := int64(1)
	if err := subject.ReplaceAutoVEX("registry.example/app", []types.VEXStatement{{
		ID: "CVE-auto", State: types.VEXStateNotAffected, Justification: types.VEXJustRequiresConfiguration, ExpiresAt: &expires,
	}}); err != nil {
		t.Fatal(err)
	}
	if got := subject.AutoVEX("registry.example/app"); len(got) != 1 || got[0].State != types.VEXStateNotAffected {
		t.Fatalf("replaced auto vex = %+v", got)
	}
	resolved := subject.ResolveEvidence("registry.example/app")
	if resolved.VEXStatements[0].Detail != "human" || resolved.VEXStatements[0].Source != types.VEXSourceManual {
		t.Fatalf("hot-swap changed the human statement: %+v", resolved.VEXStatements[0])
	}
}

func TestConfigCatalogInvalidCooldownIsLocalToPolicy(t *testing.T) {
	statementExpiry := time.Now().Add(24 * time.Hour).Unix()
	subject := NewConfigCatalog(&config.RegsyncConfig{
		Sync: []config.SyncEntry{{
			Target:   "repo",
			Type:     "repository",
			Policy:   &config.PolicyConfig{Expression: "criticalCount == 0"},
			Cooldown: "not-a-duration",
			VEXRepo:  boolPointer(true),
			VEX: []types.VEXStatement{
				{ID: "CVE-active", State: types.VEXStateNotAffected, ExpiresAt: &statementExpiry},
			},
		}},
	})

	_, err := subject.ResolvePolicy("repo")
	if err == nil || !strings.Contains(err.Error(), "invalid cooldown for target repo") {
		t.Fatalf("ResolvePolicy() error = %v, want target-specific parse error", err)
	}

	if got := subject.ResolveExpression("repo"); got != "criticalCount == 0" {
		t.Errorf("ResolveExpression() = %q, want configured expression", got)
	}

	evidence := subject.ResolveEvidence("repo")
	if len(evidence.VEXStatements) != 1 || evidence.VEXStatements[0].ID != "CVE-active" {
		t.Errorf("ResolveEvidence() statements = %+v, want CVE-active", evidence.VEXStatements)
	}
	if !evidence.UseVEXRepo {
		t.Error("ResolveEvidence() UseVEXRepo = false, want true")
	}
	if exempted, _ := subject.IsExempted("repo", "CVE-active", time.Now()); !exempted {
		t.Error("IsExempted() = false, want true")
	}
	if got := strings.Join(subject.StatementIDs(), ","); got != "CVE-active" {
		t.Errorf("StatementIDs() = %q, want CVE-active", got)
	}
	if got := strings.Join(subject.Repositories(), ","); got != "repo" {
		t.Errorf("Repositories() = %q, want repo", got)
	}
	if listing := subject.ListPolicies(); listing.Overrides["repo"].Expression != "criticalCount == 0" {
		t.Errorf("ListPolicies() overrides = %+v, want configured expression", listing.Overrides)
	}
	if !subject.UsesVEXRepo() {
		t.Error("UsesVEXRepo() = false, want true")
	}
}

func TestConfigCatalogOperations(t *testing.T) {
	now := time.Unix(2_000, 0)
	expired := now.Add(-time.Second).Unix()
	active := now.Add(time.Second).Unix()
	subject := NewConfigCatalog(&config.RegsyncConfig{
		Defaults: config.Defaults{
			Policy:  &config.PolicyConfig{Expression: "criticalCount == 0"},
			VEXRepo: boolPointer(false),
			VEX: []types.VEXStatement{
				{ID: "CVE-active", State: types.VEXStateNotAffected, ExpiresAt: &active},
				{ID: "CVE-expired", State: types.VEXStateNotAffected, ExpiresAt: &expired},
			},
		},
		Sync: []config.SyncEntry{
			{
				Target:  "registry.example/app:latest",
				Type:    "image",
				Policy:  &config.PolicyConfig{Expression: "highCount == 0"},
				VEXRepo: boolPointer(true),
				VEX:     []types.VEXStatement{{ID: "CVE-informational", State: types.VEXStateAffected}},
			},
			{Target: "registry.example/inherited", Type: "repository"},
		},
	})

	if got := strings.Join(subject.Repositories(), ","); got != "registry.example/app,registry.example/inherited" {
		t.Errorf("Repositories() = %q", got)
	}
	if got := strings.Join(subject.StatementIDs(), ","); got != "CVE-active,CVE-expired,CVE-informational" {
		t.Errorf("StatementIDs() = %q", got)
	}
	if !subject.UsesVEXRepo() {
		t.Error("UsesVEXRepo() = false, want true")
	}

	tests := []struct {
		id   string
		want bool
	}{
		{id: "CVE-active", want: true},
		{id: "CVE-expired", want: false},
		{id: "CVE-informational", want: false},
		{id: "CVE-missing", want: false},
	}
	for _, test := range tests {
		t.Run(test.id, func(t *testing.T) {
			got, _ := subject.IsExempted("registry.example/app", test.id, now)
			if got != test.want {
				t.Errorf("IsExempted() = %t, want %t", got, test.want)
			}
		})
	}

	listing := subject.ListPolicies()
	if listing.Default == nil || listing.Default.Expression != "criticalCount == 0" {
		t.Errorf("default listing = %+v", listing.Default)
	}
	if len(listing.Overrides) != 1 || listing.Overrides["registry.example/app"].Expression != "highCount == 0" {
		t.Errorf("override listing = %+v", listing.Overrides)
	}
}

func TestUpsertManualVEXWinsOverAuto(t *testing.T) {
	cat := NewConfigCatalog(&config.RegsyncConfig{
		Sync: []config.SyncEntry{{
			Target: "registry.example/app",
			Type:   "repository",
			VEXAuto: []types.VEXStatement{{
				ID: "CVE-1", State: types.VEXStateNotAffected, Justification: types.VEXJustCodeNotReachable, Detail: "auto",
			}},
		}},
	})
	if err := cat.UpsertManualVEX("registry.example/app", types.VEXStatement{
		ID: "CVE-1", State: types.VEXStateNotAffected, Justification: types.VEXJustProtectedAtPerimeter, Detail: "human",
	}); err != nil {
		t.Fatal(err)
	}
	evidence := cat.ResolveEvidence("registry.example/app")
	if len(evidence.VEXStatements) != 1 || evidence.VEXStatements[0].Source != types.VEXSourceManual || evidence.VEXStatements[0].Detail != "human" {
		t.Fatalf("effective = %+v", evidence.VEXStatements)
	}
	if len(cat.AutoVEX("registry.example/app")) != 1 {
		t.Fatal("auto statement was removed")
	}
}

func TestReplaceReportsRepositoriesWhoseDecisionChanged(t *testing.T) {
	cat := NewConfigCatalog(&config.RegsyncConfig{
		Sync: []config.SyncEntry{
			{Target: "registry.example/app", Type: "repository", VEX: []types.VEXStatement{{ID: "CVE-1", State: types.VEXStateNotAffected}}},
			{Target: "registry.example/other", Type: "repository"},
		},
	})
	changed := cat.Replace(&config.RegsyncConfig{
		Sync: []config.SyncEntry{
			{Target: "registry.example/app", Type: "repository", VEX: []types.VEXStatement{
				{ID: "CVE-1", State: types.VEXStateNotAffected},
				{ID: "CVE-2", State: types.VEXStateNotAffected},
			}},
			{Target: "registry.example/other", Type: "repository"},
		},
	})
	if len(changed) != 1 || changed[0] != "registry.example/app" {
		t.Fatalf("changed = %v, want registry.example/app", changed)
	}
	evidence := cat.ResolveEvidence("registry.example/app")
	if len(evidence.VEXStatements) != 2 || evidence.VEXStatements[1].ID != "CVE-2" {
		t.Fatalf("evidence = %+v", evidence.VEXStatements)
	}
	if again := cat.Replace(&config.RegsyncConfig{
		Sync: []config.SyncEntry{
			{Target: "registry.example/app", Type: "repository", VEX: []types.VEXStatement{
				{ID: "CVE-1", State: types.VEXStateNotAffected},
				{ID: "CVE-2", State: types.VEXStateNotAffected},
			}},
			{Target: "registry.example/other", Type: "repository"},
		},
	}); len(again) != 0 {
		t.Fatalf("unchanged replace reported %v", again)
	}
}

// internal-1, 2026-11-16: removing the gitlab-agent_agentk sync entry requeued
// all 122 of its images. They delayed every other rescan by about 20 minutes
// and recreated state the removal had just cleaned up.
func TestDecisionChangesLeavesOutRemovedRepositories(t *testing.T) {
	prev := &config.RegsyncConfig{Sync: []config.SyncEntry{
		{Target: "registry.example/app", Type: "repository"},
		{Target: "registry.example/agentk", Type: "repository"},
	}}
	next := &config.RegsyncConfig{Sync: []config.SyncEntry{
		{Target: "registry.example/app", Type: "repository"},
		{Target: "registry.example/added", Type: "repository"},
	}}
	if got := DecisionChanges(prev, next); len(got) != 1 || got[0] != "registry.example/added" {
		t.Fatalf("DecisionChanges = %v, want only the added repository", got)
	}

	cat := NewConfigCatalog(prev)
	if got := cat.Replace(next); len(got) != 1 || got[0] != "registry.example/added" {
		t.Fatalf("Replace = %v, want only the added repository", got)
	}
}

func TestConfigCatalogImplicitDefaultPolicy(t *testing.T) {
	cfg := &config.RegsyncConfig{
		Sync: []config.SyncEntry{
			{Target: "registry.example/team/app", Type: "repository"},
			{
				Target: "registry.example/team/strict",
				Type:   "repository",
				Policy: &config.PolicyConfig{Expression: "highCount == 0", FailureMessage: "strict"},
			},
			{
				Target: "registry.example/team/worded",
				Type:   "repository",
				Policy: &config.PolicyConfig{FailureMessage: "own words"},
			},
		},
	}
	subject := NewConfigCatalog(cfg)

	resolved, err := subject.ResolvePolicy("registry.example/team/app")
	if err != nil {
		t.Fatal(err)
	}
	if resolved.Expression != policy.DefaultExpression || resolved.FailureMessage != policy.DefaultFailureMessage {
		t.Errorf("no policy resolves to %+v, want the implicit default", resolved)
	}
	if got := subject.ResolveExpression("registry.example/team/app"); got != policy.DefaultExpression {
		t.Errorf("ResolveExpression() = %q, want the implicit default", got)
	}
	if got := subject.ResolveExpression("registry.example/unknown"); got != policy.DefaultExpression {
		t.Errorf("unknown repository resolves to %q, want the implicit default", got)
	}
	if got := subject.ResolveExpression("registry.example/team/strict"); got != "highCount == 0" {
		t.Errorf("an own policy must win, got %q", got)
	}
	worded, err := subject.ResolvePolicy("registry.example/team/worded")
	if err != nil {
		t.Fatal(err)
	}
	if worded.Expression != policy.DefaultExpression || worded.FailureMessage != "own words" {
		t.Errorf("a policy without an expression resolves to %+v, want the default expression with its own message", worded)
	}

	listing := subject.ListPolicies()
	if listing.Default == nil || listing.Default.Expression != policy.DefaultExpression {
		t.Errorf("default listing = %+v, want the implicit default", listing.Default)
	}
	if len(listing.Overrides) != 1 || listing.Overrides["registry.example/team/strict"].Expression != "highCount == 0" {
		t.Errorf("override listing = %+v, want only the strict repository", listing.Overrides)
	}
}
