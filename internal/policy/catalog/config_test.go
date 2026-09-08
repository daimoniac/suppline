package catalog

import (
	"strings"
	"testing"
	"time"

	"github.com/daimoniac/suppline/internal/config"
	"github.com/daimoniac/suppline/internal/types"
)

func boolPointer(value bool) *bool { return &value }

func TestConfigCatalogResolve(t *testing.T) {
	cfg := &config.RegsyncConfig{
		Defaults: config.Defaults{
			Policy: &config.PolicyConfig{
				Expression:        "criticalCount == 0",
				FailureMessage:    "default failure",
				MinimumReleaseAge: "24h",
			},
			VEXRepo: boolPointer(true),
			VEX: []types.VEXStatement{
				{ID: "CVE-shared", Detail: "default wins"},
				{ID: "CVE-default"},
			},
		},
		Sync: []config.SyncEntry{
			{
				Target:  "registry.example/team/app:1.2.3",
				Type:    "image",
				Policy:  &config.PolicyConfig{Expression: "highCount == 0", FailureMessage: "override failure", MinimumReleaseAge: "2d"},
				VEXRepo: boolPointer(false),
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
		wantMinimumAge time.Duration
		wantVEXRepo    bool
		wantStatements []string
	}{
		{
			name:           "image target is normalized and override replaces policy",
			repository:     "registry.example/team/app",
			wantExpression: "highCount == 0",
			wantFailure:    "override failure",
			wantMinimumAge: 48 * time.Hour,
			wantStatements: []string{"CVE-shared", "CVE-default", "CVE-app"},
		},
		{
			name:           "repository inherits defaults",
			repository:     "registry.example/team/other",
			wantExpression: "criticalCount == 0",
			wantFailure:    "default failure",
			wantMinimumAge: 24 * time.Hour,
			wantVEXRepo:    true,
			wantStatements: []string{"CVE-shared", "CVE-default"},
		},
		{
			name:           "unknown repository gets defaults",
			repository:     "registry.example/team/unknown",
			wantExpression: "criticalCount == 0",
			wantFailure:    "default failure",
			wantMinimumAge: 24 * time.Hour,
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
			if gotPolicy.MinimumReleaseAge != test.wantMinimumAge {
				t.Errorf("minimum release age = %v, want %v", gotPolicy.MinimumReleaseAge, test.wantMinimumAge)
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
func TestConfigCatalogInvalidMinimumReleaseAgeIsLocalToPolicy(t *testing.T) {
	statementExpiry := time.Now().Add(24 * time.Hour).Unix()
	subject := NewConfigCatalog(&config.RegsyncConfig{
		Sync: []config.SyncEntry{{
			Target:  "repo",
			Type:    "repository",
			Policy:  &config.PolicyConfig{Expression: "criticalCount == 0", MinimumReleaseAge: "not-a-duration"},
			VEXRepo: boolPointer(true),
			VEX: []types.VEXStatement{
				{ID: "CVE-active", State: types.VEXStateNotAffected, ExpiresAt: &statementExpiry},
			},
		}},
	})

	_, err := subject.ResolvePolicy("repo")
	if err == nil || !strings.Contains(err.Error(), "invalid minimumReleaseAge for target repo") {
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
