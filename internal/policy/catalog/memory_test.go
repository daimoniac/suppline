package catalog

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/daimoniac/suppline/internal/policy"
	"github.com/daimoniac/suppline/internal/types"
)

func TestMemoryCatalogAdapters(t *testing.T) {
	now := time.Unix(2_000, 0)
	active := now.Add(time.Hour).Unix()
	expired := now.Add(-time.Hour).Unix()
	subject := NewMemoryCatalog(
		MemoryEntry{
			Policy: policy.PolicyConfig{Expression: "criticalCount == 0"},
			Evidence: Evidence{
				VEXStatements: []types.VEXStatement{{ID: "CVE-default", State: types.VEXStateNotAffected}},
			},
		},
		map[string]MemoryEntry{
			"repo-b": {
				Policy: policy.PolicyConfig{Expression: "highCount == 0", MinimumReleaseAge: time.Hour},
				Evidence: Evidence{
					UseVEXRepo: true,
					VEXStatements: []types.VEXStatement{
						{ID: "CVE-active", State: types.VEXStateNotAffected, ExpiresAt: &active},
						{ID: "CVE-expired", State: types.VEXStateNotAffected, ExpiresAt: &expired},
						{ID: "CVE-affected", State: types.VEXStateAffected},
					},
				},
				PolicyOverride: true,
			},
			"repo-a": {Policy: policy.PolicyConfig{Expression: "criticalCount == 0"}},
		},
	)

	tests := []struct {
		name           string
		repository     string
		wantExpression string
		wantStatements int
	}{
		{name: "known repository", repository: "repo-b", wantExpression: "highCount == 0", wantStatements: 3},
		{name: "default repository", repository: "missing", wantExpression: "criticalCount == 0", wantStatements: 1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			gotPolicy, err := subject.ResolvePolicy(test.repository)
			if err != nil {
				t.Fatalf("ResolvePolicy() error = %v", err)
			}
			if gotPolicy.Expression != test.wantExpression {
				t.Errorf("ResolvePolicy() = %+v, want expression %q", gotPolicy, test.wantExpression)
			}
			if got := subject.ResolveExpression(test.repository); got != test.wantExpression {
				t.Errorf("ResolveExpression() = %q, want %q", got, test.wantExpression)
			}

			gotEvidence := subject.ResolveEvidence(test.repository)
			if len(gotEvidence.VEXStatements) != test.wantStatements {
				t.Errorf("ResolveEvidence() = %+v, want %d statements", gotEvidence, test.wantStatements)
			}
			gotEvidence.VEXStatements[0].ID = "mutated"
			if again := subject.ResolveEvidence(test.repository); again.VEXStatements[0].ID == "mutated" {
				t.Error("ResolveEvidence() leaked mutable statement storage")
			}
		})
	}

	if got := strings.Join(subject.Repositories(), ","); got != "repo-a,repo-b" {
		t.Errorf("Repositories() = %q", got)
	}
	if got := strings.Join(subject.StatementIDs(), ","); got != "CVE-active,CVE-affected,CVE-default,CVE-expired" {
		t.Errorf("StatementIDs() = %q", got)
	}
	if !subject.UsesVEXRepo() {
		t.Error("UsesVEXRepo() = false, want true")
	}

	exemptionTests := []struct {
		id   string
		want bool
	}{
		{id: "CVE-active", want: true},
		{id: "CVE-expired", want: false},
		{id: "CVE-affected", want: false},
	}
	for _, test := range exemptionTests {
		t.Run(test.id, func(t *testing.T) {
			got, _ := subject.IsExempted("repo-b", test.id, now)
			if got != test.want {
				t.Errorf("IsExempted() = %t, want %t", got, test.want)
			}
		})
	}

	listing := subject.ListPolicies()
	if listing.Default == nil || listing.Default.Expression != "criticalCount == 0" {
		t.Errorf("default listing = %+v", listing.Default)
	}
	if len(listing.Overrides) != 1 || listing.Overrides["repo-b"].Expression != "highCount == 0" {
		t.Errorf("override listing = %+v", listing.Overrides)
	}
}

// The in-memory adapter must be able to reproduce the config adapter's only
// failure mode without withholding evidence for that repository.
func TestMemoryCatalogPolicyErrorIsLocalToPolicy(t *testing.T) {
	wantErr := errors.New("invalid minimumReleaseAge for target repo-b")
	subject := NewMemoryCatalog(MemoryEntry{}, map[string]MemoryEntry{
		"repo-b": {
			Policy:      policy.PolicyConfig{Expression: "criticalCount == 0"},
			PolicyError: wantErr,
			Evidence: Evidence{
				UseVEXRepo:    true,
				VEXStatements: []types.VEXStatement{{ID: "CVE-active", State: types.VEXStateNotAffected}},
			},
		},
	})

	if _, err := subject.ResolvePolicy("repo-b"); !errors.Is(err, wantErr) {
		t.Fatalf("ResolvePolicy() error = %v, want %v", err, wantErr)
	}
	if got := subject.ResolveExpression("repo-b"); got != "criticalCount == 0" {
		t.Errorf("ResolveExpression() = %q, want configured expression", got)
	}
	evidence := subject.ResolveEvidence("repo-b")
	if len(evidence.VEXStatements) != 1 || !evidence.UseVEXRepo {
		t.Errorf("ResolveEvidence() = %+v, want one statement and VEX repo enabled", evidence)
	}
	if exempted, _ := subject.IsExempted("repo-b", "CVE-active", time.Now()); !exempted {
		t.Error("IsExempted() = false, want true")
	}
	if got := strings.Join(subject.StatementIDs(), ","); got != "CVE-active" {
		t.Errorf("StatementIDs() = %q, want CVE-active", got)
	}
}
