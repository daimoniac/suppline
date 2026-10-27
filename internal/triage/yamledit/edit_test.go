package yamledit

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/daimoniac/suppline/internal/config"
	"github.com/daimoniac/suppline/internal/types"
)

func TestUpsertPreservesHumanVEXAndTemplates(t *testing.T) {
	original := []byte(`# keep me
version: 1
sync:
  - source: example.com/app
    target: registry.local/app
    type: repository
    # human statement stays
    x-vex:
      - id: CVE-HUMAN
        state: not_affected
        justification: code_not_present
        detail: 'kept {{ env "FOO" }}'
`)
	expires := time.Date(2026, 11, 22, 10, 0, 0, 0, time.UTC).Unix()
	updated, err := Upsert(original, "registry.local/app", types.VEXStatement{
		ID:            "CVE-AUTO",
		State:         types.VEXStateNotAffected,
		Justification: types.VEXJustRequiresConfiguration,
		Detail:        "auto-generated\nline two",
		ExpiresAt:     &expires,
	})
	if err != nil {
		t.Fatal(err)
	}
	text := string(updated)
	for _, want := range []string{"# keep me", "# human statement stays", `{{ env "FOO" }}`, "CVE-HUMAN", "x-vex-auto", "CVE-AUTO", "requires_configuration"} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing %q in\n%s", want, text)
		}
	}
	path := t.TempDir() + "/suppline.yml"
	if err := os.WriteFile(path, updated, 0o644); err != nil {
		t.Fatal(err)
	}
	parsed, err := config.ParseRegsync(path)
	if err != nil {
		t.Fatalf("%v\n%s", err, text)
	}
	if len(parsed.Sync) != 1 || len(parsed.Sync[0].VEX) != 1 || parsed.Sync[0].VEX[0].ID != "CVE-HUMAN" {
		t.Fatalf("human x-vex = %+v", parsed.Sync[0].VEX)
	}
	if len(parsed.Sync[0].VEXAuto) != 1 || parsed.Sync[0].VEXAuto[0].ID != "CVE-AUTO" {
		t.Fatalf("x-vex-auto = %+v", parsed.Sync[0].VEXAuto)
	}

	affected, err := Upsert(updated, "registry.local/app", types.VEXStatement{
		ID: "CVE-AUTO", State: types.VEXStateAffected, Detail: "now affected", ExpiresAt: &expires,
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(affected), "justification:") && strings.Count(string(affected), "justification:") != 1 {
		t.Fatalf("affected statement must not add a justification:\n%s", affected)
	}
}

func TestUpsertManualLeavesAutoUntouched(t *testing.T) {
	original := []byte(`# keep me
version: 1
sync:
  - source: example.com/app
    target: registry.local/app
    type: repository
    x-vex-auto:
      - id: CVE-AUTO
        state: not_affected
        justification: code_not_reachable
        detail: auto
`)
	updated, err := UpsertManual(original, "registry.local/app", types.VEXStatement{
		ID: "CVE-AUTO", State: types.VEXStateNotAffected, Justification: types.VEXJustProtectedAtPerimeter, Detail: "human",
	})
	if err != nil {
		t.Fatal(err)
	}
	text := string(updated)
	if !strings.Contains(text, "# keep me") || !strings.Contains(text, "code_not_reachable") || !strings.Contains(text, "protected_at_perimeter") {
		t.Fatalf("manual edit:\n%s", text)
	}
	if strings.Count(text, "x-vex:") != 1 {
		t.Fatalf("x-vex key:\n%s", text)
	}
}

func TestUpsertManualMatchesExpandedRegistryTarget(t *testing.T) {
	t.Setenv("SUPPLINE_REGISTRY_URL", "hostingmaloonde")
	original := []byte(`sync:
  - source: docker.io/supabase/studio
    target: '{{ env "SUPPLINE_REGISTRY_URL" }}/supabase_studio'
    type: repository
`)
	updated, err := UpsertManual(original, "hostingmaloonde/supabase_studio", types.VEXStatement{
		ID: "GHSA-673q-mjm6-r5xr", State: types.VEXStateNotAffected, Justification: types.VEXJustRequiresConfiguration, Detail: "human",
	})
	if err != nil {
		t.Fatal(err)
	}
	text := string(updated)
	if !strings.Contains(text, `{{ env "SUPPLINE_REGISTRY_URL" }}/supabase_studio`) {
		t.Fatalf("template target was rewritten:\n%s", text)
	}
	if strings.Contains(text, "target: hostingmaloonde/supabase_studio") {
		t.Fatalf("expanded target was written back:\n%s", text)
	}
	if !strings.Contains(text, "GHSA-673q-mjm6-r5xr") || !strings.Contains(text, "requires_configuration") {
		t.Fatalf("statement missing:\n%s", text)
	}
	for _, line := range strings.Split(string(original), "\n") {
		if line != "" && !strings.Contains(text, line) {
			t.Fatalf("rewrote %q\n%s", line, text)
		}
	}
}

func TestUpsertManualKeepsIndentlessCatalog(t *testing.T) {
	t.Setenv("SUPPLINE_REGISTRY_URL", "hostingmaloonde")
	original := []byte(`version: 1
sync:
- source: docker.io/supabase/studio
  target: '{{ env "SUPPLINE_REGISTRY_URL" }}/supabase_studio'
  type: repository
  x-vex:
  - id: CVE-1
    state: not_affected
    justification: code_not_reachable
    detail: keep
x-triage:
  enabled: true
`)
	updated, err := UpsertManual(original, "hostingmaloonde/supabase_studio", types.VEXStatement{
		ID: "GHSA-673q-mjm6-r5xr", State: types.VEXStateNotAffected, Justification: types.VEXJustRequiresConfiguration, Detail: "human",
	})
	if err != nil {
		t.Fatal(err)
	}
	text := string(updated)
	if !strings.HasPrefix(text, string(original[:len(original)-len("x-triage:\n  enabled: true\n")])) && !strings.Contains(text, "x-triage:\n  enabled: true") {
		t.Fatalf("catalog tail changed:\n%s", text)
	}
	if strings.Count(text, "x-vex:") != 1 || !strings.Contains(text, "GHSA-673q-mjm6-r5xr") {
		t.Fatalf("statement:\n%s", text)
	}
	if strings.Contains(text, "  - source:") || strings.Contains(text, "target: hostingmaloonde/") {
		t.Fatalf("reindented catalog:\n%s", text)
	}
}

func TestUpsertRejectsUnknownRepository(t *testing.T) {
	_, err := Upsert([]byte("version: 1\nsync: []\n"), "missing", types.VEXStatement{
		ID: "CVE-1", State: types.VEXStateAffected,
	})
	if err == nil {
		t.Fatal("expected error")
	}
}
