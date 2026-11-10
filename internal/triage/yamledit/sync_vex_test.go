package yamledit

import (
	"errors"
	"strings"
	"testing"

	"github.com/daimoniac/suppline/internal/config"
	"github.com/daimoniac/suppline/internal/types"
	"gopkg.in/yaml.v3"
)

const syncVEXConfig = `version: 1
defaults:
  x-vex:
    - id: CVE-DEFAULT
      state: not_affected
sync:
  - source: a
    target: registry.local/app
    type: repository
    x-vex:
      - id: CVE-1
        state: not_affected
      - id: CVE-2
        state: not_affected
    x-vex-auto:
      - id: CVE-1
        state: not_affected
  - source: b
    target: registry.local/app:v2
    type: image
    x-vex:
      - id: CVE-1
        state: not_affected
  - source: c
    target: registry.local/other
    type: repository
    x-vex:
      - id: CVE-1
        state: not_affected
`

func TestRemoveSyncVEXStatementsOnlyTouchesMatchingKeyAndRepository(t *testing.T) {
	updated, n, err := RemoveSyncVEXStatements([]byte(syncVEXConfig), []SyncVEXRef{
		{Repository: "registry.local/app", ID: "CVE-1", Source: "x-vex"},
	})
	if err != nil {
		t.Fatal(err)
	}
	// sync[0].x-vex CVE-1 and sync[1].x-vex CVE-1 (image target, same repository).
	if n != 2 {
		t.Fatalf("removed %d items, want 2:\n%s", n, updated)
	}

	var raw config.RegsyncConfig
	if err := yaml.Unmarshal(updated, &raw); err != nil {
		t.Fatalf("result does not parse: %v\n%s", err, updated)
	}
	if got := ids(raw.Sync[0].VEX); len(got) != 1 || got[0] != "CVE-2" {
		t.Fatalf("sync[0] x-vex = %v, want [CVE-2]", got)
	}
	if got := ids(raw.Sync[0].VEXAuto); len(got) != 1 || got[0] != "CVE-1" {
		t.Fatalf("sync[0] x-vex-auto = %v, want [CVE-1] kept", got)
	}
	if got := ids(raw.Sync[1].VEX); len(got) != 0 {
		t.Fatalf("sync[1] x-vex = %v, want empty", got)
	}
	if got := ids(raw.Sync[2].VEX); len(got) != 1 || got[0] != "CVE-1" {
		t.Fatalf("other repository lost its statement: %v", got)
	}
	if got := ids(raw.Defaults.VEX); len(got) != 1 || got[0] != "CVE-DEFAULT" {
		t.Fatalf("defaults changed: %v", got)
	}
}

func TestRemoveSyncVEXStatementsRemovesAutoCopyOnly(t *testing.T) {
	updated, n, err := RemoveSyncVEXStatements([]byte(syncVEXConfig), []SyncVEXRef{
		{Repository: "registry.local/app", ID: "CVE-1", Source: "x-vex-auto"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("removed %d items, want 1:\n%s", n, updated)
	}
	var raw config.RegsyncConfig
	if err := yaml.Unmarshal(updated, &raw); err != nil {
		t.Fatal(err)
	}
	if got := ids(raw.Sync[0].VEX); len(got) != 2 {
		t.Fatalf("manual statements changed: %v", got)
	}
	if got := ids(raw.Sync[0].VEXAuto); len(got) != 0 {
		t.Fatalf("auto copy not removed: %v", got)
	}
}

func TestRemoveSyncVEXStatementsRejectsBadInput(t *testing.T) {
	if _, _, err := RemoveSyncVEXStatements([]byte(syncVEXConfig), nil); err == nil {
		t.Fatal("expected error for empty refs")
	}
	if _, _, err := RemoveSyncVEXStatements([]byte(syncVEXConfig), []SyncVEXRef{{Repository: "registry.local/app", ID: "CVE-1", Source: "defaults"}}); err == nil {
		t.Fatal("expected error for unknown source")
	}
	if _, _, err := RemoveSyncVEXStatements([]byte(syncVEXConfig), []SyncVEXRef{{Repository: " ", ID: "CVE-1", Source: "x-vex"}}); err == nil {
		t.Fatal("expected error for empty repository")
	}
	_, _, err := RemoveSyncVEXStatements([]byte(syncVEXConfig), []SyncVEXRef{{Repository: "registry.local/missing", ID: "CVE-1", Source: "x-vex"}})
	if !errors.Is(err, ErrNoMatch) {
		t.Fatalf("got %v, want ErrNoMatch", err)
	}
}

func TestRemoveSyncVEXStatementsExpandsTargetTemplate(t *testing.T) {
	t.Setenv("SUPPLINE_REGISTRY_URL", "hostingmaloonde")
	doc := []byte("version: 1\nsync:\n  - source: a\n    target: '{{ env \"SUPPLINE_REGISTRY_URL\" }}/supabase_studio'\n    type: repository\n    x-vex:\n      - id: CVE-1\n        state: not_affected\n      - id: CVE-2\n        state: not_affected\n")
	updated, n, err := RemoveSyncVEXStatements(doc, []SyncVEXRef{{
		Repository: "hostingmaloonde/supabase_studio", ID: "CVE-1", Source: "x-vex",
	}})
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("removed %d items, want 1:\n%s", n, updated)
	}
	text := string(updated)
	if strings.Contains(text, "CVE-1") || !strings.Contains(text, "CVE-2") || !strings.Contains(text, `{{ env "SUPPLINE_REGISTRY_URL" }}`) {
		t.Fatalf("template edit:\n%s", text)
	}
}

func TestRemoveSyncVEXStatementsKeepsOtherContentIntact(t *testing.T) {
	updated, _, err := RemoveSyncVEXStatements([]byte(syncVEXConfig), []SyncVEXRef{
		{Repository: "registry.local/other", ID: "CVE-1", Source: "x-vex"},
	})
	if err != nil {
		t.Fatal(err)
	}
	text := string(updated)
	if strings.Count(text, "CVE-1") != 3 || !strings.Contains(text, "CVE-DEFAULT") || !strings.Contains(text, "CVE-2") {
		t.Fatalf("unrelated statements were touched:\n%s", text)
	}
}

func ids(statements []types.VEXStatement) []string {
	out := make([]string, 0, len(statements))
	for _, statement := range statements {
		out = append(out, statement.ID)
	}
	return out
}
