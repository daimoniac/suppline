package yamledit

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/daimoniac/suppline/internal/config"
	"github.com/daimoniac/suppline/internal/types"
)

const inPlaceDoc = `version: 1
sync:
  - source: example.com/app
    target: registry.local/app
    type: repository
in-place:
  - repository: registry.gitlab.com/group/app
    tags:
      allow: ['sha[0-9a-f]{8,}']
    vex:
      - id: CVE-HUMAN
        state: not_affected
        justification: code_not_present
        detail: kept
  # trailing comment stays
  - repository: registry.gitlab.com/group/other
`

func parseEdited(t *testing.T, document []byte) *config.RegsyncConfig {
	t.Helper()
	path := t.TempDir() + "/suppline.yml"
	if err := os.WriteFile(path, document, 0o644); err != nil {
		t.Fatal(err)
	}
	parsed, err := config.ParseRegsync(path)
	if err != nil {
		t.Fatalf("%v\n%s", err, document)
	}
	return parsed
}

func TestUpsertWritesVEXAutoOnInPlaceEntry(t *testing.T) {
	expires := time.Date(2026, 12, 22, 10, 0, 0, 0, time.UTC).Unix()
	updated, err := Upsert([]byte(inPlaceDoc), "registry.gitlab.com/group/app", types.VEXStatement{
		ID:            "CVE-AUTO",
		State:         types.VEXStateNotAffected,
		Justification: types.VEXJustRequiresConfiguration,
		Detail:        "auto",
		ExpiresAt:     &expires,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(updated), "# trailing comment stays") {
		t.Fatalf("comment lost:\n%s", updated)
	}
	parsed := parseEdited(t, updated)
	entry, ok := parsed.InPlaceEntryFor("registry.gitlab.com/group/app")
	if !ok {
		t.Fatalf("in-place entry lost:\n%s", updated)
	}
	if len(entry.VEXAuto) != 1 || entry.VEXAuto[0].ID != "CVE-AUTO" || len(entry.VEX) != 1 {
		t.Fatalf("vex = %+v, vex-auto = %+v\n%s", entry.VEX, entry.VEXAuto, updated)
	}
	other, _ := parsed.InPlaceEntryFor("registry.gitlab.com/group/other")
	if len(other.VEXAuto) != 0 {
		t.Fatalf("other in-place entry changed: %+v", other.VEXAuto)
	}
}

func TestCooldownReleaseNeverTargetsInPlaceEntry(t *testing.T) {
	_, err := AddCooldownRelease([]byte(inPlaceDoc), "registry.gitlab.com/group/app", config.CooldownRelease{Digest: "sha256:abc"})
	if err == nil {
		t.Fatal("a cooldown release must not be written into an in-place entry")
	}
}

func TestRemoveSyncTargetsRemovesInPlaceEntry(t *testing.T) {
	updated, removed, err := RemoveSyncTargets([]byte(inPlaceDoc), []string{"registry.gitlab.com/group/app"})
	if err != nil {
		t.Fatal(err)
	}
	if removed != 1 {
		t.Fatalf("removed = %d", removed)
	}
	parsed := parseEdited(t, updated)
	if parsed.IsInPlace("registry.gitlab.com/group/app") || !parsed.IsInPlace("registry.gitlab.com/group/other") {
		t.Fatalf("unexpected result:\n%s", updated)
	}
}

func TestRemoveSyncVEXStatementsOnInPlaceEntry(t *testing.T) {
	updated, removed, err := RemoveSyncVEXStatements([]byte(inPlaceDoc), []SyncVEXRef{{Repository: "registry.gitlab.com/group/app", ID: "CVE-HUMAN", Source: "vex"}})
	if err != nil {
		t.Fatal(err)
	}
	if removed != 1 {
		t.Fatalf("removed = %d\n%s", removed, updated)
	}
	entry, _ := parseEdited(t, updated).InPlaceEntryFor("registry.gitlab.com/group/app")
	if len(entry.VEX) != 0 {
		t.Fatalf("vex = %+v", entry.VEX)
	}
}
