package catalog

import (
	"testing"

	"github.com/daimoniac/suppline/internal/config"
	"github.com/daimoniac/suppline/internal/types"
	"gopkg.in/yaml.v3"
)

const syncVEXCatalogConfig = `version: 1
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
      - id: CVE-3
        state: not_affected
      - id: CVE-DEFAULT
        state: not_affected
  - source: b
    target: registry.local/app
    type: repository
    x-vex:
      - id: CVE-1
        state: not_affected
`

func newSyncVEXCatalog(t *testing.T) *ConfigCatalog {
	t.Helper()
	var raw config.RegsyncConfig
	if err := yaml.Unmarshal([]byte(syncVEXCatalogConfig), &raw); err != nil {
		t.Fatal(err)
	}
	return NewConfigCatalog(&raw)
}

func TestSyncVEXLeavesOutAmbiguousAndShadowedIDs(t *testing.T) {
	cat := newSyncVEXCatalog(t)
	got := cat.SyncVEX("registry.local/app")

	// CVE-1 is stored on two entries and CVE-DEFAULT is also in defaults; both are left out.
	if len(got) != 2 {
		t.Fatalf("SyncVEX = %+v, want CVE-2 and CVE-3 only", got)
	}
	if got[0].ID != "CVE-2" || got[0].Source != types.VEXSourceManual {
		t.Fatalf("first = %+v", got[0])
	}
	if got[1].ID != "CVE-3" || got[1].Source != types.VEXSourceAuto {
		t.Fatalf("second = %+v", got[1])
	}
}

func TestRemoveEntryVEXRemovesOnlyTheNamedCopy(t *testing.T) {
	cat := newSyncVEXCatalog(t)

	removed, err := cat.RemoveEntryVEX([]EntryVEXRef{
		{Repository: "registry.local/app", ID: "CVE-2", Source: types.VEXSourceManual},
		// Wrong key for CVE-3: it is stored under x-vex-auto, so nothing is removed.
		{Repository: "registry.local/app", ID: "CVE-3", Source: types.VEXSourceManual},
	})
	if err != nil {
		t.Fatal(err)
	}
	if removed != 1 {
		t.Fatalf("removed = %d, want 1", removed)
	}
	if got := cat.SyncVEX("registry.local/app"); len(got) != 1 || got[0].ID != "CVE-3" {
		t.Fatalf("after removal SyncVEX = %+v, want CVE-3 only", got)
	}
	found := false
	for _, statement := range cat.ResolveEvidence("registry.local/app").VEXStatements {
		if statement.ID == "CVE-DEFAULT" {
			found = true
		}
	}
	if !found {
		t.Fatal("defaults must stay in effect")
	}
}
