package catalog

import (
	"testing"

	"github.com/daimoniac/suppline/internal/config"
	"github.com/daimoniac/suppline/internal/types"
)

func snapshotConfig() *config.RegsyncConfig {
	return &config.RegsyncConfig{
		Defaults: config.Defaults{VEX: []types.VEXStatement{{ID: "CVE-default"}}},
		Sync: []config.SyncEntry{
			{
				Source: "upstream/app", Target: "mirror/app", Type: "repository",
				Tags: &config.TagFilter{SemverRange: []string{">=1.0.0"}},
				VEX:  []types.VEXStatement{{ID: "CVE-manual", State: types.VEXStateNotAffected}},
			},
			{Source: "upstream/other", Target: "mirror/other", Type: "repository"},
		},
	}
}

func closed(ch <-chan struct{}) bool {
	select {
	case <-ch:
		return true
	default:
		return false
	}
}

// Readers hold a snapshot from Current while edits happen concurrently.
// An edit must publish a new snapshot and leave the held one untouched.
func TestConfigCatalogEditsPublishNewSnapshots(t *testing.T) {
	edits := []struct {
		name  string
		apply func(*ConfigCatalog) error
		check func(t *testing.T, before, after *config.RegsyncConfig)
	}{
		{
			name: "SetSemverRanges",
			apply: func(c *ConfigCatalog) error {
				_, err := c.SetSemverRanges("mirror/app", []string{">=2.0.0"})
				return err
			},
			check: func(t *testing.T, before, after *config.RegsyncConfig) {
				if got := before.Sync[0].Tags.SemverRange[0]; got != ">=1.0.0" {
					t.Errorf("held snapshot semverRange = %s, want >=1.0.0", got)
				}
				if got := after.Sync[0].Tags.SemverRange[0]; got != ">=2.0.0" {
					t.Errorf("current semverRange = %s, want >=2.0.0", got)
				}
			},
		},
		{
			name: "ReplaceAutoVEX",
			apply: func(c *ConfigCatalog) error {
				return c.ReplaceAutoVEX("mirror/app", []types.VEXStatement{{ID: "CVE-auto"}})
			},
			check: func(t *testing.T, before, after *config.RegsyncConfig) {
				if len(before.Sync[0].VEXAuto) != 0 || len(after.Sync[0].VEXAuto) != 1 {
					t.Errorf("vex-auto before=%v after=%v, want none then one", before.Sync[0].VEXAuto, after.Sync[0].VEXAuto)
				}
			},
		},
		{
			name: "UpsertManualVEX replacing an existing statement",
			apply: func(c *ConfigCatalog) error {
				return c.UpsertManualVEX("mirror/app", types.VEXStatement{ID: "CVE-manual", State: types.VEXStateAffected})
			},
			check: func(t *testing.T, before, after *config.RegsyncConfig) {
				if before.Sync[0].VEX[0].State != types.VEXStateNotAffected || after.Sync[0].VEX[0].State != types.VEXStateAffected {
					t.Errorf("vex state before=%s after=%s", before.Sync[0].VEX[0].State, after.Sync[0].VEX[0].State)
				}
			},
		},
		{
			name: "RemoveSyncTargets",
			apply: func(c *ConfigCatalog) error {
				_, err := c.RemoveSyncTargets([]string{"mirror/other"})
				return err
			},
			check: func(t *testing.T, before, after *config.RegsyncConfig) {
				if len(before.Sync) != 2 || len(after.Sync) != 1 {
					t.Errorf("sync entries before=%d after=%d, want 2 then 1", len(before.Sync), len(after.Sync))
				}
			},
		},
		{
			name: "RemoveVEXIDs",
			apply: func(c *ConfigCatalog) error {
				_, err := c.RemoveVEXIDs([]string{"CVE-default", "CVE-manual"})
				return err
			},
			check: func(t *testing.T, before, after *config.RegsyncConfig) {
				if len(before.Defaults.VEX) != 1 || len(before.Sync[0].VEX) != 1 {
					t.Errorf("held snapshot lost VEX: defaults=%v sync=%v", before.Defaults.VEX, before.Sync[0].VEX)
				}
				if len(after.Defaults.VEX) != 0 || len(after.Sync[0].VEX) != 0 {
					t.Errorf("current kept VEX: defaults=%v sync=%v", after.Defaults.VEX, after.Sync[0].VEX)
				}
			},
		},
		{
			name: "RemoveEntryVEX",
			apply: func(c *ConfigCatalog) error {
				_, err := c.RemoveEntryVEX([]EntryVEXRef{{Repository: "mirror/app", Source: types.VEXSourceManual, ID: "CVE-manual"}})
				return err
			},
			check: func(t *testing.T, before, after *config.RegsyncConfig) {
				if len(before.Sync[0].VEX) != 1 || len(after.Sync[0].VEX) != 0 {
					t.Errorf("vex before=%v after=%v, want one then none", before.Sync[0].VEX, after.Sync[0].VEX)
				}
			},
		},
		{
			name: "Replace",
			apply: func(c *ConfigCatalog) error {
				next := snapshotConfig()
				next.Sync = next.Sync[:1]
				c.Replace(next)
				return nil
			},
			check: func(t *testing.T, before, after *config.RegsyncConfig) {
				if len(before.Sync) != 2 || len(after.Sync) != 1 {
					t.Errorf("sync entries before=%d after=%d, want 2 then 1", len(before.Sync), len(after.Sync))
				}
			},
		},
	}
	for _, tt := range edits {
		t.Run(tt.name, func(t *testing.T) {
			c := NewConfigCatalog(snapshotConfig())
			before := c.Current()
			changed := c.Changed()

			if err := tt.apply(c); err != nil {
				t.Fatalf("edit error = %v", err)
			}
			after := c.Current()
			if after == before {
				t.Fatal("edit did not publish a new snapshot")
			}
			if !closed(changed) {
				t.Error("Changed() channel not closed after the edit")
			}
			if closed(c.Changed()) {
				t.Error("Changed() after the edit is already closed")
			}
			tt.check(t, before, after)
		})
	}
}

func TestConfigCatalogFailedEditPublishesNothing(t *testing.T) {
	c := NewConfigCatalog(snapshotConfig())
	before := c.Current()
	changed := c.Changed()

	if err := c.ReplaceAutoVEX("mirror/unknown", []types.VEXStatement{{ID: "CVE-auto"}}); err == nil {
		t.Fatal("ReplaceAutoVEX() on an unknown repository returned nil error")
	}
	if c.Current() != before {
		t.Error("failed edit published a snapshot")
	}
	if closed(changed) {
		t.Error("failed edit closed Changed()")
	}
}
