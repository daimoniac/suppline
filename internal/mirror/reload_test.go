package mirror

import (
	"context"
	"testing"
	"time"

	"github.com/daimoniac/suppline/internal/config"
	"github.com/daimoniac/suppline/internal/policy/catalog"
	"github.com/daimoniac/suppline/internal/types"
)

func reloadConfig() *config.RegsyncConfig {
	return &config.RegsyncConfig{
		Creds:    []config.RegistryCredential{{Registry: "registry.local"}},
		Defaults: config.Defaults{Parallel: 2},
		Sync: []config.SyncEntry{{
			Source: "upstream/app", Target: "registry.local/app", Type: "repository",
			Tags: &config.TagFilter{SemverRange: []string{">=1.0.0"}},
		}},
	}
}

func TestMirrorSettingsChanged(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*config.RegsyncConfig)
		want   bool
	}{
		{"identical", func(*config.RegsyncConfig) {}, false},
		{"vex-auto only", func(c *config.RegsyncConfig) { c.Sync[0].VEXAuto = []types.VEXStatement{{ID: "CVE-1"}} }, false},
		{"policy only", func(c *config.RegsyncConfig) { c.Sync[0].Policy = &config.PolicyConfig{Expression: "true"} }, false},
		{"default rescan interval", func(c *config.RegsyncConfig) { c.Defaults.RescanInterval = "1d" }, false},
		{"suppline ignore", func(c *config.RegsyncConfig) { c.Sync[0].Ignore = true }, false},
		{"semver range", func(c *config.RegsyncConfig) { c.Sync[0].Tags = &config.TagFilter{SemverRange: []string{">=2.0.0"}} }, true},
		{"new sync entry", func(c *config.RegsyncConfig) {
			c.Sync = append(c.Sync, config.SyncEntry{Source: "upstream/b", Target: "registry.local/b", Type: "repository"})
		}, true},
		{"per-entry attestation toggle", func(c *config.RegsyncConfig) {
			off := false
			c.Sync[0].CreateSBOMAttestation = &off
		}, false},
		{"new in-place entry", func(c *config.RegsyncConfig) {
			c.Sync = append(c.Sync, config.SyncEntry{Source: "ci.local/app", Target: "ci.local/app", Type: "repository", InPlace: true})
		}, false},
		{"credentials", func(c *config.RegsyncConfig) { c.Creds[0].User = "robot" }, true},
		{"parallel", func(c *config.RegsyncConfig) { c.Defaults.Parallel = 4 }, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			next := reloadConfig()
			tt.mutate(next)
			if got := mirrorSettingsChanged(reloadConfig(), next); got != tt.want {
				t.Errorf("mirrorSettingsChanged() = %t, want %t", got, tt.want)
			}
		})
	}
}

// A snapshot that changes only scan settings must leave the schedule running;
// one that changes what is mirrored must stop it for a restart.
func TestWaitForChangeRestartsOnlyForMirrorSettings(t *testing.T) {
	running := catalog.NewConfigCatalog(reloadConfig())
	m := &runner{current: running.Current, changed: running.Changed}
	done := make(chan error)
	result := make(chan bool, 1)
	go func() {
		restarted, _ := m.waitForChange(context.Background(), running.Current(), running.Changed(), done)
		result <- restarted
	}()

	if err := running.ReplaceAutoVEX("registry.local/app", []types.VEXStatement{{ID: "CVE-1"}}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-result:
		t.Fatal("waitForChange returned after an vex-auto edit")
	case <-time.After(50 * time.Millisecond):
	}

	if _, err := running.SetSemverRanges("registry.local/app", []string{">=2.0.0"}); err != nil {
		t.Fatal(err)
	}
	select {
	case restarted := <-result:
		if !restarted {
			t.Fatal("waitForChange did not report a restart")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("waitForChange did not return after a semver edit")
	}
}

// The mirror never schedules, journals or cleans an in-place repository.
func TestJournalLeavesOutInPlaceEntries(t *testing.T) {
	cfg := reloadConfig()
	cfg.Sync = append(cfg.Sync, config.SyncEntry{Source: "ci.local/app", Target: "ci.local/app", Type: "repository", InPlace: true})
	j := newJournal(nil, nil, cfg, nil)
	if len(j.entries) != 1 {
		t.Fatalf("journal entries = %d, want 1", len(j.entries))
	}
	m := &runner{cfg: cfg}
	if got := m.findSyncEntriesForTarget("ci.local/app"); len(got) != 0 {
		t.Fatalf("findSyncEntriesForTarget returned in-place entry: %#v", got)
	}
}
