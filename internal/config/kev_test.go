package config

import (
	"strings"
	"testing"
	"time"
)

func TestResolveKEVDefaults(t *testing.T) {
	got := ResolveKEV(nil, nil)
	if !got.Enabled || got.FeedURL != DefaultKEVFeedURL || got.FallbackURL != DefaultKEVFallbackURL ||
		got.SyncInterval != DefaultKEVSyncInterval || got.StaleAfter != DefaultKEVStaleAfter || got.FromTriage {
		t.Fatalf("defaults = %+v", got)
	}
}

func TestResolveKEVFallsBackToTriageKeys(t *testing.T) {
	triage := &TriageConfig{KEVFeedURL: " https://mirror.internal/kev.json ", KEVCacheTTL: "3d"}
	got := ResolveKEV(nil, triage)
	if got.FeedURL != "https://mirror.internal/kev.json" || got.SyncInterval != 72*time.Hour || !got.FromTriage {
		t.Fatalf("resolved = %+v", got)
	}
	if got.StaleAfter < got.SyncInterval {
		t.Fatalf("stale_after %s must cover the triage TTL %s", got.StaleAfter, got.SyncInterval)
	}
}

func TestResolveKEVBlockWinsOverTriageKeys(t *testing.T) {
	disabled := false
	triage := &TriageConfig{KEVFeedURL: "https://old.example/kev.json", KEVCacheTTL: "1h"}
	got := ResolveKEV(&KEVConfig{FeedURL: "https://new.example/kev.json", SyncInterval: "2h", StaleAfter: "1d"}, triage)
	if got.FeedURL != "https://new.example/kev.json" || got.SyncInterval != 2*time.Hour || got.StaleAfter != 24*time.Hour || got.FromTriage {
		t.Fatalf("resolved = %+v", got)
	}
	if got := ResolveKEV(&KEVConfig{Enabled: &disabled}, triage); got.Enabled {
		t.Fatal("enabled: false must disable the feed")
	}
}

func TestKEVValidate(t *testing.T) {
	disabled := false
	for _, tc := range []struct {
		name string
		cfg  *KEVConfig
		want string
	}{
		{"absent", nil, ""},
		{"disabled ignores bad values", &KEVConfig{Enabled: &disabled, SyncInterval: "nope"}, ""},
		{"bad interval", &KEVConfig{SyncInterval: "nope"}, "kev.sync_interval"},
		{"negative stale", &KEVConfig{StaleAfter: "-1h"}, "kev.stale_after"},
		{"stale below interval", &KEVConfig{SyncInterval: "12h", StaleAfter: "1h"}, "at least sync_interval"},
		{"valid", &KEVConfig{SyncInterval: "1h", StaleAfter: "2d"}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.cfg.Validate()
			if tc.want == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestParseRegsyncReadsKEVBlock(t *testing.T) {
	cfg, err := parseMaliciousConfig(t, "kev:\n  enabled: false\n  feed_url: https://mirror.internal/kev.json\n")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.KEV == nil || cfg.KEV.Enabled == nil || *cfg.KEV.Enabled || cfg.KEV.FeedURL != "https://mirror.internal/kev.json" {
		t.Fatalf("kev block = %+v", cfg.KEV)
	}
	if _, err := parseMaliciousConfig(t, "kev:\n  sync_interval: nope\n"); err == nil || !strings.Contains(err.Error(), "kev.sync_interval") {
		t.Fatalf("a bad kev block must fail parsing, got %v", err)
	}
}
