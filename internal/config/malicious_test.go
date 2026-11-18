package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func parseMaliciousConfig(t *testing.T, block string) (*RegsyncConfig, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "suppline.yml")
	content := "version: 1\ndefaults:\n  interval: 60m\nsync: []\n" + block
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return ParseRegsync(path)
}

func TestMaliciousPackagesDefaults(t *testing.T) {
	cfg, err := parseMaliciousConfig(t, "")
	if err != nil {
		t.Fatal(err)
	}
	m := cfg.MaliciousPackages
	if m != nil {
		t.Fatalf("expected no block, got %+v", m)
	}
	if !m.IsEnabled() || !m.BlockEnabled() {
		t.Fatal("missing block must mean enabled and blocking")
	}
	if m.RepoURL() != DefaultMaliciousRepoURL || m.RepoRef() != "main" || m.Dir() != DefaultMaliciousCheckoutDir {
		t.Fatalf("unexpected repo defaults %s %s %s", m.RepoURL(), m.RepoRef(), m.Dir())
	}
	if m.Interval() != time.Hour || m.Staleness() != 6*time.Hour {
		t.Fatalf("unexpected durations %s %s", m.Interval(), m.Staleness())
	}
	if m.RepoAuth().Type != "" {
		t.Fatal("default auth must be anonymous")
	}
}

func TestMaliciousPackagesParse(t *testing.T) {
	cfg, err := parseMaliciousConfig(t, `malicious-packages:
  enabled: true
  block: false
  repo:
    url: https://git.example/mirror/malicious-packages.git
    ref: stable
    auth: { type: https-token, env: MAL_TOKEN }
  checkout_dir: /tmp/mal
  sync_interval: 30m
  stale_after: 1d
  ecosystems: [npm, PyPI]
`)
	if err != nil {
		t.Fatal(err)
	}
	m := cfg.MaliciousPackages
	if !m.IsEnabled() || m.BlockEnabled() {
		t.Fatal("expected enabled without blocking")
	}
	if m.RepoURL() != "https://git.example/mirror/malicious-packages.git" || m.RepoRef() != "stable" || m.Dir() != "/tmp/mal" {
		t.Fatalf("unexpected repo %s %s %s", m.RepoURL(), m.RepoRef(), m.Dir())
	}
	if m.RepoAuth().Env != "MAL_TOKEN" {
		t.Fatalf("unexpected auth %+v", m.RepoAuth())
	}
	if m.Interval() != 30*time.Minute || m.Staleness() != 24*time.Hour {
		t.Fatalf("unexpected durations %s %s", m.Interval(), m.Staleness())
	}
	if got := m.EcosystemList(); len(got) != 2 || got[1] != "PyPI" {
		t.Fatalf("unexpected ecosystems %v", got)
	}
}

func TestMaliciousPackagesValidate(t *testing.T) {
	tests := []struct {
		name  string
		block string
		want  string
	}{
		{"bad interval", "malicious-packages:\n  sync_interval: soon\n", "sync_interval"},
		{"stale before sync", "malicious-packages:\n  sync_interval: 2h\n  stale_after: 1h\n", "stale_after must be at least sync_interval"},
		{"incomplete auth", "malicious-packages:\n  repo:\n    auth: { type: https-token }\n", "auth.env is required"},
		{"unknown auth", "malicious-packages:\n  repo:\n    auth: { type: basic }\n", "auth.type must be"},
		{"disabled skips checks", "malicious-packages:\n  enabled: false\n  sync_interval: soon\n", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseMaliciousConfig(t, tt.block)
			if tt.want == "" {
				if err != nil {
					t.Fatalf("unexpected error %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("want error containing %q, got %v", tt.want, err)
			}
		})
	}
}

func TestMaliciousVEXStatementsValidated(t *testing.T) {
	base := "version: 1\ndefaults:\n  interval: 60m\nsync:\n  - source: docker.io/library/app\n    target: registry/app\n    type: repository\n"
	tests := []struct {
		name  string
		extra string
		want  string
	}{
		{"false_positive ok", "    vex:\n      - id: MAL-2025-1\n        state: false_positive\n        detail: workspace package\n", ""},
		{"not_affected rejected", "    vex:\n      - id: MAL-2025-1\n        state: not_affected\n        justification: code_not_reachable\n", "must be \"false_positive\""},
		{"auto rejected", "    vex-auto:\n      - id: MAL-2025-1\n        state: false_positive\n", "only hand-written vex"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "suppline.yml")
			if err := os.WriteFile(path, []byte(base+tt.extra), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := ParseRegsync(path)
			if tt.want == "" {
				if err != nil {
					t.Fatalf("unexpected error %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("want error containing %q, got %v", tt.want, err)
			}
		})
	}
}
