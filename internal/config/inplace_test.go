package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func parseInPlaceDoc(t *testing.T, lines ...string) (*RegsyncConfig, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "suppline.yml")
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return ParseRegsync(path)
}

func TestInPlace_ParseAppendsEntriesWithoutMirrorDefaults(t *testing.T) {
	t.Setenv("CI_REGISTRY", "registry.gitlab.com")
	cfg, err := parseInPlaceDoc(t,
		"defaults:",
		"  interval: 60m",
		"  cleanupTags: true",
		"  cooldown: 5d",
		"  createSBOMAttestation: false",
		"sync:",
		"  - source: nginx",
		"    target: mirror.example/nginx",
		"    type: repository",
		"in-place:",
		`  - repository: '{{ env "CI_REGISTRY" }}/cmd/dev/shcomp'`,
		"    scan-requesters: [cmd/dev/shcomp]",
		"    createSBOMAttestation: true",
		"    tags:",
		"      allow: ['sha[0-9a-f]{8,}']",
		"      newest: 30",
	)
	if err != nil {
		t.Fatalf("ParseRegsync: %v", err)
	}
	if len(cfg.InPlace) != 0 {
		t.Fatalf("InPlace should be folded into Sync, got %d", len(cfg.InPlace))
	}
	if len(cfg.Sync) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(cfg.Sync))
	}
	repo := "registry.gitlab.com/cmd/dev/shcomp"
	entry, ok := cfg.InPlaceEntryFor(repo)
	if !ok {
		t.Fatalf("in-place entry for %s not found; targets %v", repo, cfg.GetTargetRepositories())
	}
	if entry.Schedule != "" || entry.Interval != 0 {
		t.Errorf("in-place entry inherited a mirror schedule: %q %v", entry.Schedule, entry.Interval)
	}
	if entry.CleanupTags == nil || *entry.CleanupTags {
		t.Errorf("in-place entry must never clean up tags")
	}
	if got := entry.ScanRequesters; len(got) != 1 || got[0] != "cmd/dev/shcomp" {
		t.Errorf("scan-requesters = %v", got)
	}
	if mirrored := cfg.MirrorEntries(); len(mirrored) != 1 || mirrored[0].Target != "mirror.example/nginx" {
		t.Errorf("MirrorEntries = %#v", mirrored)
	}
	if !cfg.IsInPlace(repo) || cfg.IsInPlace("mirror.example/nginx") {
		t.Errorf("IsInPlace mismatch")
	}

	cooldown, err := cfg.GetCooldown(repo)
	if err != nil || cooldown != 0 {
		t.Errorf("in-place cooldown = %v, %v; want 0", cooldown, err)
	}
	if cooldown, _ := cfg.GetCooldown("mirror.example/nginx"); cooldown == 0 {
		t.Errorf("mirrored entry lost the default cooldown")
	}
	if !cfg.CreateSBOMAttestation(repo) {
		t.Errorf("entry createSBOMAttestation should override defaults")
	}
	if cfg.CreateSBOMAttestation("mirror.example/nginx") {
		t.Errorf("mirrored entry should inherit createSBOMAttestation=false")
	}
	if !cfg.CreateVulnerabilityAttestation(repo) {
		t.Errorf("unset vulnerability toggle should mean yes")
	}
}

func TestInPlace_RejectsInvalidEntries(t *testing.T) {
	cases := map[string][]string{
		"mirror field": {
			"in-place:",
			"  - repository: registry.example/app",
			"    cooldown: 1d",
		},
		"tagged repository": {
			"in-place:",
			"  - repository: registry.example/app:latest",
		},
		"digest repository": {
			"in-place:",
			"  - repository: registry.example/app@sha256:abc",
		},
		"missing repository": {
			"in-place:",
			"  - scan-requesters: [group/app]",
		},
		"listed twice": {
			"in-place:",
			"  - repository: registry.example/app",
			"  - repository: registry.example/app",
		},
		"also mirrored": {
			"sync:",
			"  - source: upstream/app",
			"    target: registry.example/app",
			"    type: repository",
			"in-place:",
			"  - repository: registry.example/app",
		},
		"empty requester": {
			"in-place:",
			"  - repository: registry.example/app",
			"    scan-requesters: ['']",
		},
	}
	for name, doc := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := parseInPlaceDoc(t, doc...); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

func TestInPlace_RegistryPortIsNotATag(t *testing.T) {
	cfg, err := parseInPlaceDoc(t,
		"in-place:",
		"  - repository: localhost:5000/demo-ci",
	)
	if err != nil {
		t.Fatalf("ParseRegsync: %v", err)
	}
	if !cfg.IsInPlace("localhost:5000/demo-ci") {
		t.Fatal("repository with a registry port should be accepted")
	}
}

func TestWorkerUrgentConcurrency(t *testing.T) {
	var cfg RegsyncConfig
	if got := cfg.GetWorkerUrgentConcurrency(); got != DefaultWorkerUrgentConcurrency {
		t.Fatalf("unset = %d, want %d", got, DefaultWorkerUrgentConcurrency)
	}
	none := 0
	cfg.Defaults.WorkerUrgentConcurrency = &none
	if got := cfg.GetWorkerUrgentConcurrency(); got != 0 {
		t.Fatalf("explicit 0 = %d", got)
	}
	five := 5
	cfg.Defaults.WorkerUrgentConcurrency = &five
	if got := cfg.GetWorkerUrgentConcurrency(); got != 5 {
		t.Fatalf("5 = %d", got)
	}
}
