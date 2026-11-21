package config

import (
	"os"
	"strings"
	"testing"
	"time"
)

func TestExpandConfig(t *testing.T) {
	tests := []struct {
		name     string
		config   *RegsyncConfig
		envVars  map[string]string
		wantUser string
		wantPass string
		wantErr  bool
	}{
		{
			name: "expand environment variables",
			config: &RegsyncConfig{
				Creds: []RegistryCredential{
					{
						Registry: "docker.io",
						User:     `{{ env "DOCKER_USERNAME" }}`,
						Pass:     `{{ env "DOCKER_PASSWORD" }}`,
					},
				},
			},
			envVars: map[string]string{
				"DOCKER_USERNAME": "testuser",
				"DOCKER_PASSWORD": "testpass",
			},
			wantUser: "testuser",
			wantPass: "testpass",
			wantErr:  false,
		},
		{
			name: "no template syntax - pass through",
			config: &RegsyncConfig{
				Creds: []RegistryCredential{
					{
						Registry: "docker.io",
						User:     "plainuser",
						Pass:     "plainpass",
					},
				},
			},
			envVars:  map[string]string{},
			wantUser: "plainuser",
			wantPass: "plainpass",
			wantErr:  false,
		},
		{
			name: "empty environment variable",
			config: &RegsyncConfig{
				Creds: []RegistryCredential{
					{
						Registry: "docker.io",
						User:     `{{ env "MISSING_VAR" }}`,
						Pass:     "testpass",
					},
				},
			},
			envVars:  map[string]string{},
			wantUser: "",
			wantPass: "testpass",
			wantErr:  false,
		},
		{
			name: "multiple registries",
			config: &RegsyncConfig{
				Creds: []RegistryCredential{
					{
						Registry: "registry-1.docker.io",
						User:     `{{ env "DOCKER_USERNAME" }}`,
						Pass:     `{{ env "DOCKER_PASSWORD" }}`,
					},
					{
						Registry: "docker.io",
						User:     `{{ env "DOCKER_USERNAME" }}`,
						Pass:     `{{ env "DOCKER_PASSWORD" }}`,
					},
				},
			},
			envVars: map[string]string{
				"DOCKER_USERNAME": "myuser",
				"DOCKER_PASSWORD": "mypass",
			},
			wantUser: "myuser",
			wantPass: "mypass",
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set environment variables
			for k, v := range tt.envVars {
				os.Setenv(k, v)
				defer os.Unsetenv(k)
			}

			err := expandConfig(tt.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("expandConfig() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && len(tt.config.Creds) > 0 {
				if tt.config.Creds[0].User != tt.wantUser {
					t.Errorf("User = %v, want %v", tt.config.Creds[0].User, tt.wantUser)
				}
				if tt.config.Creds[0].Pass != tt.wantPass {
					t.Errorf("Pass = %v, want %v", tt.config.Creds[0].Pass, tt.wantPass)
				}
			}
		})
	}
}

func TestParseRegsyncWithTemplates(t *testing.T) {
	// Create a temporary regsync file with template syntax
	tmpfile, err := os.CreateTemp("", "regsync-*.yml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpfile.Name())

	content := `version: 1
creds:
  - registry: registry-1.docker.io
    user: '{{ env "DOCKER_USERNAME" }}'
    pass: '{{ env "DOCKER_PASSWORD" }}'
    repoAuth: false
    reqPerSec: 10
    reqConcurrent: 10
  - registry: docker.io
    user: '{{ env "DOCKER_USERNAME" }}'
    pass: '{{ env "DOCKER_PASSWORD" }}'
    repoAuth: false
    reqPerSec: 10
    reqConcurrent: 10
sync:
  - source: nginx
    target: myprivateregistry/nginx
    type: repository
`
	if _, err := tmpfile.Write([]byte(content)); err != nil {
		t.Fatal(err)
	}
	if err := tmpfile.Close(); err != nil {
		t.Fatal(err)
	}

	// Set environment variables
	os.Setenv("DOCKER_USERNAME", "testuser")
	os.Setenv("DOCKER_PASSWORD", "testpass")
	defer func() {
		os.Unsetenv("DOCKER_USERNAME")
		os.Unsetenv("DOCKER_PASSWORD")
	}()

	config, err := ParseRegsync(tmpfile.Name())
	if err != nil {
		t.Fatalf("ParseRegsync failed: %v", err)
	}

	if len(config.Creds) != 2 {
		t.Fatalf("Expected 2 credentials, got %d", len(config.Creds))
	}

	// Check first credential
	if config.Creds[0].Registry != "registry-1.docker.io" {
		t.Errorf("Expected registry registry-1.docker.io, got %s", config.Creds[0].Registry)
	}
	if config.Creds[0].User != "testuser" {
		t.Errorf("Expected user testuser, got %s", config.Creds[0].User)
	}
	if config.Creds[0].Pass != "testpass" {
		t.Errorf("Expected pass testpass, got %s", config.Creds[0].Pass)
	}

	// Check second credential
	if config.Creds[1].Registry != "docker.io" {
		t.Errorf("Expected registry docker.io, got %s", config.Creds[1].Registry)
	}
	if config.Creds[1].User != "testuser" {
		t.Errorf("Expected user testuser, got %s", config.Creds[1].User)
	}
	if config.Creds[1].Pass != "testpass" {
		t.Errorf("Expected pass testpass, got %s", config.Creds[1].Pass)
	}
}

func TestSupplineIgnore_IsIgnored(t *testing.T) {
	active := SyncEntry{Source: "nginx", Target: "registry/nginx", Type: "repository", Ignore: false}
	ignored := SyncEntry{Source: "alpine", Target: "registry/alpine", Type: "repository", Ignore: true}

	if active.IsIgnored() {
		t.Error("expected IsIgnored() = false for entry without suppline-ignore")
	}
	if !ignored.IsIgnored() {
		t.Error("expected IsIgnored() = true for entry with suppline-ignore: true")
	}
}

func TestSupplineIgnore_ParseYAML(t *testing.T) {
	content := strings.Join([]string{
		"version: 1",
		"sync:",
		"  - source: nginx",
		"    target: myregistry/nginx",
		"    type: repository",
		"  - source: alpine",
		"    target: myregistry/alpine",
		"    type: repository",
		"    suppline-ignore: true",
		"  - source: redis",
		"    target: myregistry/redis",
		"    type: repository",
		"    suppline-ignore: false",
		"",
	}, "\n")
	tmpfile, err := os.CreateTemp("", "regsync-*.yml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpfile.Name())

	if _, err := tmpfile.Write([]byte(content)); err != nil {
		t.Fatal(err)
	}
	if err := tmpfile.Close(); err != nil {
		t.Fatal(err)
	}

	cfg, err := ParseRegsync(tmpfile.Name())
	if err != nil {
		t.Fatalf("ParseRegsync failed: %v", err)
	}

	if len(cfg.Sync) != 3 {
		t.Fatalf("expected ignored entries to stay on Sync, got %d", len(cfg.Sync))
	}
	active := cfg.Active()
	if len(active) != 2 {
		t.Fatalf("expected 2 active sync entries, got %d", len(active))
	}

	if active[0].Source != "nginx" {
		t.Errorf("expected first active entry to be nginx, got %q", active[0].Source)
	}
	if active[1].Source != "redis" {
		t.Errorf("expected second active entry to be redis, got %q", active[1].Source)
	}
}

func TestSupplineIgnore_GetTargetRepositories(t *testing.T) {
	cfg := &RegsyncConfig{
		Sync: []SyncEntry{
			{Source: "nginx", Target: "myregistry/nginx", Type: "repository", Ignore: false},
			{Source: "alpine", Target: "myregistry/alpine", Type: "repository", Ignore: true},
			{Source: "redis", Target: "myregistry/redis", Type: "repository", Ignore: false},
			{Source: "busybox", Target: "myregistry/busybox:latest", Type: "image", Ignore: true},
		},
	}

	targets := cfg.GetTargetRepositories()

	if len(targets) != 2 {
		t.Fatalf("expected 2 non-ignored targets, got %d: %v", len(targets), targets)
	}

	expected := map[string]bool{
		"myregistry/nginx": true,
		"myregistry/redis": true,
	}
	for _, target := range targets {
		if !expected[target] {
			t.Errorf("unexpected target %q in results", target)
		}
	}
}

func TestParseRegsyncServerFields(t *testing.T) {
	content := strings.Join([]string{
		"version: 1",
		"defaults:",
		"  interval: 60m",
		"  cleanupTags: true",
		"  cleanupTagsExclude:",
		"    - \".*\\\\.sig$\"",
		"sync:",
		"  - source: nginx",
		"    target: myregistry/nginx",
		"    type: repository",
		"    tags:",
		"      allow:",
		"        - \"v.*\"",
		"  - source: alpine",
		"    target: myregistry/alpine",
		"    type: repository",
		"    suppline-ignore: true",
		"",
	}, "\n")
	tmpfile, err := os.CreateTemp("", "regsync-*.yml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpfile.Name())
	if _, err := tmpfile.Write([]byte(content)); err != nil {
		t.Fatal(err)
	}
	if err := tmpfile.Close(); err != nil {
		t.Fatal(err)
	}

	cfg, err := ParseRegsync(tmpfile.Name())
	if err != nil {
		t.Fatalf("ParseRegsync failed: %v", err)
	}
	if cfg.Sync[0].Interval.Std() != 60*time.Minute {
		t.Fatalf("interval = %s, want 60m", cfg.Sync[0].Interval)
	}
	if cfg.Sync[0].Tags == nil || len(cfg.Sync[0].Tags.Allow) != 1 || cfg.Sync[0].Tags.Allow[0] != "v.*" {
		t.Fatalf("tags.allow = %#v", cfg.Sync[0].Tags)
	}
	if cfg.Sync[0].CleanupTags == nil || !*cfg.Sync[0].CleanupTags {
		t.Fatal("cleanupTags was not inherited")
	}
	if len(cfg.Sync[0].CleanupTagsExclude) != 1 {
		t.Fatalf("cleanupTagsExclude = %#v", cfg.Sync[0].CleanupTagsExclude)
	}
	if cfg.Sync[1].CleanupTags == nil || !*cfg.Sync[1].CleanupTags {
		t.Fatal("ignored entry did not inherit cleanupTags")
	}
	if len(cfg.Active()) != 1 || cfg.Active()[0].Source != "nginx" {
		t.Fatalf("Active() = %#v", cfg.Active())
	}
	if len(cfg.Sync[0].MediaTypes) == 0 {
		t.Fatal("default media types were not applied")
	}
}

func TestCreateVulnerabilityAttestationDefault(t *testing.T) {
	var cfg RegsyncConfig
	if !cfg.CreateVulnerabilityAttestation() {
		t.Fatal("unset option should publish vulnerability attestations")
	}
	off := false
	cfg.Defaults.CreateVulnerabilityAttestation = &off
	if cfg.CreateVulnerabilityAttestation() {
		t.Fatal("false option should skip vulnerability attestations")
	}
}

func TestCreateSBOMAttestationDefault(t *testing.T) {
	var cfg RegsyncConfig
	if !cfg.CreateSBOMAttestation() {
		t.Fatal("unset option should publish SBOM attestations")
	}
	off := false
	cfg.Defaults.CreateSBOMAttestation = &off
	if cfg.CreateSBOMAttestation() {
		t.Fatal("false option should skip SBOM attestations")
	}
}

func TestGetCooldown(t *testing.T) {
	cfg := &RegsyncConfig{
		Defaults: Defaults{Cooldown: "7d"},
		Sync: []SyncEntry{
			{Target: "registry.example/app", Type: "repository", Cooldown: "3d",
				CooldownReleases: []CooldownRelease{{Digest: "sha256:aaa"}}},
			{Target: "registry.example/off", Type: "repository", Cooldown: "0"},
			{Target: "registry.example/img:1.0", Type: "image"},
		},
	}
	tests := []struct {
		target string
		want   time.Duration
	}{
		{"registry.example/app", 3 * 24 * time.Hour},
		{"registry.example/off", 0},
		{"registry.example/img", 7 * 24 * time.Hour},
		{"registry.example/unknown", 7 * 24 * time.Hour},
	}
	for _, test := range tests {
		got, err := cfg.GetCooldown(test.target)
		if err != nil || got != test.want {
			t.Errorf("GetCooldown(%q) = %v, %v; want %v", test.target, got, err, test.want)
		}
	}
	if !cfg.CooldownReleased("registry.example/app", "sha256:aaa") {
		t.Error("CooldownReleased() = false for a released digest")
	}
	if cfg.CooldownReleased("registry.example/app", "sha256:bbb") || cfg.CooldownReleased("registry.example/off", "sha256:aaa") {
		t.Error("CooldownReleased() = true for a digest released elsewhere or not at all")
	}
}

func TestValidateCooldowns(t *testing.T) {
	bad := []*RegsyncConfig{
		{Defaults: Defaults{Cooldown: "soon"}},
		{Sync: []SyncEntry{{Target: "r", Cooldown: "-1d"}}},
		{Sync: []SyncEntry{{Target: "r", CooldownReleases: []CooldownRelease{{Digest: "latest"}}}}},
	}
	for i, cfg := range bad {
		if err := cfg.ValidateCooldowns(); err == nil {
			t.Errorf("config %d: ValidateCooldowns() = nil, want error", i)
		}
	}
	good := &RegsyncConfig{Defaults: Defaults{Cooldown: "72h"}, Sync: []SyncEntry{{Target: "r", Cooldown: "0"}}}
	if err := good.ValidateCooldowns(); err != nil {
		t.Errorf("ValidateCooldowns() = %v", err)
	}
}

func TestValidateTagFilters(t *testing.T) {
	bad := []*RegsyncConfig{
		{Sync: []SyncEntry{{Target: "r", Tags: &TagFilter{Newest: -1}}}},
		{Sync: []SyncEntry{{Target: "r", TagSets: []TagFilter{{Newest: 3}, {Newest: -2}}}}},
	}
	for i, cfg := range bad {
		if err := cfg.ValidateTagFilters(); err == nil {
			t.Errorf("config %d: ValidateTagFilters() = nil, want error", i)
		}
	}
	good := &RegsyncConfig{Sync: []SyncEntry{{Target: "r", Tags: &TagFilter{Allow: []string{"sha.*"}, Newest: 30}}}}
	if err := good.ValidateTagFilters(); err != nil {
		t.Errorf("ValidateTagFilters() = %v", err)
	}
}
