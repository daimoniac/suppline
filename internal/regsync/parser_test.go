package regsync

import (
	"os"
	"testing"
	"time"
)

func TestParse(t *testing.T) {
	// Create a temporary test file
	content := `version: 1
creds:
  - registry: docker.io
    user: testuser
    pass: testpass
    repoAuth: true
defaults:
  parallel: 2
sync:
  - source: nginx
    target: hostingmaloonde/nginx
    type: repository
    x-tolerate:
      - id: CVE-2024-56171
        statement: test toleration
        expires_at: 2025-12-31T23:59:59Z
      - id: CVE-2025-0838
        statement: permanent toleration
`

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

	// Parse the file
	config, err := Parse(tmpfile.Name())
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	// Verify basic structure
	if config.Version != 1 {
		t.Errorf("Expected version 1, got %d", config.Version)
	}

	if len(config.Creds) != 1 {
		t.Errorf("Expected 1 credential, got %d", len(config.Creds))
	}

	if config.Creds[0].Registry != "docker.io" {
		t.Errorf("Expected registry docker.io, got %s", config.Creds[0].Registry)
	}

	if len(config.Sync) != 1 {
		t.Errorf("Expected 1 sync entry, got %d", len(config.Sync))
	}

	// Verify tolerations
	if len(config.Sync[0].Tolerate) != 2 {
		t.Errorf("Expected 2 tolerations, got %d", len(config.Sync[0].Tolerate))
	}

	// Check first toleration with expiry
	if config.Sync[0].Tolerate[0].ID != "CVE-2024-56171" {
		t.Errorf("Expected CVE-2024-56171, got %s", config.Sync[0].Tolerate[0].ID)
	}

	if config.Sync[0].Tolerate[0].ExpiresAt == nil {
		t.Error("Expected expiry date, got nil")
	}

	// Check second toleration without expiry
	if config.Sync[0].Tolerate[1].ID != "CVE-2025-0838" {
		t.Errorf("Expected CVE-2025-0838, got %s", config.Sync[0].Tolerate[1].ID)
	}

	if config.Sync[0].Tolerate[1].ExpiresAt != nil {
		t.Error("Expected no expiry date, got one")
	}
}

func TestGetTolerationsForTarget(t *testing.T) {
	config := &Config{
		Sync: []SyncEntry{
			{
				Target: "hostingmaloonde/nginx",
				Tolerate: []CVEToleration{
					{ID: "CVE-2024-56171", Statement: "test"},
				},
			},
			{
				Target: "hostingmaloonde/alpine",
				Tolerate: []CVEToleration{
					{ID: "CVE-2024-12345", Statement: "test2"},
				},
			},
		},
	}

	tolerations := config.GetTolerationsForTarget("hostingmaloonde/nginx")
	if len(tolerations) != 1 {
		t.Errorf("Expected 1 toleration, got %d", len(tolerations))
	}

	if tolerations[0].ID != "CVE-2024-56171" {
		t.Errorf("Expected CVE-2024-56171, got %s", tolerations[0].ID)
	}
}

func TestIsToleratedCVE(t *testing.T) {
	futureTime := time.Now().Add(24 * time.Hour)
	pastTime := time.Now().Add(-24 * time.Hour)

	config := &Config{
		Sync: []SyncEntry{
			{
				Target: "hostingmaloonde/nginx",
				Tolerate: []CVEToleration{
					{ID: "CVE-ACTIVE", Statement: "active", ExpiresAt: &futureTime},
					{ID: "CVE-EXPIRED", Statement: "expired", ExpiresAt: &pastTime},
					{ID: "CVE-PERMANENT", Statement: "permanent", ExpiresAt: nil},
				},
			},
		},
	}

	// Test active toleration
	tolerated, _ := config.IsToleratedCVE("hostingmaloonde/nginx", "CVE-ACTIVE")
	if !tolerated {
		t.Error("Expected CVE-ACTIVE to be tolerated")
	}

	// Test expired toleration
	tolerated, _ = config.IsToleratedCVE("hostingmaloonde/nginx", "CVE-EXPIRED")
	if tolerated {
		t.Error("Expected CVE-EXPIRED to not be tolerated")
	}

	// Test permanent toleration
	tolerated, _ = config.IsToleratedCVE("hostingmaloonde/nginx", "CVE-PERMANENT")
	if !tolerated {
		t.Error("Expected CVE-PERMANENT to be tolerated")
	}

	// Test non-existent CVE
	tolerated, _ = config.IsToleratedCVE("hostingmaloonde/nginx", "CVE-NOTFOUND")
	if tolerated {
		t.Error("Expected CVE-NOTFOUND to not be tolerated")
	}
}

func TestGetExpiringTolerations(t *testing.T) {
	now := time.Now()
	expiringSoon := now.Add(3 * 24 * time.Hour)  // 3 days from now
	expiringLater := now.Add(10 * 24 * time.Hour) // 10 days from now
	expired := now.Add(-24 * time.Hour)           // 1 day ago

	config := &Config{
		Sync: []SyncEntry{
			{
				Target: "hostingmaloonde/nginx",
				Tolerate: []CVEToleration{
					{ID: "CVE-SOON", Statement: "expiring soon", ExpiresAt: &expiringSoon},
					{ID: "CVE-LATER", Statement: "expiring later", ExpiresAt: &expiringLater},
					{ID: "CVE-EXPIRED", Statement: "already expired", ExpiresAt: &expired},
					{ID: "CVE-PERMANENT", Statement: "no expiry", ExpiresAt: nil},
				},
			},
		},
	}

	// Get tolerations expiring within 7 days
	expiring := config.GetExpiringTolerations(7 * 24 * time.Hour)

	if len(expiring) != 1 {
		t.Errorf("Expected 1 expiring toleration, got %d", len(expiring))
	}

	if len(expiring) > 0 && expiring[0].ID != "CVE-SOON" {
		t.Errorf("Expected CVE-SOON, got %s", expiring[0].ID)
	}
}

func TestGetTargetRepositories(t *testing.T) {
	config := &Config{
		Sync: []SyncEntry{
			{Target: "hostingmaloonde/nginx"},
			{Target: "hostingmaloonde/alpine"},
			{Target: "hostingmaloonde/redis"},
		},
	}

	targets := config.GetTargetRepositories()
	if len(targets) != 3 {
		t.Errorf("Expected 3 targets, got %d", len(targets))
	}

	expected := map[string]bool{
		"hostingmaloonde/nginx":  true,
		"hostingmaloonde/alpine": true,
		"hostingmaloonde/redis":  true,
	}

	for _, target := range targets {
		if !expected[target] {
			t.Errorf("Unexpected target: %s", target)
		}
	}
}

func TestParseInterval(t *testing.T) {
	tests := []struct {
		name     string
		interval string
		want     time.Duration
		wantErr  bool
	}{
		{
			name:     "minutes notation",
			interval: "30m",
			want:     30 * time.Minute,
			wantErr:  false,
		},
		{
			name:     "hours notation",
			interval: "3h",
			want:     3 * time.Hour,
			wantErr:  false,
		},
		{
			name:     "days notation",
			interval: "7d",
			want:     7 * 24 * time.Hour,
			wantErr:  false,
		},
		{
			name:     "invalid format - too short",
			interval: "d",
			want:     0,
			wantErr:  true,
		},
		{
			name:     "invalid format - no number",
			interval: "abcd",
			want:     0,
			wantErr:  true,
		},
		{
			name:     "invalid unit",
			interval: "5s",
			want:     0,
			wantErr:  true,
		},
		{
			name:     "negative value",
			interval: "-5d",
			want:     0,
			wantErr:  true,
		},
		{
			name:     "zero value",
			interval: "0d",
			want:     0,
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseInterval(tt.interval)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseInterval() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("parseInterval() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetRescanInterval(t *testing.T) {
	tests := []struct {
		name    string
		config  *Config
		target  string
		want    time.Duration
		wantErr bool
	}{
		{
			name: "sync entry override",
			config: &Config{
				Defaults: Defaults{
					RescanInterval: "7d",
				},
				Sync: []SyncEntry{
					{
						Target:         "hostingmaloonde/nginx",
						RescanInterval: "3d",
					},
				},
			},
			target:  "hostingmaloonde/nginx",
			want:    3 * 24 * time.Hour,
			wantErr: false,
		},
		{
			name: "default fallback",
			config: &Config{
				Defaults: Defaults{
					RescanInterval: "5d",
				},
				Sync: []SyncEntry{
					{
						Target: "hostingmaloonde/nginx",
					},
				},
			},
			target:  "hostingmaloonde/nginx",
			want:    5 * 24 * time.Hour,
			wantErr: false,
		},
		{
			name: "hardcoded fallback",
			config: &Config{
				Sync: []SyncEntry{
					{
						Target: "hostingmaloonde/nginx",
					},
				},
			},
			target:  "hostingmaloonde/nginx",
			want:    7 * 24 * time.Hour,
			wantErr: false,
		},
		{
			name: "invalid sync entry interval",
			config: &Config{
				Sync: []SyncEntry{
					{
						Target:         "hostingmaloonde/nginx",
						RescanInterval: "invalid",
					},
				},
			},
			target:  "hostingmaloonde/nginx",
			want:    0,
			wantErr: true,
		},
		{
			name: "invalid default interval",
			config: &Config{
				Defaults: Defaults{
					RescanInterval: "invalid",
				},
				Sync: []SyncEntry{
					{
						Target: "hostingmaloonde/nginx",
					},
				},
			},
			target:  "hostingmaloonde/nginx",
			want:    0,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.config.GetRescanInterval(tt.target)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetRescanInterval() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("GetRescanInterval() = %v, want %v", got, tt.want)
			}
		})
	}
}
