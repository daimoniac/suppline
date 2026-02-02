package config

import (
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/daimoniac/suppline/internal/types"
)

func TestLoad(t *testing.T) {
	// Create a temporary regsync file
	tmpfile, err := os.CreateTemp("", "regsync-*.yml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpfile.Name())

	content := `version: 1
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
	os.Setenv("SUPPLINE_CONFIG", tmpfile.Name())
	os.Setenv("TRIVY_SERVER_ADDR", "localhost:4954")
	os.Setenv("ATTESTATION_KEY", "dGVzdC1rZXk=")
	defer func() {
		os.Unsetenv("SUPPLINE_CONFIG")
		os.Unsetenv("TRIVY_SERVER_ADDR")
		os.Unsetenv("ATTESTATION_KEY")
	}()

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	// Verify defaults
	if cfg.Queue.BufferSize != 1000 {
		t.Errorf("Expected buffer size 1000, got %d", cfg.Queue.BufferSize)
	}

	if cfg.Worker.RetryAttempts != 3 {
		t.Errorf("Expected 3 retry attempts, got %d", cfg.Worker.RetryAttempts)
	}

	if cfg.Scanner.ServerAddr != "localhost:4954" {
		t.Errorf("Expected Trivy server localhost:4954, got %s", cfg.Scanner.ServerAddr)
	}

	if cfg.StateStore.Type != "sqlite" {
		t.Errorf("Expected sqlite state store, got %s", cfg.StateStore.Type)
	}

	if cfg.API.Port != 8080 {
		t.Errorf("Expected API port 8080, got %d", cfg.API.Port)
	}
}

func TestLoadWithCustomValues(t *testing.T) {
	// Create a temporary regsync file
	tmpfile, err := os.CreateTemp("", "regsync-*.yml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpfile.Name())

	content := `version: 1
defaults:
  x-queue-buffer-size: 2000
  x-worker-retry-attempts: 5
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

	// Set custom environment variables
	os.Setenv("SUPPLINE_CONFIG", tmpfile.Name())
	os.Setenv("TRIVY_SERVER_ADDR", "trivy:4954")
	os.Setenv("ATTESTATION_KEY", "dGVzdC1rZXk=")
	os.Setenv("API_PORT", "9000")
	os.Setenv("LOG_LEVEL", "debug")
	defer func() {
		os.Unsetenv("SUPPLINE_CONFIG")
		os.Unsetenv("TRIVY_SERVER_ADDR")
		os.Unsetenv("ATTESTATION_KEY")
		os.Unsetenv("API_PORT")
		os.Unsetenv("LOG_LEVEL")
	}()

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if cfg.Queue.BufferSize != 2000 {
		t.Errorf("Expected buffer size 2000, got %d", cfg.Queue.BufferSize)
	}

	if cfg.Worker.RetryAttempts != 5 {
		t.Errorf("Expected 5 retry attempts, got %d", cfg.Worker.RetryAttempts)
	}

	if cfg.Scanner.ServerAddr != "trivy:4954" {
		t.Errorf("Expected Trivy server trivy:4954, got %s", cfg.Scanner.ServerAddr)
	}

	if cfg.API.Port != 9000 {
		t.Errorf("Expected API port 9000, got %d", cfg.API.Port)
	}

	if cfg.Observability.LogLevel != "debug" {
		t.Errorf("Expected log level debug, got %s", cfg.Observability.LogLevel)
	}
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name    string
		config  *Config
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid config with key-based attestation",
			config: &Config{
				RegsyncPath: "suppline.yml",
				Scanner: ScannerConfig{
					ServerAddr: "localhost:4954",
				},
				StateStore: StateStoreConfig{
					Type:       "sqlite",
					SQLitePath: "test.db",
				},
				Attestation: AttestationConfig{
					KeyBased: struct {
						Key string
					}{
						Key: "dGVzdC1rZXk=", // base64 encoded "test-key"
					},
					UseKeyless: false,
				},
			},
			wantErr: false,
		},
		{
			name: "missing regsync path",
			config: &Config{
				RegsyncPath: "",
			},
			wantErr: true,
			errMsg:  "regsync path is required",
		},
		{
			name: "missing trivy server",
			config: &Config{
				RegsyncPath: "suppline.yml",
				Scanner: ScannerConfig{
					ServerAddr: "",
				},
			},
			wantErr: true,
			errMsg:  "TRIVY_SERVER_ADDR environment variable is required",
		},
		{
			name: "invalid state store type",
			config: &Config{
				RegsyncPath: "suppline.yml",
				Scanner: ScannerConfig{
					ServerAddr: "localhost:4954",
				},
				StateStore: StateStoreConfig{
					Type: "invalid",
				},
			},
			wantErr: true,
			errMsg:  "invalid state store type",
		},
		{
			name: "postgres without URL",
			config: &Config{
				RegsyncPath: "suppline.yml",
				Scanner: ScannerConfig{
					ServerAddr: "localhost:4954",
				},
				StateStore: StateStoreConfig{
					Type:        "postgres",
					PostgresURL: "",
				},
			},
			wantErr: true,
			errMsg:  "postgres URL is required",
		},
		{
			name: "key-based without key path",
			config: &Config{
				RegsyncPath: "suppline.yml",
				Scanner: ScannerConfig{
					ServerAddr: "localhost:4954",
				},
				StateStore: StateStoreConfig{
					Type:       "sqlite",
					SQLitePath: "test.db",
				},
				Attestation: AttestationConfig{
					KeyBased: struct {
						Key string
					}{
						Key: "",
					},
					UseKeyless: false,
				},
			},
			wantErr: true,
			errMsg:  "attestation key is required",
		},
		{
			name: "keyless without OIDC config",
			config: &Config{
				RegsyncPath: "suppline.yml",
				Scanner: ScannerConfig{
					ServerAddr: "localhost:4954",
				},
				StateStore: StateStoreConfig{
					Type:       "sqlite",
					SQLitePath: "test.db",
				},
				Attestation: AttestationConfig{
					UseKeyless:   true,
					OIDCIssuer:   "",
					OIDCClientID: "",
				},
			},
			wantErr: true,
			errMsg:  "OIDC issuer and client ID are required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create temp file for tests that need it
			if tt.config.RegsyncPath == "suppline.yml" {
				tmpfile, err := os.CreateTemp("", "regsync-*.yml")
				if err != nil {
					t.Fatal(err)
				}
				defer os.Remove(tmpfile.Name())
				_, _ = tmpfile.Write([]byte("version: 1\n"))
				_ = tmpfile.Close()
				tt.config.RegsyncPath = tmpfile.Name()
			}

			err := tt.config.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr && err != nil && tt.errMsg != "" {
				// Check that error contains the expected message (may be wrapped)
				if !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("Validate() error = %v, want error containing %v", err, tt.errMsg)
				}
			}
		})
	}
}

func TestGetEnvDuration(t *testing.T) {
	os.Setenv("TEST_DURATION", "5m")
	defer os.Unsetenv("TEST_DURATION")

	duration := getEnvDuration("TEST_DURATION", 1*time.Minute)
	if duration != 5*time.Minute {
		t.Errorf("Expected 5m, got %v", duration)
	}

	// Test default value
	duration = getEnvDuration("NONEXISTENT", 2*time.Minute)
	if duration != 2*time.Minute {
		t.Errorf("Expected 2m default, got %v", duration)
	}
}

func TestGetEnvBool(t *testing.T) {
	tests := []struct {
		value    string
		expected bool
	}{
		{"true", true},
		{"1", true},
		{"yes", true},
		{"false", false},
		{"0", false},
		{"no", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.value, func(t *testing.T) {
			if tt.value != "" {
				os.Setenv("TEST_BOOL", tt.value)
				defer os.Unsetenv("TEST_BOOL")
			}

			result := getEnvBool("TEST_BOOL", false)
			if result != tt.expected {
				t.Errorf("getEnvBool(%q) = %v, want %v", tt.value, result, tt.expected)
			}
		})
	}
}

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

func TestGetTolerationsForTarget_WithDefaults(t *testing.T) {
	defaultExpiresAt := time.Now().Add(60 * 24 * time.Hour).Unix()
	syncExpiresAt := time.Now().Add(30 * 24 * time.Hour).Unix()

	config := &RegsyncConfig{
		Version: 1,
		Defaults: Defaults{
			Tolerate: []types.CVEToleration{
				{
					ID:        "CVE-2024-00001",
					Statement: "Default toleration for all targets",
					ExpiresAt: &defaultExpiresAt,
				},
				{
					ID:        "CVE-2024-00002",
					Statement: "Another default toleration",
					ExpiresAt: nil, // No expiry
				},
			},
		},
		Sync: []SyncEntry{
			{
				Source: "nginx",
				Target: "myregistry.com/nginx",
				Type:   "repository",
				Tolerate: []types.CVEToleration{
					{
						ID:        "CVE-2024-12345",
						Statement: "Sync-specific toleration",
						ExpiresAt: &syncExpiresAt,
					},
				},
			},
			{
				Source: "alpine",
				Target: "myregistry.com/alpine",
				Type:   "repository",
				// No sync-specific tolerations, should only get defaults
			},
		},
	}

	// Test nginx target - should have both default and sync-specific tolerations
	tolerations := config.GetTolerationsForTarget("myregistry.com/nginx")
	if len(tolerations) != 3 {
		t.Errorf("expected 3 tolerations (2 default + 1 sync-specific) but got %d", len(tolerations))
	}

	// Verify default tolerations are included
	foundDefault1 := false
	foundDefault2 := false
	foundSync := false
	for _, tol := range tolerations {
		if tol.ID == "CVE-2024-00001" {
			foundDefault1 = true
		}
		if tol.ID == "CVE-2024-00002" {
			foundDefault2 = true
		}
		if tol.ID == "CVE-2024-12345" {
			foundSync = true
		}
	}

	if !foundDefault1 {
		t.Error("expected to find default toleration CVE-2024-00001")
	}
	if !foundDefault2 {
		t.Error("expected to find default toleration CVE-2024-00002")
	}
	if !foundSync {
		t.Error("expected to find sync-specific toleration CVE-2024-12345")
	}

	// Test alpine target - should only have default tolerations
	tolerations = config.GetTolerationsForTarget("myregistry.com/alpine")
	if len(tolerations) != 2 {
		t.Errorf("expected 2 tolerations (defaults only) but got %d", len(tolerations))
	}

	// Verify only default tolerations are present
	foundDefault1 = false
	foundDefault2 = false
	for _, tol := range tolerations {
		if tol.ID == "CVE-2024-00001" {
			foundDefault1 = true
		}
		if tol.ID == "CVE-2024-00002" {
			foundDefault2 = true
		}
	}

	if !foundDefault1 {
		t.Error("expected to find default toleration CVE-2024-00001 for alpine")
	}
	if !foundDefault2 {
		t.Error("expected to find default toleration CVE-2024-00002 for alpine")
	}
}

func TestGetExpiringTolerations_WithDefaults(t *testing.T) {
	// Create tolerations with various expiration times
	within7Days := time.Now().Add(5 * 24 * time.Hour).Unix()     // Expires in 5 days (within 7 days)
	beyond7Days := time.Now().Add(10 * 24 * time.Hour).Unix()    // Expires in 10 days (beyond 7 days)
	syncWithin7Days := time.Now().Add(3 * 24 * time.Hour).Unix() // Expires in 3 days (within 7 days)

	config := &RegsyncConfig{
		Version: 1,
		Defaults: Defaults{
			Tolerate: []types.CVEToleration{
				{
					ID:        "CVE-2024-00001",
					Statement: "Expiring soon default",
					ExpiresAt: &within7Days,
				},
				{
					ID:        "CVE-2024-00002",
					Statement: "Expiring later default",
					ExpiresAt: &beyond7Days,
				},
				{
					ID:        "CVE-2024-00003",
					Statement: "Permanent default",
					ExpiresAt: nil,
				},
			},
		},
		Sync: []SyncEntry{
			{
				Source: "nginx",
				Target: "myregistry.com/nginx",
				Type:   "repository",
				Tolerate: []types.CVEToleration{
					{
						ID:        "CVE-2024-12345",
						Statement: "Expiring soon sync-specific",
						ExpiresAt: &syncWithin7Days,
					},
				},
			},
		},
	}

	// Get tolerations expiring within 7 days
	expiring := config.GetExpiringTolerations(7 * 24 * time.Hour)

	// Should include: CVE-2024-00001 (5 days) and CVE-2024-12345 (3 days)
	// Should NOT include: CVE-2024-00002 (10 days) and CVE-2024-00003 (permanent)
	if len(expiring) != 2 {
		t.Errorf("expected 2 expiring tolerations but got %d", len(expiring))
	}

	foundDefault := false
	foundSync := false
	for _, tol := range expiring {
		if tol.ID == "CVE-2024-00001" {
			foundDefault = true
		}
		if tol.ID == "CVE-2024-12345" {
			foundSync = true
		}
	}

	if !foundDefault {
		t.Error("expected to find expiring default toleration CVE-2024-00001")
	}
	if !foundSync {
		t.Error("expected to find expiring sync-specific toleration CVE-2024-12345")
	}
}

func TestParseRegsyncWithExpiresAtTimestamp(t *testing.T) {
	// Create a temporary regsync file with expires_at as RFC3339 timestamp
	tmpfile, err := os.CreateTemp("", "regsync-*.yml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpfile.Name())

	content := `version: 1
defaults:
  x-tolerate:
    - id: CVE-2025-15467
      statement: tolerating openssl issue until end of february
      expires_at: 2026-02-28T23:59:59Z
    - id: CVE-2024-99999
      statement: permanent toleration
sync:
  - source: nginx
    target: myregistry.com/nginx
    type: repository
    x-tolerate:
      - id: CVE-2024-12345
        statement: sync-specific with expiry
        expires_at: 2026-03-15T12:00:00Z
`
	if _, err := tmpfile.Write([]byte(content)); err != nil {
		t.Fatal(err)
	}
	if err := tmpfile.Close(); err != nil {
		t.Fatal(err)
	}

	config, err := ParseRegsync(tmpfile.Name())
	if err != nil {
		t.Fatalf("ParseRegsync failed: %v", err)
	}

	// Check defaults
	if len(config.Defaults.Tolerate) != 2 {
		t.Fatalf("expected 2 default tolerations, got %d", len(config.Defaults.Tolerate))
	}

	// Verify first default toleration with expiry
	tol1 := config.Defaults.Tolerate[0]
	if tol1.ID != "CVE-2025-15467" {
		t.Errorf("expected ID CVE-2025-15467, got %s", tol1.ID)
	}
	if tol1.ExpiresAt == nil {
		t.Error("expected ExpiresAt to be non-nil for CVE-2025-15467")
	} else {
		expectedTime := time.Date(2026, 2, 28, 23, 59, 59, 0, time.UTC).Unix()
		if *tol1.ExpiresAt != expectedTime {
			t.Errorf("expected ExpiresAt %d (%s), got %d (%s)",
				expectedTime, time.Unix(expectedTime, 0).UTC(),
				*tol1.ExpiresAt, time.Unix(*tol1.ExpiresAt, 0).UTC())
		}
	}

	// Verify second default toleration without expiry
	tol2 := config.Defaults.Tolerate[1]
	if tol2.ID != "CVE-2024-99999" {
		t.Errorf("expected ID CVE-2024-99999, got %s", tol2.ID)
	}
	if tol2.ExpiresAt != nil {
		t.Errorf("expected ExpiresAt to be nil for CVE-2024-99999, got %v", tol2.ExpiresAt)
	}

	// Check sync-specific toleration
	if len(config.Sync) != 1 {
		t.Fatalf("expected 1 sync entry, got %d", len(config.Sync))
	}
	if len(config.Sync[0].Tolerate) != 1 {
		t.Fatalf("expected 1 sync toleration, got %d", len(config.Sync[0].Tolerate))
	}

	syncTol := config.Sync[0].Tolerate[0]
	if syncTol.ID != "CVE-2024-12345" {
		t.Errorf("expected ID CVE-2024-12345, got %s", syncTol.ID)
	}
	if syncTol.ExpiresAt == nil {
		t.Error("expected ExpiresAt to be non-nil for CVE-2024-12345")
	} else {
		expectedTime := time.Date(2026, 3, 15, 12, 0, 0, 0, time.UTC).Unix()
		if *syncTol.ExpiresAt != expectedTime {
			t.Errorf("expected ExpiresAt %d (%s), got %d (%s)",
				expectedTime, time.Unix(expectedTime, 0).UTC(),
				*syncTol.ExpiresAt, time.Unix(*syncTol.ExpiresAt, 0).UTC())
		}
	}

	// Test GetTolerationsForTarget includes both defaults and sync-specific
	allTols := config.GetTolerationsForTarget("myregistry.com/nginx")
	if len(allTols) != 3 {
		t.Errorf("expected 3 total tolerations (2 defaults + 1 sync), got %d", len(allTols))
	}
}

func TestParseRegsyncWithDateOnlyExpiresAt(t *testing.T) {
	// Create a temporary regsync file with expires_at as date-only format
	tmpfile, err := os.CreateTemp("", "regsync-*.yml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpfile.Name())

	content := `version: 1
defaults:
  x-tolerate:
    - id: CVE-2025-15467
      statement: tolerating openssl issue until end of february
      expires_at: 2026-02-28
sync:
  - source: nginx
    target: myregistry.com/nginx
    type: repository
`
	if _, err := tmpfile.Write([]byte(content)); err != nil {
		t.Fatal(err)
	}
	if err := tmpfile.Close(); err != nil {
		t.Fatal(err)
	}

	config, err := ParseRegsync(tmpfile.Name())
	if err != nil {
		t.Fatalf("ParseRegsync failed: %v", err)
	}

	// Check that the date was parsed and set to end of day
	if len(config.Defaults.Tolerate) != 1 {
		t.Fatalf("expected 1 default toleration, got %d", len(config.Defaults.Tolerate))
	}

	tol := config.Defaults.Tolerate[0]
	if tol.ID != "CVE-2025-15467" {
		t.Errorf("expected ID CVE-2025-15467, got %s", tol.ID)
	}
	if tol.ExpiresAt == nil {
		t.Error("expected ExpiresAt to be non-nil")
	} else {
		// Should be set to 2026-02-28 23:59:59 UTC
		expectedTime := time.Date(2026, 2, 28, 23, 59, 59, 0, time.UTC).Unix()
		if *tol.ExpiresAt != expectedTime {
			t.Errorf("expected ExpiresAt %d (%s), got %d (%s)",
				expectedTime, time.Unix(expectedTime, 0).UTC(),
				*tol.ExpiresAt, time.Unix(*tol.ExpiresAt, 0).UTC())
		}
	}
}

func TestParseRegsyncWithInvalidExpiresAt(t *testing.T) {
	tests := []struct {
		name      string
		expiresAt string
		wantErr   string
	}{
		{
			name:      "invalid date - Feb 29 non-leap year",
			expiresAt: "2026-02-29",
			wantErr:   "invalid expires_at format",
		},
		{
			name:      "invalid format",
			expiresAt: "February 28, 2026",
			wantErr:   "invalid expires_at format",
		},
		{
			name:      "invalid date - month 13",
			expiresAt: "2026-13-01",
			wantErr:   "invalid expires_at format",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpfile, err := os.CreateTemp("", "regsync-*.yml")
			if err != nil {
				t.Fatal(err)
			}
			defer os.Remove(tmpfile.Name())

			content := fmt.Sprintf(`version: 1
defaults:
  x-tolerate:
    - id: CVE-2025-15467
      statement: test toleration
      expires_at: %s
sync:
  - source: nginx
    target: myregistry.com/nginx
    type: repository
`, tt.expiresAt)

			if _, err := tmpfile.Write([]byte(content)); err != nil {
				t.Fatal(err)
			}
			if err := tmpfile.Close(); err != nil {
				t.Fatal(err)
			}

			_, err = ParseRegsync(tmpfile.Name())
			if err == nil {
				t.Error("expected error but got nil")
				return
			}

			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %v, want error containing %q", err, tt.wantErr)
			}
		})
	}
}
