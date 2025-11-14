package config

import (
	"os"
	"testing"
	"time"
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
    target: hostingmaloonde/nginx
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
	os.Setenv("ATTESTATION_KEY_PATH", "/tmp/test.key")
	defer func() {
		os.Unsetenv("SUPPLINE_CONFIG")
		os.Unsetenv("TRIVY_SERVER_ADDR")
		os.Unsetenv("ATTESTATION_KEY_PATH")
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
sync:
  - source: nginx
    target: hostingmaloonde/nginx
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
	os.Setenv("QUEUE_BUFFER_SIZE", "2000")
	os.Setenv("WORKER_RETRY_ATTEMPTS", "5")
	os.Setenv("TRIVY_SERVER_ADDR", "trivy:4954")
	os.Setenv("ATTESTATION_KEY_PATH", "/keys/signing.key")
	os.Setenv("API_PORT", "9000")
	os.Setenv("LOG_LEVEL", "debug")
	defer func() {
		os.Unsetenv("SUPPLINE_CONFIG")
		os.Unsetenv("QUEUE_BUFFER_SIZE")
		os.Unsetenv("WORKER_RETRY_ATTEMPTS")
		os.Unsetenv("TRIVY_SERVER_ADDR")
		os.Unsetenv("ATTESTATION_KEY_PATH")
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
						KeyPath     string
						KeyPassword string
					}{
						KeyPath: "/tmp/key",
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
			errMsg:  "trivy server address is required",
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
						KeyPath     string
						KeyPassword string
					}{
						KeyPath: "",
					},
					UseKeyless: false,
				},
			},
			wantErr: true,
			errMsg:  "attestation key path is required",
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
				if err.Error()[:len(tt.errMsg)] != tt.errMsg {
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
