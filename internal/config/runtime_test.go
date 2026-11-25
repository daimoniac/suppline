package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeConfig(t *testing.T, lines ...string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "suppline.yml")
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func clearSecretEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{"SUPPLINE_API_KEY", "POSTGRES_URL", "TRIVY_TOKEN", "ATTESTATION_KEY"} {
		t.Setenv(k, "")
	}
}

func TestLoad_Defaults(t *testing.T) {
	clearSecretEnv(t)
	t.Setenv("SUPPLINE_CONFIG", writeConfig(t, "version: 1", "sync: []"))

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	checks := []struct {
		name      string
		got, want any
	}{
		{"api port", cfg.API.Port, 8080},
		{"base path", cfg.API.BasePath, ""},
		{"observability port", cfg.Observability.Port, 9090},
		{"log level", cfg.Observability.LogLevel, "info"},
		{"mirror", cfg.MirrorEnabled, true},
		{"trivy server", cfg.Scanner.ServerAddr, "localhost:4954"},
		{"trivy timeout", cfg.Scanner.Timeout, 5 * time.Minute},
		{"local fallback", cfg.Scanner.LocalFallback, true},
		{"rescan interval", cfg.StateStore.RescanInterval, 7 * 24 * time.Hour},
		{"queue buffer", cfg.Queue.BufferSize, 1000},
		{"worker concurrency", cfg.Worker.Concurrency, 3},
		{"attest timeout", cfg.Attestation.CommandTimeout, 2 * time.Minute},
		{"bundle format", cfg.Attestation.NewBundleFormat, true},
		{"http registry", cfg.Attestation.AllowHTTPRegistry, false},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s = %v, want %v", c.name, c.got, c.want)
		}
	}
}

func TestLoad_SettingsFromFileAndSecretsFromEnv(t *testing.T) {
	clearSecretEnv(t)
	t.Setenv("SUPPLINE_CONFIG", writeConfig(t,
		"version: 1",
		"server:",
		"  port: 9000",
		"  basePath: /suppline/",
		"  readOnly: true",
		"  allowNoAuth: true",
		"observability:",
		"  logLevel: debug",
		"  port: 9100",
		"mirror:",
		"  enabled: false",
		"scanner:",
		"  server: trivy:4954",
		"  timeout: 90s",
		"  insecure: true",
		"  localFallback: false",
		"attestation:",
		"  commandTimeout: 3m",
		"  allowHttpRegistry: true",
		"  newBundleFormat: false",
		"defaults:",
		"  queue-buffer-size: 2000",
		"  worker-retry-attempts: 5",
		"  worker-poll-interval: 15s",
		"  worker-retry-backoff: 1m",
		"sync: []",
	))
	t.Setenv("SUPPLINE_API_KEY", "k")
	t.Setenv("POSTGRES_URL", "postgres://x")
	t.Setenv("TRIVY_TOKEN", "tok")
	t.Setenv("ATTESTATION_KEY", "a2V5")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}

	checks := []struct {
		name      string
		got, want any
	}{
		{"api port", cfg.API.Port, 9000},
		{"base path", cfg.API.BasePath, "/suppline"},
		{"read only", cfg.API.ReadOnly, true},
		{"allow no auth", cfg.API.AllowNoAuth, true},
		{"api key", cfg.API.APIKey, "k"},
		{"observability port", cfg.Observability.Port, 9100},
		{"log level", cfg.Observability.LogLevel, "debug"},
		{"mirror", cfg.MirrorEnabled, false},
		{"trivy server", cfg.Scanner.ServerAddr, "trivy:4954"},
		{"trivy timeout", cfg.Scanner.Timeout, 90 * time.Second},
		{"trivy insecure", cfg.Scanner.Insecure, true},
		{"local fallback", cfg.Scanner.LocalFallback, false},
		{"trivy token", cfg.Scanner.Token, "tok"},
		{"postgres url", cfg.StateStore.PostgresURL, "postgres://x"},
		{"queue buffer", cfg.Queue.BufferSize, 2000},
		{"retry attempts", cfg.Worker.RetryAttempts, 5},
		{"poll interval", cfg.Worker.PollInterval, 15 * time.Second},
		{"retry backoff", cfg.Worker.RetryBackoff, time.Minute},
		{"attest key", cfg.Attestation.Key, "a2V5"},
		{"attest timeout", cfg.Attestation.CommandTimeout, 3 * time.Minute},
		{"http registry", cfg.Attestation.AllowHTTPRegistry, true},
		{"bundle format", cfg.Attestation.NewBundleFormat, false},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s = %v, want %v", c.name, c.got, c.want)
		}
	}
}

func TestLoad_Errors(t *testing.T) {
	cases := map[string][]string{
		"old x- key":          {"version: 1", "defaults:", "  x-rescanInterval: 1d", "sync: []"},
		"unknown section":     {"version: 1", "api:", "  port: 1", "sync: []"},
		"misspelled key":      {"version: 1", "server:", "  prot: 8080", "sync: []"},
		"bad timeout":         {"version: 1", "scanner:", "  timeout: soon", "sync: []"},
		"bad attest timeout":  {"version: 1", "attestation:", "  commandTimeout: -1s", "sync: []"},
		"bad poll interval":   {"version: 1", "defaults:", "  worker-poll-interval: often", "sync: []"},
		"bad rescan interval": {"version: 1", "defaults:", "  rescanInterval: 5s", "sync: []"},
	}
	for name, lines := range cases {
		t.Run(name, func(t *testing.T) {
			clearSecretEnv(t)
			t.Setenv("SUPPLINE_CONFIG", writeConfig(t, lines...))
			if _, err := Load(); err == nil {
				t.Fatal("Load succeeded, want error")
			}
		})
	}

	t.Run("missing file", func(t *testing.T) {
		t.Setenv("SUPPLINE_CONFIG", filepath.Join(t.TempDir(), "nope.yml"))
		if _, err := Load(); err == nil {
			t.Fatal("Load succeeded, want error")
		}
	})
}

func TestValidate(t *testing.T) {
	valid := func() *Config {
		return &Config{
			RegsyncPath: writeConfig(t, "version: 1", "sync: []"),
			Attestation: AttestationConfig{Key: "a2V5"},
			API:         APIConfig{APIKey: "k"},
			StateStore:  StateStoreConfig{PostgresURL: "postgres://x"},
		}
	}

	if err := valid().Validate(); err != nil {
		t.Fatalf("valid config: %v", err)
	}

	cases := map[string]func(*Config){
		"missing attestation key": func(c *Config) { c.Attestation.Key = "" },
		"missing postgres url":    func(c *Config) { c.StateStore.PostgresURL = "" },
		"missing api key":         func(c *Config) { c.API.APIKey = "" },
		"bad base path":           func(c *Config) { c.API.BasePath = "suppline" },
		"missing config file":     func(c *Config) { c.RegsyncPath = filepath.Join(t.TempDir(), "nope.yml") },
		"oidc issuer not https":   func(c *Config) { c.API.OIDC = &OIDCSettings{Issuer: "http://gitlab.com", Audience: "a"} },
		"oidc without audience":   func(c *Config) { c.API.OIDC = &OIDCSettings{Issuer: "https://gitlab.com"} },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			c := valid()
			mutate(c)
			if err := c.Validate(); err == nil {
				t.Fatal("Validate succeeded, want error")
			}
		})
	}

	t.Run("oidc claim defaults to project_path", func(t *testing.T) {
		c := valid()
		c.API.OIDC = &OIDCSettings{Issuer: "https://gitlab.com", Audience: "https://suppline.example"}
		if err := c.Validate(); err != nil {
			t.Fatalf("Validate: %v", err)
		}
		if c.API.OIDC.Claim != DefaultOIDCClaim {
			t.Fatalf("claim = %q", c.API.OIDC.Claim)
		}
	})

	t.Run("allowNoAuth permits an empty api key", func(t *testing.T) {
		c := valid()
		c.API.APIKey = ""
		c.API.AllowNoAuth = true
		if err := c.Validate(); err != nil {
			t.Fatalf("Validate: %v", err)
		}
	})
}

func TestLoad_RejectsRemovedStoreSection(t *testing.T) {
	clearSecretEnv(t)
	t.Setenv("SUPPLINE_CONFIG", writeConfig(t, "version: 1", "store:", "  sqlitePath: suppline.db", "sync: []"))

	_, err := Load()
	if err == nil || !strings.Contains(err.Error(), "SQLite support was removed") {
		t.Fatalf("Load error = %v, want a hint that SQLite support was removed", err)
	}
}

func TestValidate_RequiresPostgresURL(t *testing.T) {
	clearSecretEnv(t)
	t.Setenv("SUPPLINE_CONFIG", writeConfig(t, "version: 1", "sync: []"))
	t.Setenv("ATTESTATION_KEY", "a2V5")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "POSTGRES_URL is required") {
		t.Fatalf("Validate error = %v, want POSTGRES_URL is required", err)
	}
}

// The chart and the docs set the address from the pod IP with a template.
func TestLoad_ExpandsAdvertiseAddressTemplate(t *testing.T) {
	clearSecretEnv(t)
	t.Setenv("POD_IP", "10.42.0.7")
	t.Setenv("SUPPLINE_CONFIG", writeConfig(t, "version: 1", "server:",
		`  advertiseAddress: 'http://{{ env "POD_IP" }}:8080'`, "sync: []"))

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.API.AdvertiseAddress != "http://10.42.0.7:8080" {
		t.Fatalf("advertise address = %q, want http://10.42.0.7:8080", cfg.API.AdvertiseAddress)
	}
}

func TestValidate_AdvertiseAddress(t *testing.T) {
	base := func() *Config {
		return &Config{
			RegsyncPath: writeConfig(t, "version: 1", "sync: []"),
			Attestation: AttestationConfig{Key: "a2V5"},
			API:         APIConfig{APIKey: "k", Port: 8080},
			StateStore:  StateStoreConfig{PostgresURL: "postgres://x"},
		}
	}

	c := base()
	if err := c.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if !strings.HasPrefix(c.API.AdvertiseAddress, "http://") || !strings.HasSuffix(c.API.AdvertiseAddress, ":8080") {
		t.Fatalf("default advertise address = %q, want http://<host>:8080", c.API.AdvertiseAddress)
	}

	c = base()
	c.API.AdvertiseAddress = "http://10.0.3.7:8080"
	if err := c.Validate(); err != nil || c.API.AdvertiseAddress != "http://10.0.3.7:8080" {
		t.Fatalf("explicit address: %v, %q", err, c.API.AdvertiseAddress)
	}

	for _, bad := range []string{"10.0.3.7:8080", "ftp://x", "http://"} {
		c = base()
		c.API.AdvertiseAddress = bad
		if err := c.Validate(); err == nil {
			t.Errorf("Validate accepted advertise address %q", bad)
		}
	}
}
