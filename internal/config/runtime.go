package config

import (
	"fmt"
	"strings"
	"time"
)

// Runtime settings in suppline.yml. They are read once at startup; changing
// them needs a restart. Secrets stay in environment variables (see Load).

// ServerSettings configures the HTTP server for the web UI, API and Swagger.
type ServerSettings struct {
	Port int `yaml:"port,omitempty"`
	// BasePath is the URL prefix everything is served under, e.g. /suppline.
	BasePath string `yaml:"basePath,omitempty"`
	ReadOnly bool   `yaml:"readOnly,omitempty"`
	// AllowNoAuth starts the API without SUPPLINE_API_KEY. Isolated evaluation only.
	AllowNoAuth bool `yaml:"allowNoAuth,omitempty"`
	// OIDC lets CI jobs authenticate scan requests with an OIDC ID token,
	// such as a GitLab CI id_token, instead of the API key.
	OIDC *OIDCSettings `yaml:"oidc,omitempty"`
	// AdvertiseAddress is the URL other instances use to reach this one's
	// API, e.g. http://10.0.3.7:8080. Default: the first non-loopback IPv4
	// address and server.port.
	AdvertiseAddress string `yaml:"advertiseAddress,omitempty"`
}

// OIDCSettings configures the OIDC issuer whose ID tokens may request scans.
type OIDCSettings struct {
	// Issuer is the token issuer, e.g. https://gitlab.com.
	Issuer string `yaml:"issuer"`
	// Audience is the aud the CI job requests for its token.
	Audience string `yaml:"audience"`
	// Claim names the token claim matched against an in-place entry's
	// scan-requesters. Default: project_path (GitLab).
	Claim string `yaml:"claim,omitempty"`
}

// DefaultOIDCClaim is the GitLab CI claim naming the project that ran the job.
const DefaultOIDCClaim = "project_path"

// ObservabilitySettings configures logging and the operations port.
type ObservabilitySettings struct {
	LogLevel string `yaml:"logLevel,omitempty"`
	// Port serves /metrics, /health and /ready.
	Port int `yaml:"port,omitempty"`
}

// MirrorSettings configures the in-process mirror.
type MirrorSettings struct {
	// Enabled copies sync entries into the target registry. Nil means true.
	Enabled *bool `yaml:"enabled,omitempty"`
}

// ScannerSettings configures the Trivy client.
type ScannerSettings struct {
	// Server is the Trivy server address, host:port.
	Server   string `yaml:"server,omitempty"`
	Timeout  string `yaml:"timeout,omitempty"`
	Insecure bool   `yaml:"insecure,omitempty"`
	// LocalFallback retries a failed server-mode scan locally. Nil means true.
	LocalFallback *bool `yaml:"localFallback,omitempty"`
}

// AttestationSettings configures how cosign writes attestations.
type AttestationSettings struct {
	// CommandTimeout bounds one cosign invocation.
	CommandTimeout string `yaml:"commandTimeout,omitempty"`
	// AllowHTTPRegistry lets cosign talk to plain-HTTP registries.
	AllowHTTPRegistry bool `yaml:"allowHttpRegistry,omitempty"`
	// NewBundleFormat writes Sigstore protobuf bundles. Nil means true; false
	// writes classic sha256-<digest>.att tags.
	NewBundleFormat *bool `yaml:"newBundleFormat,omitempty"`
}

const (
	defaultAPIPort              = 8080
	defaultObservabilityPort    = 9090
	defaultLogLevel             = "info"
	defaultTrivyServer          = "localhost:4954"
	defaultTrivyTimeout         = 5 * time.Minute
	defaultAttestCommandTimeout = 2 * time.Minute
)

func boolOr(v *bool, def bool) bool {
	if v == nil {
		return def
	}
	return *v
}

func intOr(v, def int) int {
	if v == 0 {
		return def
	}
	return v
}

func stringOr(v, def string) string {
	if s := strings.TrimSpace(v); s != "" {
		return s
	}
	return def
}

// parseDurationSetting parses a Go duration (e.g. "90s", "5m"); empty means def.
func parseDurationSetting(field, v string, def time.Duration) (time.Duration, error) {
	s := strings.TrimSpace(v)
	if s == "" {
		return def, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("%s must be a positive duration like 90s or 5m, got %q", field, v)
	}
	return d, nil
}
