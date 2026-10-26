package config

import (
	"fmt"
	"strings"
	"time"

	"github.com/daimoniac/suppline/internal/types"
)

const (
	TriageModeDryRun  = "dry-run"
	TriageModeEnforce = "enforce"

	GitAuthHTTPSToken = "https-token"
	GitAuthSSH        = "ssh"
)

// TriageConfig is the x-triage block. The LLM API key is never stored here;
// it is read from SUPPLINE_LLM_API_KEY.
type TriageConfig struct {
	Enabled               bool              `yaml:"enabled"`
	OnlyInUse             *bool             `yaml:"only_in_use,omitempty"`
	Mode                  string            `yaml:"mode,omitempty"`
	LLM                   TriageLLMConfig   `yaml:"llm"`
	MinConfidence         *float64          `yaml:"min_confidence,omitempty"`
	Expiry                string            `yaml:"expiry,omitempty"`
	RenewBefore           string            `yaml:"renew_before,omitempty"`
	RetriageInterval      string            `yaml:"retriage_interval,omitempty"`
	AllowedJustifications []string          `yaml:"allowed_justifications,omitempty"`
	BlockKEV              *bool             `yaml:"block_kev,omitempty"`
	KEVFeedURL            string            `yaml:"kev_feed_url,omitempty"`
	KEVCacheTTL           string            `yaml:"kev_cache_ttl,omitempty"`
	ContextRepos          []GitRepoConfig   `yaml:"context_repos,omitempty"`
	ConfigRepo            *ConfigRepoConfig `yaml:"config_repo,omitempty"`
	BackupRetention       int               `yaml:"backup_retention,omitempty"`
	CheckoutDir           string            `yaml:"checkout_dir,omitempty"`
	MaxFileBytes          int               `yaml:"max_file_bytes,omitempty"`
	// Prompt replaces the built-in decision policy. The tool workflow and the
	// JSON output contract stay in place. Empty uses the built-in policy.
	Prompt string `yaml:"prompt,omitempty"`
}

// TriageLLMConfig selects an OpenAI-compatible chat completions endpoint.
type TriageLLMConfig struct {
	BaseURL          string `yaml:"base_url"`
	Model            string `yaml:"model"`
	MaxSteps         int    `yaml:"max_steps,omitempty"`
	DailyTokenBudget int    `yaml:"daily_token_budget,omitempty"`
}

// GitAuthConfig names environment variables that hold git credentials.
type GitAuthConfig struct {
	Type          string `yaml:"type"`
	Env           string `yaml:"env,omitempty"`
	Username      string `yaml:"username,omitempty"`
	KeyEnv        string `yaml:"key_env,omitempty"`
	KnownHostsEnv string `yaml:"known_hosts_env,omitempty"`
}

// GitRepoConfig is a read-only gitops checkout used as triage context.
type GitRepoConfig struct {
	Name    string        `yaml:"name,omitempty"`
	URL     string        `yaml:"url"`
	Branch  string        `yaml:"branch,omitempty"`
	Auth    GitAuthConfig `yaml:"auth"`
	Include []string      `yaml:"include,omitempty"`
	Exclude []string      `yaml:"exclude,omitempty"`
}

// ConfigRepoConfig is the gitops repository that contains suppline.yml.
// When it is absent, triage writes the local file instead.
type ConfigRepoConfig struct {
	URL    string        `yaml:"url"`
	Branch string        `yaml:"branch,omitempty"`
	Path   string        `yaml:"path"`
	Auth   GitAuthConfig `yaml:"auth"`
	Author GitAuthor     `yaml:"author"`
}

// GitAuthor is the committer used for auto-triage commits.
type GitAuthor struct {
	Name  string `yaml:"name"`
	Email string `yaml:"email"`
}

// DefaultTriageJustifications are the justifications an automatic decision may use.
// The deployment justifications come from the gitops checkout. code_not_reachable
// comes from an upstream call site the agent read.
func DefaultTriageJustifications() []string {
	return []string{
		string(types.VEXJustRequiresConfiguration),
		string(types.VEXJustRequiresEnvironment),
		string(types.VEXJustProtectedAtPerimeter),
		string(types.VEXJustProtectedAtRuntime),
		string(types.VEXJustProtectedByMitigations),
		string(types.VEXJustCodeNotReachable),
	}
}

// Validate reports configuration errors for an enabled triage block.
func (t *TriageConfig) Validate() error {
	if t == nil || !t.Enabled {
		return nil
	}
	mode := t.Mode
	if mode == "" {
		mode = TriageModeDryRun
	}
	if mode != TriageModeDryRun && mode != TriageModeEnforce {
		return fmt.Errorf("x-triage.mode must be %q or %q, got %q", TriageModeDryRun, TriageModeEnforce, t.Mode)
	}
	if strings.TrimSpace(t.LLM.BaseURL) == "" || strings.TrimSpace(t.LLM.Model) == "" {
		return fmt.Errorf("x-triage.llm.base_url and x-triage.llm.model are required when triage is enabled")
	}
	if t.MinConfidence != nil && (*t.MinConfidence < 0 || *t.MinConfidence > 1) {
		return fmt.Errorf("x-triage.min_confidence must be between 0 and 1")
	}
	for _, field := range []struct{ name, value string }{
		{"expiry", t.Expiry},
		{"renew_before", t.RenewBefore},
		{"retriage_interval", t.RetriageInterval},
		{"kev_cache_ttl", t.KEVCacheTTL},
	} {
		if field.value == "" {
			continue
		}
		if _, err := ParseFlexibleDuration(field.value); err != nil {
			return fmt.Errorf("x-triage.%s: %w", field.name, err)
		}
	}
	for _, justification := range t.AllowedJustifications {
		stmt := types.VEXStatement{
			ID:            "triage-config",
			State:         types.VEXStateNotAffected,
			Justification: types.VEXJustification(justification),
		}
		if err := types.ValidateVEXStatement(stmt); err != nil {
			return fmt.Errorf("x-triage.allowed_justifications: %w", err)
		}
	}
	for i, repo := range t.ContextRepos {
		if err := validateGitAuth(fmt.Sprintf("x-triage.context_repos[%d]", i), repo.URL, repo.Auth); err != nil {
			return err
		}
	}
	if t.ConfigRepo != nil {
		if strings.TrimSpace(t.ConfigRepo.Path) == "" {
			return fmt.Errorf("x-triage.config_repo.path is required")
		}
		if err := validateGitAuth("x-triage.config_repo", t.ConfigRepo.URL, t.ConfigRepo.Auth); err != nil {
			return err
		}
	}
	if t.BackupRetention < 0 {
		return fmt.Errorf("x-triage.backup_retention must be >= 0")
	}
	if len(t.Prompt) > 16*1024 {
		return fmt.Errorf("x-triage.prompt must be at most 16KiB")
	}
	return nil
}

func validateGitAuth(where, rawURL string, auth GitAuthConfig) error {
	if strings.TrimSpace(rawURL) == "" {
		return fmt.Errorf("%s.url is required", where)
	}
	switch auth.Type {
	case GitAuthHTTPSToken:
		if strings.TrimSpace(auth.Env) == "" {
			return fmt.Errorf("%s.auth.env is required for https-token", where)
		}
	case GitAuthSSH:
		if strings.TrimSpace(auth.KeyEnv) == "" || strings.TrimSpace(auth.KnownHostsEnv) == "" {
			return fmt.Errorf("%s.auth.key_env and known_hosts_env are required for ssh", where)
		}
	case "":
		return fmt.Errorf("%s.auth.type is required", where)
	default:
		return fmt.Errorf("%s.auth.type must be %q or %q", where, GitAuthHTTPSToken, GitAuthSSH)
	}
	return nil
}

// ParseFlexibleDuration parses Go durations and a day suffix (30d).
func ParseFlexibleDuration(value string) (time.Duration, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, fmt.Errorf("empty duration")
	}
	if strings.HasSuffix(value, "d") {
		var days int
		if _, err := fmt.Sscanf(strings.TrimSuffix(value, "d"), "%d", &days); err != nil || days < 0 {
			return 0, fmt.Errorf("invalid duration %q", value)
		}
		return time.Duration(days) * 24 * time.Hour, nil
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		return 0, fmt.Errorf("invalid duration %q", value)
	}
	return parsed, nil
}
