package triage

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/daimoniac/suppline/internal/config"
	"github.com/daimoniac/suppline/internal/gitops"
	"github.com/daimoniac/suppline/internal/types"
)

const (
	envLLMAPIKey = "SUPPLINE_LLM_API_KEY"

	defaultKEVFeed = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)

// Settings is the resolved runtime view of x-triage.
type Settings struct {
	Enabled          bool
	OnlyInUse        bool
	Mode             string
	BaseURL          string
	Model            string
	APIKey           string
	MaxSteps         int
	DailyTokenBudget int
	MinConfidence    float64
	Expiry           time.Duration
	RenewBefore      time.Duration
	RetriageInterval time.Duration
	Allowed          map[types.VEXJustification]struct{}
	BlockKEV         bool
	KEVFeedURL       string
	KEVCacheTTL      time.Duration
	Context          []config.GitRepoConfig
	ConfigRepo       *config.ConfigRepoConfig
	BackupRetention  int
	CheckoutDir      string
	MaxFileBytes     int
	ConfigPath       string
}

// Resolve applies defaults. An enabled block with an empty API key is returned
// disabled so the process can still start.
func Resolve(cfg *config.TriageConfig, configPath string) (Settings, error) {
	settings := Settings{
		Mode:             config.TriageModeDryRun,
		OnlyInUse:        true,
		MaxSteps:         20,
		DailyTokenBudget: 2_000_000,
		MinConfidence:    0.8,
		Expiry:           30 * 24 * time.Hour,
		RenewBefore:      7 * 24 * time.Hour,
		RetriageInterval: 24 * time.Hour,
		BlockKEV:         true,
		KEVFeedURL:       defaultKEVFeed,
		KEVCacheTTL:      12 * time.Hour,
		BackupRetention:  10,
		CheckoutDir:      "/data/gitops",
		MaxFileBytes:     32 * 1024,
		ConfigPath:       configPath,
		Allowed:          justificationSet(config.DefaultTriageJustifications()),
	}
	if cfg == nil || !cfg.Enabled {
		settings.Enabled = false
		return settings, nil
	}
	if err := cfg.Validate(); err != nil {
		return Settings{}, err
	}
	settings.Enabled = true
	settings.APIKey = strings.TrimSpace(os.Getenv(envLLMAPIKey))
	if settings.APIKey == "" {
		settings.Enabled = false
		return settings, nil
	}
	if cfg.OnlyInUse != nil {
		settings.OnlyInUse = *cfg.OnlyInUse
	}
	if cfg.Mode != "" {
		settings.Mode = cfg.Mode
	}
	settings.BaseURL = strings.TrimRight(strings.TrimSpace(cfg.LLM.BaseURL), "/")
	settings.Model = strings.TrimSpace(cfg.LLM.Model)
	if cfg.LLM.MaxSteps > 0 {
		settings.MaxSteps = cfg.LLM.MaxSteps
	}
	if cfg.LLM.DailyTokenBudget > 0 {
		settings.DailyTokenBudget = cfg.LLM.DailyTokenBudget
	}
	if cfg.MinConfidence != nil {
		settings.MinConfidence = *cfg.MinConfidence
	}
	if cfg.Expiry != "" {
		parsed, err := config.ParseFlexibleDuration(cfg.Expiry)
		if err != nil {
			return Settings{}, err
		}
		settings.Expiry = parsed
	}
	if cfg.RenewBefore != "" {
		parsed, err := config.ParseFlexibleDuration(cfg.RenewBefore)
		if err != nil {
			return Settings{}, err
		}
		settings.RenewBefore = parsed
	}
	if cfg.RetriageInterval != "" {
		parsed, err := config.ParseFlexibleDuration(cfg.RetriageInterval)
		if err != nil {
			return Settings{}, err
		}
		settings.RetriageInterval = parsed
	}
	if len(cfg.AllowedJustifications) > 0 {
		settings.Allowed = justificationSet(cfg.AllowedJustifications)
	}
	if cfg.BlockKEV != nil {
		settings.BlockKEV = *cfg.BlockKEV
	}
	if strings.TrimSpace(cfg.KEVFeedURL) != "" {
		settings.KEVFeedURL = strings.TrimSpace(cfg.KEVFeedURL)
	}
	if cfg.KEVCacheTTL != "" {
		parsed, err := config.ParseFlexibleDuration(cfg.KEVCacheTTL)
		if err != nil {
			return Settings{}, err
		}
		settings.KEVCacheTTL = parsed
	}
	if cfg.BackupRetention > 0 {
		settings.BackupRetention = cfg.BackupRetention
	}
	if strings.TrimSpace(cfg.CheckoutDir) != "" {
		settings.CheckoutDir = strings.TrimSpace(cfg.CheckoutDir)
	}
	if cfg.MaxFileBytes > 0 {
		settings.MaxFileBytes = cfg.MaxFileBytes
	}
	settings.Context = append([]config.GitRepoConfig(nil), cfg.ContextRepos...)
	settings.ConfigRepo = cfg.ConfigRepo
	return settings, nil
}

func justificationSet(values []string) map[types.VEXJustification]struct{} {
	set := make(map[types.VEXJustification]struct{}, len(values))
	for _, value := range values {
		set[types.NormalizeVEXJustification(types.VEXJustification(value))] = struct{}{}
	}
	return set
}

func (s Settings) contextSpecs() ([]gitops.Spec, error) {
	specs := make([]gitops.Spec, 0, len(s.Context))
	for _, repo := range s.Context {
		auth, err := resolveAuth(repo.Auth)
		if err != nil {
			return nil, fmt.Errorf("context repo %s: %w", repo.URL, err)
		}
		specs = append(specs, gitops.Spec{
			Name:   repo.Name,
			URL:    repo.URL,
			Branch: repo.Branch,
			Auth:   auth,
		})
	}
	return specs, nil
}

func (s Settings) configSpec() (gitops.Spec, error) {
	if s.ConfigRepo == nil {
		return gitops.Spec{}, fmt.Errorf("no config repo")
	}
	auth, err := resolveAuth(s.ConfigRepo.Auth)
	if err != nil {
		return gitops.Spec{}, err
	}
	return gitops.Spec{
		Name:        "config",
		URL:         s.ConfigRepo.URL,
		Branch:      s.ConfigRepo.Branch,
		Auth:        auth,
		AuthorName:  s.ConfigRepo.Author.Name,
		AuthorEmail: s.ConfigRepo.Author.Email,
	}, nil
}

func resolveAuth(cfg config.GitAuthConfig) (gitops.Auth, error) {
	switch cfg.Type {
	case config.GitAuthHTTPSToken:
		token := os.Getenv(cfg.Env)
		if strings.TrimSpace(token) == "" {
			return gitops.Auth{}, fmt.Errorf("environment variable %s is empty", cfg.Env)
		}
		return gitops.Auth{Username: cfg.Username, Token: token}, nil
	case config.GitAuthSSH:
		key := os.Getenv(cfg.KeyEnv)
		hosts := os.Getenv(cfg.KnownHostsEnv)
		if strings.TrimSpace(key) == "" || strings.TrimSpace(hosts) == "" {
			return gitops.Auth{}, fmt.Errorf("environment variables %s and %s are required", cfg.KeyEnv, cfg.KnownHostsEnv)
		}
		return gitops.Auth{
			Username:   cfg.Username,
			PrivateKey: gitops.NormalizeSecret(key),
			KnownHosts: gitops.NormalizeSecret(hosts),
		}, nil
	default:
		return gitops.Auth{}, fmt.Errorf("unsupported git auth type %q", cfg.Type)
	}
}
