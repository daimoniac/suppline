package gitops

import (
	"fmt"
	"os"
	"strings"

	suppconfig "github.com/daimoniac/suppline/internal/config"
)

// ResolveAuth reads the credentials named by cfg from the environment. An
// empty auth type is anonymous access.
func ResolveAuth(cfg suppconfig.GitAuthConfig) (Auth, error) {
	switch cfg.Type {
	case "":
		return Auth{}, nil
	case suppconfig.GitAuthHTTPSToken:
		token := os.Getenv(cfg.Env)
		if strings.TrimSpace(token) == "" {
			return Auth{}, fmt.Errorf("environment variable %s is empty", cfg.Env)
		}
		return Auth{Username: cfg.Username, Token: token}, nil
	case suppconfig.GitAuthSSH:
		key := os.Getenv(cfg.KeyEnv)
		hosts := os.Getenv(cfg.KnownHostsEnv)
		if strings.TrimSpace(key) == "" || strings.TrimSpace(hosts) == "" {
			return Auth{}, fmt.Errorf("environment variables %s and %s are required", cfg.KeyEnv, cfg.KnownHostsEnv)
		}
		return Auth{
			Username:   cfg.Username,
			PrivateKey: NormalizeSecret(key),
			KnownHosts: NormalizeSecret(hosts),
		}, nil
	default:
		return Auth{}, fmt.Errorf("unsupported git auth type %q", cfg.Type)
	}
}
