package scanner

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/suppline/suppline/internal/errors"
	"gopkg.in/yaml.v3"
)

// RegsyncConfig represents the regsync configuration structure
type RegsyncConfig struct {
	Creds []struct {
		Registry string `yaml:"registry"`
		User     string `yaml:"user"`
		Pass     string `yaml:"pass"`
	} `yaml:"creds"`
}

// DockerConfig represents Docker's config.json structure
type DockerConfig struct {
	Auths map[string]DockerAuth `json:"auths"`
}

// DockerAuth represents authentication for a single registry
type DockerAuth struct {
	Auth string `json:"auth"`
}

// GenerateDockerConfigFromRegsync reads suppline.yml and generates a Docker config.json
// that Trivy can use for registry authentication
func GenerateDockerConfigFromRegsync(regsyncPath string) (string, error) {
	// Read suppline.yml
	data, err := os.ReadFile(regsyncPath)
	if err != nil {
		return "", errors.NewTransientf("failed to read regsync config: %w", err)
	}

	// Parse regsync config
	var regsync RegsyncConfig
	if err := yaml.Unmarshal(data, &regsync); err != nil {
		return "", errors.NewPermanentf("failed to parse regsync config: %w", err)
	}

	// Build Docker config
	dockerConfig := DockerConfig{
		Auths: make(map[string]DockerAuth),
	}

	for _, cred := range regsync.Creds {
		// Docker uses base64(username:password) for auth
		auth := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", cred.User, cred.Pass)))
		
		// Normalize registry name (docker.io is the default)
		registry := cred.Registry
		if registry == "docker.io" {
			// Docker config uses the full URL format for docker.io
			registry = "https://index.docker.io/v1/"
		}
		
		dockerConfig.Auths[registry] = DockerAuth{
			Auth: auth,
		}
	}

	// Create temp directory for Docker config
	configDir := filepath.Join(os.TempDir(), "trivy-docker-config")
	if err := os.MkdirAll(configDir, 0700); err != nil {
		return "", errors.NewTransientf("failed to create config directory: %w", err)
	}

	// Write config.json
	configPath := filepath.Join(configDir, "config.json")
	configJSON, err := json.MarshalIndent(dockerConfig, "", "  ")
	if err != nil {
		return "", errors.NewPermanentf("failed to marshal docker config: %w", err)
	}

	if err := os.WriteFile(configPath, configJSON, 0600); err != nil {
		return "", errors.NewTransientf("failed to write docker config: %w", err)
	}

	return configDir, nil
}
