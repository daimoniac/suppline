package scanner

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestGenerateDockerConfigFromRegsync(t *testing.T) {
	// Create a temporary regsync.yml file
	tmpDir := t.TempDir()
	regsyncPath := filepath.Join(tmpDir, "regsync.yml")
	
	regsyncContent := `version: 1
creds:
- registry: docker.io
  user: testuser
  pass: testpass
- registry: ghcr.io
  user: ghuser
  pass: ghpass
`
	
	if err := os.WriteFile(regsyncPath, []byte(regsyncContent), 0600); err != nil {
		t.Fatalf("failed to create test regsync file: %v", err)
	}
	
	// Generate Docker config
	configDir, err := GenerateDockerConfigFromRegsync(regsyncPath)
	if err != nil {
		t.Fatalf("GenerateDockerConfigFromRegsync failed: %v", err)
	}
	
	// Verify config directory exists
	if _, err := os.Stat(configDir); os.IsNotExist(err) {
		t.Fatalf("config directory does not exist: %s", configDir)
	}
	
	// Read and parse the generated config.json
	configPath := filepath.Join(configDir, "config.json")
	configData, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("failed to read config.json: %v", err)
	}
	
	var dockerConfig DockerConfig
	if err := json.Unmarshal(configData, &dockerConfig); err != nil {
		t.Fatalf("failed to parse config.json: %v", err)
	}
	
	// Verify docker.io credentials (should be mapped to https://index.docker.io/v1/)
	dockerAuth, ok := dockerConfig.Auths["https://index.docker.io/v1/"]
	if !ok {
		t.Errorf("docker.io credentials not found in config (should be https://index.docker.io/v1/)")
	} else {
		// Decode and verify auth
		decoded, err := base64.StdEncoding.DecodeString(dockerAuth.Auth)
		if err != nil {
			t.Errorf("failed to decode auth: %v", err)
		}
		expected := "testuser:testpass"
		if string(decoded) != expected {
			t.Errorf("docker.io auth mismatch: got %s, want %s", string(decoded), expected)
		}
	}
	
	// Verify ghcr.io credentials
	ghcrAuth, ok := dockerConfig.Auths["ghcr.io"]
	if !ok {
		t.Errorf("ghcr.io credentials not found in config")
	} else {
		decoded, err := base64.StdEncoding.DecodeString(ghcrAuth.Auth)
		if err != nil {
			t.Errorf("failed to decode auth: %v", err)
		}
		expected := "ghuser:ghpass"
		if string(decoded) != expected {
			t.Errorf("ghcr.io auth mismatch: got %s, want %s", string(decoded), expected)
		}
	}
	
	t.Logf("Generated Docker config at: %s", configPath)
	t.Logf("Config content: %s", string(configData))
}

func TestGenerateDockerConfigFromRegsync_InvalidFile(t *testing.T) {
	_, err := GenerateDockerConfigFromRegsync("/nonexistent/regsync.yml")
	if err == nil {
		t.Error("expected error for nonexistent file, got nil")
	}
}

func TestGenerateDockerConfigFromRegsync_InvalidYAML(t *testing.T) {
	tmpDir := t.TempDir()
	regsyncPath := filepath.Join(tmpDir, "regsync.yml")
	
	// Write invalid YAML
	if err := os.WriteFile(regsyncPath, []byte("invalid: yaml: content: ["), 0600); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}
	
	_, err := GenerateDockerConfigFromRegsync(regsyncPath)
	if err == nil {
		t.Error("expected error for invalid YAML, got nil")
	}
}
