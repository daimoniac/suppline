package integration

import (
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"

	"github.com/daimoniac/suppline/internal/config"
	"github.com/daimoniac/suppline/internal/errors"
)

// ExtractPublicKey extracts the public key from a base64-encoded private key using cosign
// The ATTESTATION_KEY_PASSWORD environment variable should be set if the key is encrypted
func ExtractPublicKey(base64Key string) (string, error) {
	// Decode base64 key
	keyData, err := base64.StdEncoding.DecodeString(base64Key)
	if err != nil {
		return "", errors.NewPermanentf("failed to decode base64 key: %w", err)
	}

	// Write key to temporary file
	tmpFile, err := os.CreateTemp("", "cosign-key-*.key")
	if err != nil {
		return "", errors.NewPermanentf("failed to create temp key file: %w", err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.Write(keyData); err != nil {
		tmpFile.Close()
		return "", errors.NewPermanentf("failed to write key to temp file: %w", err)
	}
	tmpFile.Close()

	// Set restrictive permissions on key file
	if err := os.Chmod(tmpFile.Name(), 0600); err != nil {
		return "", errors.NewPermanentf("failed to set key file permissions: %w", err)
	}

	// Use cosign to extract the public key
	// ATTESTATION_KEY_PASSWORD will be read from the environment if set
	cmd := exec.Command("cosign", "public-key", "--key", tmpFile.Name())
	cmd.Env = os.Environ()
	// Ensure COSIGN_PASSWORD is set from ATTESTATION_KEY_PASSWORD if available
	if password := os.Getenv("ATTESTATION_KEY_PASSWORD"); password != "" {
		cmd.Env = append(cmd.Env, "COSIGN_PASSWORD="+password)
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", errors.NewPermanentf("failed to extract public key using cosign: %w (output: %s)", err, string(output))
	}

	return string(output), nil
}

// GetPublicKeyFromConfig extracts the public key from the attestation config
func GetPublicKeyFromConfig(cfg config.AttestationConfig) (string, error) {
	if cfg.KeyBased.Key == "" {
		return "", fmt.Errorf("no attestation key configured")
	}

	return ExtractPublicKey(cfg.KeyBased.Key)
}
