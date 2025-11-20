package integration

import (
	"testing"

	"github.com/daimoniac/suppline/internal/config"
)

func TestGetPublicKeyFromConfig_NoKey(t *testing.T) {
	cfg := config.AttestationConfig{
		KeyBased: struct {
			Key         string
			KeyPassword string
		}{
			Key:         "",
			KeyPassword: "",
		},
	}

	_, err := GetPublicKeyFromConfig(cfg)
	if err == nil {
		t.Error("Expected error when no key is configured")
	}
}
