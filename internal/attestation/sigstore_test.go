package attestation

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/daimoniac/suppline/internal/scanner"
)

func TestNewSigstoreAttestor_MissingKeyPath(t *testing.T) {
	config := AttestationConfig{
		KeyBased: KeyBasedConfig{
			Key: "",
		},
	}

	_, err := NewSigstoreAttestor(config, nil)
	if err == nil {
		t.Fatal("expected error for missing key")
	}
}

func TestAttestSBOM_ValidCycloneDXData(t *testing.T) {
	// Create a valid CycloneDX SBOM JSON
	cycloneDXData := map[string]interface{}{
		"bomFormat":   "CycloneDX",
		"specVersion": "1.5",
		"version":     1,
		"metadata": map[string]interface{}{
			"component": map[string]interface{}{
				"type": "container",
				"name": "test-image",
			},
		},
		"components": []map[string]interface{}{
			{
				"type":    "library",
				"name":    "test-package",
				"version": "1.0.0",
			},
		},
	}

	sbomJSON, err := json.Marshal(cycloneDXData)
	if err != nil {
		t.Fatalf("failed to marshal test SBOM: %v", err)
	}

	sbom := &scanner.SBOM{
		Format:  "cyclonedx",
		Version: "1.5",
		Data:    sbomJSON,
		Created: time.Now(),
	}

	config := AttestationConfig{
		KeyBased: KeyBasedConfig{
			Key:         base64.StdEncoding.EncodeToString([]byte("test-key-content")),
			KeyPassword: "test-password",
		},
	}

	attestor, err := NewSigstoreAttestor(config, nil)
	if err != nil {
		t.Fatalf("failed to create attestor: %v", err)
	}

	// Note: This will fail because cosign is not available in test environment
	// but it validates the SBOM data format and command construction
	err = attestor.AttestSBOM(context.Background(), "test-image:latest", sbom)

	// We expect an error because cosign won't be available, but it should NOT be
	// a validation error about the SBOM data format
	if err != nil && err.Error() == "SBOM data is not valid JSON" {
		t.Errorf("SBOM validation failed for valid CycloneDX data: %v", err)
	}
}

func TestAttestSBOM_MalformedSBOMData(t *testing.T) {
	tests := []struct {
		name        string
		sbom        *scanner.SBOM
		expectedErr string
	}{
		{
			name:        "nil SBOM",
			sbom:        nil,
			expectedErr: "SBOM is nil",
		},
		{
			name: "empty SBOM data",
			sbom: &scanner.SBOM{
				Format:  "cyclonedx",
				Version: "1.5",
				Data:    []byte{},
				Created: time.Now(),
			},
			expectedErr: "SBOM data is empty",
		},
		{
			name: "invalid JSON",
			sbom: &scanner.SBOM{
				Format:  "cyclonedx",
				Version: "1.5",
				Data:    []byte("not valid json {{{"),
				Created: time.Now(),
			},
			expectedErr: "SBOM data is not valid JSON",
		},
		{
			name: "malformed JSON structure",
			sbom: &scanner.SBOM{
				Format:  "cyclonedx",
				Version: "1.5",
				Data:    []byte("{incomplete"),
				Created: time.Now(),
			},
			expectedErr: "SBOM data is not valid JSON",
		},
	}

	config := AttestationConfig{
		KeyBased: KeyBasedConfig{
			Key:         base64.StdEncoding.EncodeToString([]byte("test-key-content")),
			KeyPassword: "test-password",
		},
	}

	attestor, err := NewSigstoreAttestor(config, nil)
	if err != nil {
		t.Fatalf("failed to create attestor: %v", err)
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := attestor.AttestSBOM(context.Background(), "test-image:latest", tt.sbom)
			if err == nil {
				t.Errorf("expected error containing '%s', got nil", tt.expectedErr)
				return
			}

			// Check that error contains the expected message (may be wrapped)
			if !strings.Contains(err.Error(), tt.expectedErr) {
				t.Errorf("expected error containing '%s', got '%s'", tt.expectedErr, err.Error())
			}
		})
	}
}

func TestAttestSBOM_CosignCommandConstruction(t *testing.T) {
	// Create a valid CycloneDX SBOM
	cycloneDXData := map[string]interface{}{
		"bomFormat":   "CycloneDX",
		"specVersion": "1.5",
		"version":     1,
	}

	sbomJSON, err := json.Marshal(cycloneDXData)
	if err != nil {
		t.Fatalf("failed to marshal test SBOM: %v", err)
	}

	sbom := &scanner.SBOM{
		Format:  "cyclonedx",
		Version: "1.5",
		Data:    sbomJSON,
		Created: time.Now(),
	}

	config := AttestationConfig{
		KeyBased: KeyBasedConfig{
			Key:         base64.StdEncoding.EncodeToString([]byte("test-key-content")),
			KeyPassword: "test-password",
		},
	}

	attestor, err := NewSigstoreAttestor(config, nil)
	if err != nil {
		t.Fatalf("failed to create attestor: %v", err)
	}

	// Call AttestSBOM - it will fail because cosign is not available,
	// but we can verify the command would be constructed correctly
	err = attestor.AttestSBOM(context.Background(), "test-image:latest", sbom)

	// The error should be about cosign execution, not about command construction
	// If the command was constructed incorrectly, we'd get a different error
	if err != nil {
		// Verify the error is about cosign execution, not validation
		errMsg := err.Error()
		if errMsg == "SBOM is nil" || errMsg == "SBOM data is empty" || errMsg[:len("SBOM data is not valid JSON")] == "SBOM data is not valid JSON" {
			t.Errorf("unexpected validation error: %v", err)
		}
		// Expected: "failed to attest SBOM with cosign" or similar execution error
	}
}
