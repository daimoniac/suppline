package attestation

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/daimoniac/suppline/internal/errors"
	"github.com/daimoniac/suppline/internal/scanner"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func writeFakeCosign(t *testing.T, script string) string {
	t.Helper()

	tempDir := t.TempDir()
	cosignPath := filepath.Join(tempDir, "cosign")
	if err := os.WriteFile(cosignPath, []byte(script), 0755); err != nil {
		t.Fatalf("failed to write fake cosign: %v", err)
	}

	return tempDir
}

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

func TestResolveCosignAttestTimeout_DefaultAndInvalid(t *testing.T) {
	t.Setenv("ATTESTATION_COMMAND_TIMEOUT", "")
	if timeout := resolveCosignAttestTimeout(testLogger()); timeout != defaultCosignAttestTimeout {
		t.Fatalf("expected default timeout %s, got %s", defaultCosignAttestTimeout, timeout)
	}

	t.Setenv("ATTESTATION_COMMAND_TIMEOUT", "not-a-duration")
	if timeout := resolveCosignAttestTimeout(testLogger()); timeout != defaultCosignAttestTimeout {
		t.Fatalf("expected default timeout for invalid value, got %s", timeout)
	}

	t.Setenv("ATTESTATION_COMMAND_TIMEOUT", "250ms")
	if timeout := resolveCosignAttestTimeout(testLogger()); timeout != 250*time.Millisecond {
		t.Fatalf("expected parsed timeout 250ms, got %s", timeout)
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
			Key: base64.StdEncoding.EncodeToString([]byte("test-key-content")),
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
			Key: base64.StdEncoding.EncodeToString([]byte("test-key-content")),
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
			Key: base64.StdEncoding.EncodeToString([]byte("test-key-content")),
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

func testSBOM(t *testing.T) *scanner.SBOM {
	t.Helper()

	sbomJSON, err := json.Marshal(map[string]any{
		"bomFormat":   "CycloneDX",
		"specVersion": "1.5",
		"version":     1,
	})
	if err != nil {
		t.Fatalf("failed to marshal test SBOM: %v", err)
	}

	return &scanner.SBOM{
		Format:  "cyclonedx",
		Version: "1.5",
		Data:    sbomJSON,
		Created: time.Now(),
	}
}

func testAttestor(t *testing.T) *SigstoreAttestor {
	t.Helper()

	attestor, err := NewSigstoreAttestor(AttestationConfig{
		KeyBased: KeyBasedConfig{
			Key: base64.StdEncoding.EncodeToString([]byte("test-key-content")),
		},
	}, testLogger())
	if err != nil {
		t.Fatalf("failed to create attestor: %v", err)
	}
	t.Cleanup(func() { _ = attestor.Close() })

	return attestor
}

// cosign v3 defaults to a TUF signing config, which rejects --tlog-upload=false, so both flags
// have to be passed together for key-based signing to stay off the transparency log.
func TestAttestSBOM_DisablesSigningConfigAndTlogUpload(t *testing.T) {
	argsFile := filepath.Join(t.TempDir(), "args.txt")
	fakeBinDir := writeFakeCosign(t, "#!/bin/sh\necho \"$@\" > "+argsFile+"\n")
	t.Setenv("PATH", fakeBinDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	if err := testAttestor(t).AttestSBOM(context.Background(), "test-image:latest", testSBOM(t)); err != nil {
		t.Fatalf("AttestSBOM: %v", err)
	}

	recorded, err := os.ReadFile(argsFile)
	if err != nil {
		t.Fatalf("failed to read recorded args: %v", err)
	}

	for _, flag := range []string{"--tlog-upload=false", "--use-signing-config=false", "--new-bundle-format=false"} {
		if !strings.Contains(string(recorded), flag) {
			t.Errorf("expected cosign args to contain %s, got %s", flag, recorded)
		}
	}
}

func TestAttestSBOM_NewBundleFormatEnv(t *testing.T) {
	tests := []struct {
		name string
		env  string
		want string
	}{
		{name: "unset defaults to classic att tags", env: "", want: "--new-bundle-format=false"},
		{name: "explicit false", env: "false", want: "--new-bundle-format=false"},
		{name: "true enables protobuf bundles", env: "true", want: "--new-bundle-format=true"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			argsFile := filepath.Join(t.TempDir(), "args.txt")
			fakeBinDir := writeFakeCosign(t, "#!/bin/sh\necho \"$@\" > "+argsFile+"\n")
			t.Setenv("PATH", fakeBinDir+string(os.PathListSeparator)+os.Getenv("PATH"))
			if tt.env == "" {
				t.Setenv("ATTESTATION_NEW_BUNDLE_FORMAT", "")
			} else {
				t.Setenv("ATTESTATION_NEW_BUNDLE_FORMAT", tt.env)
			}

			if err := testAttestor(t).AttestSBOM(context.Background(), "test-image:latest", testSBOM(t)); err != nil {
				t.Fatalf("AttestSBOM: %v", err)
			}

			recorded, err := os.ReadFile(argsFile)
			if err != nil {
				t.Fatalf("failed to read recorded args: %v", err)
			}
			if !strings.Contains(string(recorded), tt.want) {
				t.Errorf("expected %s, got %s", tt.want, recorded)
			}
			if tt.want == "--new-bundle-format=false" && strings.Contains(string(recorded), "--new-bundle-format=true") {
				t.Errorf("did not expect --new-bundle-format=true, got %s", recorded)
			}
		})
	}
}

// A rejected invocation can never succeed on retry, so it must surface as a permanent failure
// instead of being retried until the queue gives up and the digest silently stays stale.
func TestAttestSBOM_UsageErrorIsPermanent(t *testing.T) {
	fakeBinDir := writeFakeCosign(t, "#!/bin/sh\n"+
		"echo 'Error: --tlog-upload=false is not supported with --signing-config or --use-signing-config' >&2\n"+
		"exit 1\n")
	t.Setenv("PATH", fakeBinDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	err := testAttestor(t).AttestSBOM(context.Background(), "test-image:latest", testSBOM(t))
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.IsPermanent(err) {
		t.Fatalf("expected permanent error, got transient=%v: %v", errors.IsTransient(err), err)
	}
}

// Registry and network failures must stay retryable.
func TestAttestSBOM_RuntimeFailureStaysTransient(t *testing.T) {
	fakeBinDir := writeFakeCosign(t, "#!/bin/sh\necho 'Error: GET https://registry/v2/: 503 Service Unavailable' >&2\nexit 1\n")
	t.Setenv("PATH", fakeBinDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	err := testAttestor(t).AttestSBOM(context.Background(), "test-image:latest", testSBOM(t))
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.IsTransient(err) {
		t.Fatalf("expected transient error, got %v", err)
	}
}

func TestAttestSBOM_TimesOutCosignCommand(t *testing.T) {
	fakeBinDir := writeFakeCosign(t, "#!/bin/sh\nsleep 5\n")
	t.Setenv("PATH", fakeBinDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("ATTESTATION_COMMAND_TIMEOUT", "20ms")

	sbomJSON, err := json.Marshal(map[string]any{
		"bomFormat":   "CycloneDX",
		"specVersion": "1.5",
		"version":     1,
	})
	if err != nil {
		t.Fatalf("failed to marshal test SBOM: %v", err)
	}

	attestor, err := NewSigstoreAttestor(AttestationConfig{
		KeyBased: KeyBasedConfig{
			Key: base64.StdEncoding.EncodeToString([]byte("test-key-content")),
		},
	}, testLogger())
	if err != nil {
		t.Fatalf("failed to create attestor: %v", err)
	}

	err = attestor.AttestSBOM(context.Background(), "test-image:latest", &scanner.SBOM{
		Format:  "cyclonedx",
		Version: "1.5",
		Data:    sbomJSON,
		Created: time.Now(),
	})
	if err == nil {
		t.Fatal("expected timeout error, got nil")
	}
	if !strings.Contains(err.Error(), "timed out after 20ms") {
		t.Fatalf("expected timeout error, got %v", err)
	}
}
