package attestation

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"strings"
	"testing"

	"github.com/daimoniac/suppline/internal/config"
)

// generateTestKey generates a test ECDSA key pair for testing
func generateTestKey(password string) (string, error) {
	// Generate ECDSA private key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", err
	}

	// Marshal to PKCS#8
	pkcs8Bytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return "", err
	}

	// Create PEM block
	block := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: pkcs8Bytes,
	}

	// Encrypt if password provided
	if password != "" {
		encryptedBlock, err := x509.EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(password), x509.PEMCipherAES256)
		if err != nil {
			return "", err
		}
		block = encryptedBlock
	}

	// Encode to PEM
	pemBytes := pem.EncodeToMemory(block)

	// Base64 encode
	return base64.StdEncoding.EncodeToString(pemBytes), nil
}

func TestExtractPublicKey_Unencrypted(t *testing.T) {
	// Generate test key without password
	base64Key, err := generateTestKey("")
	if err != nil {
		t.Fatalf("Failed to generate test key: %v", err)
	}

	// Extract public key
	publicKey, err := ExtractPublicKey(base64Key, "")
	if err != nil {
		t.Fatalf("Failed to extract public key: %v", err)
	}

	// Verify it's a valid PEM-encoded public key
	if !strings.Contains(publicKey, "BEGIN PUBLIC KEY") {
		t.Error("Expected public key to contain PEM header")
	}

	if !strings.Contains(publicKey, "END PUBLIC KEY") {
		t.Error("Expected public key to contain PEM footer")
	}

	// Verify we can decode it
	block, _ := pem.Decode([]byte(publicKey))
	if block == nil {
		t.Fatal("Failed to decode public key PEM")
	}

	if block.Type != "PUBLIC KEY" {
		t.Errorf("Expected block type 'PUBLIC KEY', got '%s'", block.Type)
	}

	// Verify we can parse it as a public key
	_, err = x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Errorf("Failed to parse public key: %v", err)
	}
}

func TestExtractPublicKey_Encrypted(t *testing.T) {
	password := "test-password"

	// Generate test key with password
	base64Key, err := generateTestKey(password)
	if err != nil {
		t.Fatalf("Failed to generate test key: %v", err)
	}

	// Extract public key with correct password
	publicKey, err := ExtractPublicKey(base64Key, password)
	if err != nil {
		t.Fatalf("Failed to extract public key: %v", err)
	}

	// Verify it's a valid PEM-encoded public key
	if !strings.Contains(publicKey, "BEGIN PUBLIC KEY") {
		t.Error("Expected public key to contain PEM header")
	}

	// Verify we can decode and parse it
	block, _ := pem.Decode([]byte(publicKey))
	if block == nil {
		t.Fatal("Failed to decode public key PEM")
	}

	_, err = x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Errorf("Failed to parse public key: %v", err)
	}
}

func TestExtractPublicKey_WrongPassword(t *testing.T) {
	password := "test-password"

	// Generate test key with password
	base64Key, err := generateTestKey(password)
	if err != nil {
		t.Fatalf("Failed to generate test key: %v", err)
	}

	// Try to extract with wrong password
	_, err = ExtractPublicKey(base64Key, "wrong-password")
	if err == nil {
		t.Error("Expected error when using wrong password")
	}
}

func TestExtractPublicKey_InvalidBase64(t *testing.T) {
	_, err := ExtractPublicKey("not-valid-base64!!!", "")
	if err == nil {
		t.Error("Expected error for invalid base64")
	}
}

func TestExtractPublicKey_InvalidPEM(t *testing.T) {
	// Valid base64 but not valid PEM
	invalidPEM := base64.StdEncoding.EncodeToString([]byte("not a PEM block"))
	_, err := ExtractPublicKey(invalidPEM, "")
	if err == nil {
		t.Error("Expected error for invalid PEM")
	}
}

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

func TestGetPublicKeyFromConfig_ValidKey(t *testing.T) {
	// Generate test key
	base64Key, err := generateTestKey("test-password")
	if err != nil {
		t.Fatalf("Failed to generate test key: %v", err)
	}

	cfg := config.AttestationConfig{
		KeyBased: struct {
			Key         string
			KeyPassword string
		}{
			Key:         base64Key,
			KeyPassword: "test-password",
		},
	}

	publicKey, err := GetPublicKeyFromConfig(cfg)
	if err != nil {
		t.Fatalf("Failed to get public key from config: %v", err)
	}

	// Verify it's a valid public key
	if !strings.Contains(publicKey, "BEGIN PUBLIC KEY") {
		t.Error("Expected public key to contain PEM header")
	}
}
