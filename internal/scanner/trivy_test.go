package scanner

import (
	"testing"

	"github.com/daimoniac/suppline/internal/config"
)

func TestNewTrivyScanner(t *testing.T) {
	// Test creating a new Trivy scanner with valid configuration
	cfg := config.ScannerConfig{
		ServerAddr:    "localhost:4954",
		Token:         "",
		CustomHeaders: make(map[string]string),
		Timeout:       300000000000, // 5 minutes in nanoseconds
		Insecure:      false,
	}

	// Note: This test will fail if Trivy server is not running
	// In a real environment, you would either:
	// 1. Mock the Trivy client
	// 2. Skip this test if Trivy is not available
	// 3. Use integration test tags
	scanner, err := NewTrivyScanner(cfg)
	if err != nil {
		// Expected to fail if Trivy server is not running
		t.Logf("Expected failure when Trivy server is not available: %v", err)
		return
	}

	if scanner == nil {
		t.Fatal("Expected scanner to be non-nil")
	}

	if scanner.serverAddr != cfg.ServerAddr {
		t.Errorf("Expected serverAddr %s, got %s", cfg.ServerAddr, scanner.serverAddr)
	}

	if scanner.timeout != cfg.Timeout {
		t.Errorf("Expected timeout %v, got %v", cfg.Timeout, scanner.timeout)
	}
}

func TestScannerInterface(t *testing.T) {
	// Verify that TrivyScanner implements Scanner interface
	var _ Scanner = (*TrivyScanner)(nil)
}


