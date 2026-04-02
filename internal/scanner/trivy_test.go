package scanner

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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

// makeFakeTrivy creates a fake "trivy" shell script in a temp directory.
// The script writes all its arguments to argsLog (space-joined per invocation),
// emits valid JSON when called for --format json, and creates the output file for
// --format cosign-vuln. Returns (tempDir, argsLogPath).
func makeFakeTrivy(t *testing.T) (string, string) {
	t.Helper()
	tmpDir := t.TempDir()
	argsLog := filepath.Join(tmpDir, "args.log")

	script := `#!/bin/sh
echo "$*" >> ` + argsLog + `
found_output=0
for arg in "$@"; do
  case "$arg" in
    json) printf '{"Results":[]}\n'; exit 0 ;;
  esac
  if [ $found_output -eq 1 ]; then
    echo '{}' > "$arg"
    found_output=0
  fi
  [ "$arg" = "--output" ] && found_output=1
done
exit 0
`
	scriptPath := filepath.Join(tmpDir, "trivy")
	if err := os.WriteFile(scriptPath, []byte(script), 0750); err != nil {
		t.Fatalf("failed to write fake trivy script: %v", err)
	}
	return tmpDir, argsLog
}

func TestScanVulnerabilities_VEXRepoFlag(t *testing.T) {
	tests := []struct {
		name          string
		useVEXRepo    bool
		wantVEXInArgs bool
	}{
		{
			name:          "useVEXRepo true injects --vex repo",
			useVEXRepo:    true,
			wantVEXInArgs: true,
		},
		{
			name:          "useVEXRepo false omits --vex flag",
			useVEXRepo:    false,
			wantVEXInArgs: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fakeDir, argsLog := makeFakeTrivy(t)
			t.Setenv("PATH", fakeDir+":"+os.Getenv("PATH"))

			cfg := config.ScannerConfig{
				ServerAddr: "localhost:4954",
				Timeout:    5 * time.Second,
			}
			scanner, err := NewTrivyScanner(cfg)
			if err != nil {
				t.Fatalf("NewTrivyScanner: %v", err)
			}

			ctx := context.Background()
			if _, err := scanner.ScanVulnerabilities(ctx, "myregistry/nginx@sha256:abc123", tc.useVEXRepo); err != nil {
				t.Fatalf("ScanVulnerabilities failed: %v", err)
			}

			rawBytes, readErr := os.ReadFile(argsLog)
			if readErr != nil {
				t.Fatalf("args log not found: %v", readErr)
			}
			content := string(rawBytes)

			hasVEX := strings.Contains(content, "--vex repo")
			if tc.wantVEXInArgs && !hasVEX {
				t.Errorf("expected '--vex repo' in trivy args but not found; args log:\n%s", content)
			}
			if !tc.wantVEXInArgs && hasVEX {
				t.Errorf("expected '--vex repo' NOT in trivy args but found; args log:\n%s", content)
			}
		})
	}
}
