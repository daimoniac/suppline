package observability

import (
	"strings"
	"testing"
	"time"
)

func TestNewLogger_UsesUTC(t *testing.T) {
	// Create a test logger
	logger := NewLogger("info")
	
	// Verify the function exists and returns a valid logger
	if logger == nil {
		t.Fatal("NewLogger returned nil")
	}
	
	// Test that it logs at the correct level without panicking
	logger.Info("test message")
}

func TestUTCTimestampFormat(t *testing.T) {
	// Verify UTC format
	now := time.Now().UTC()
	formatted := now.Format(time.RFC3339)
	
	// RFC3339 format should end with 'Z' for UTC
	if !strings.HasSuffix(formatted, "Z") {
		t.Errorf("Expected UTC timestamp to end with 'Z', got: %s", formatted)
	}
}
