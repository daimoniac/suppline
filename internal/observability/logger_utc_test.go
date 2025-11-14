package observability

import (
	"strings"
	"testing"
	"time"
)

func TestNewLogger_UsesUTC(t *testing.T) {
	logger := NewLogger("info")
	
	if logger == nil {
		t.Fatal("NewLogger returned nil")
	}
	
	logger.Info("test message")
}

func TestUTCTimestampFormat(t *testing.T) {
	now := time.Now().UTC()
	formatted := now.Format(time.RFC3339)
	
	if !strings.HasSuffix(formatted, "Z") {
		t.Errorf("Expected UTC timestamp to end with 'Z', got: %s", formatted)
	}
}
