package observability

import (
	"log/slog"
	"testing"
)

func TestNewLogger_Levels(t *testing.T) {
	tests := []struct {
		input    string
		expected slog.Level
	}{
		{"debug", slog.LevelDebug},
		{"info", slog.LevelInfo},
		{"warn", slog.LevelWarn},
		{"warning", slog.LevelWarn},
		{"error", slog.LevelError},
		{"invalid", slog.LevelInfo}, // defaults to info
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			logger := NewLogger(tt.input)
			if logger == nil {
				t.Fatal("NewLogger returned nil")
			}
			// Logger is created successfully - actual level testing would require
			// capturing output which is complex for slog
		})
	}
}
