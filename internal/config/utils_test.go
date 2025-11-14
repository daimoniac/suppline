package config

import (
	"testing"
	"time"
)

func TestParseInterval(t *testing.T) {
	tests := []struct {
		name     string
		interval string
		want     time.Duration
		wantErr  bool
	}{
		{
			name:     "minutes notation",
			interval: "30m",
			want:     30 * time.Minute,
			wantErr:  false,
		},
		{
			name:     "hours notation",
			interval: "3h",
			want:     3 * time.Hour,
			wantErr:  false,
		},
		{
			name:     "days notation",
			interval: "7d",
			want:     7 * 24 * time.Hour,
			wantErr:  false,
		},
		{
			name:     "invalid format - too short",
			interval: "d",
			want:     0,
			wantErr:  true,
		},
		{
			name:     "invalid format - no number",
			interval: "abcd",
			want:     0,
			wantErr:  true,
		},
		{
			name:     "invalid unit",
			interval: "5s",
			want:     0,
			wantErr:  true,
		},
		{
			name:     "negative value",
			interval: "-5d",
			want:     0,
			wantErr:  true,
		},
		{
			name:     "zero value",
			interval: "0d",
			want:     0,
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseInterval(tt.interval)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseInterval() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("parseInterval() = %v, want %v", got, tt.want)
			}
		})
	}
}
