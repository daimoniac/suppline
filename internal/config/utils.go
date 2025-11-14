package config

import (
	"fmt"
	"time"
)

// parseInterval parses interval notation (e.g., "2m", "3h", "7d") into time.Duration
func parseInterval(interval string) (time.Duration, error) {
	if len(interval) < 2 {
		return 0, fmt.Errorf("invalid interval format: %s", interval)
	}

	unit := interval[len(interval)-1]
	valueStr := interval[:len(interval)-1]

	// Parse the numeric value
	var value int
	if _, err := fmt.Sscanf(valueStr, "%d", &value); err != nil {
		return 0, fmt.Errorf("invalid interval value: %s", interval)
	}

	if value <= 0 {
		return 0, fmt.Errorf("interval value must be positive: %s", interval)
	}

	switch unit {
	case 'm':
		return time.Duration(value) * time.Minute, nil
	case 'h':
		return time.Duration(value) * time.Hour, nil
	case 'd':
		return time.Duration(value) * 24 * time.Hour, nil
	default:
		return 0, fmt.Errorf("invalid interval unit (must be m, h, or d): %s", interval)
	}
}
