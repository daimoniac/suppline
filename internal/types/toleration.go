package types

import (
	"fmt"
	"time"
)

// CVEToleration represents the canonical CVE toleration type.
// This is the single source of truth for toleration data structures.
type CVEToleration struct {
	ID        string `yaml:"id"`
	Statement string `yaml:"statement"`
	ExpiresAt *int64 `yaml:"expires_at,omitempty"` // Unix timestamp in seconds, nil means no expiry
}

// UnmarshalYAML implements custom YAML unmarshaling for CVEToleration.
// This allows expires_at to be specified as an RFC3339 timestamp or date string in YAML
// while storing it as a Unix timestamp internally.
func (c *CVEToleration) UnmarshalYAML(unmarshal func(interface{}) error) error {
	// Create a temporary struct with string expires_at for parsing
	var temp struct {
		ID        string  `yaml:"id"`
		Statement string  `yaml:"statement"`
		ExpiresAt *string `yaml:"expires_at,omitempty"`
	}

	if err := unmarshal(&temp); err != nil {
		return err
	}

	c.ID = temp.ID
	c.Statement = temp.Statement

	// Parse expires_at if provided
	if temp.ExpiresAt != nil && *temp.ExpiresAt != "" {
		var t time.Time
		var err error

		// Try RFC3339 format first (2026-02-28T23:59:59Z)
		t, err = time.Parse(time.RFC3339, *temp.ExpiresAt)
		if err != nil {
			// Try date-only format (2026-02-28) - set to end of day
			t, err = time.Parse("2006-01-02", *temp.ExpiresAt)
			if err != nil {
				return fmt.Errorf("invalid expires_at format for %s: %w (expected RFC3339 like '2026-02-28T23:59:59Z' or date like '2026-02-28')", temp.ID, err)
			}
			// Set to end of day (23:59:59) for date-only format
			t = time.Date(t.Year(), t.Month(), t.Day(), 23, 59, 59, 0, time.UTC)
		}

		timestamp := t.Unix()
		c.ExpiresAt = &timestamp
	}

	return nil
}

// ToleratedCVE extends CVEToleration with tracking metadata for storage.
// Used by StateStore to record when and where tolerations were applied.
// Note: This uses explicit fields instead of embedding to match statestore naming conventions.
type ToleratedCVE struct {
	CVEID       string
	Statement   string
	ToleratedAt int64  // Unix timestamp in seconds
	ExpiresAt   *int64 // Unix timestamp in seconds, nil means no expiry
}

// TolerationInfo extends ToleratedCVE with repository context for queries.
// Used by StateStore queries to show which repositories have which tolerations.
// Note: This uses explicit fields instead of embedding to match statestore naming conventions.
type TolerationInfo struct {
	CVEID       string
	Statement   string
	ToleratedAt int64  // Unix timestamp in seconds
	ExpiresAt   *int64 // Unix timestamp in seconds
	Repository  string
}
