package config

import (
	"fmt"
	"time"

	"gopkg.in/yaml.v3"
)

// Duration unmarshals a Go duration string such as "60m".
// yaml.v3 does not parse those strings into time.Duration.
type Duration time.Duration

// Std returns the duration as a time.Duration.
func (d Duration) Std() time.Duration {
	return time.Duration(d)
}

// String renders the duration the same way time.Duration does.
func (d Duration) String() string {
	return time.Duration(d).String()
}

// UnmarshalYAML parses a scalar duration.
func (d *Duration) UnmarshalYAML(value *yaml.Node) error {
	if value == nil || value.Tag == "!!null" || value.Value == "" {
		*d = 0
		return nil
	}
	parsed, err := time.ParseDuration(value.Value)
	if err != nil {
		return fmt.Errorf("parse duration %q: %w", value.Value, err)
	}
	*d = Duration(parsed)
	return nil
}
