// Package semverutil wraps Masterminds semver for image tag version parsing,
// shared by the tasks API and runtime image-usage filtering.
package semverutil

import (
	semver "github.com/Masterminds/semver/v3"
)

// ParseVersion parses a tag as a semver version, or returns nil if it is not valid.
func ParseVersion(tag string) (*semver.Version, bool) {
	if tag == "" {
		return nil, false
	}
	v, err := semver.NewVersion(tag)
	if err != nil {
		return nil, false
	}
	return v, true
}

// MaxVersion returns the greatest version in the slice, or nil if empty.
func MaxVersion(versions []*semver.Version) *semver.Version {
	var max *semver.Version
	for _, v := range versions {
		if v == nil {
			continue
		}
		if max == nil || v.GreaterThan(max) {
			max = v
		}
	}
	return max
}
