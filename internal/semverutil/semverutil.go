// Package semverutil wraps Masterminds semver for image tag version parsing,
// shared by the tasks API and runtime image-usage filtering.
package semverutil

import (
	"regexp"

	semver "github.com/Masterminds/semver/v3"
)

// bitnamiRevisionSuffix matches Bitnami-style image revisions (...-rN).
// SemVer treats "r16" as an alphanumeric prerelease identifier and compares
// lexicographically ("r16" < "r9"), which disagrees with Bitnami's numeric
// revision ordering. Rewriting to a numeric identifier preserves intent.
var bitnamiRevisionSuffix = regexp.MustCompile(`-r(\d+)`)

// canonicalizeSemverText rewrites Bitnami "-rN" revisions to ".N" so constraint
// checks and version comparisons order revisions numerically.
func canonicalizeSemverText(s string) string {
	return bitnamiRevisionSuffix.ReplaceAllString(s, ".$1")
}

// ParseVersion parses a tag as a semver version, or returns nil if it is not valid.
// Bitnami-style "-rN" suffixes are canonicalized so r16 > r9.
func ParseVersion(tag string) (*semver.Version, bool) {
	if tag == "" {
		return nil, false
	}
	v, err := semver.NewVersion(canonicalizeSemverText(tag))
	if err != nil {
		return nil, false
	}
	return v, true
}

// NewConstraint parses a semver constraint, canonicalizing Bitnami "-rN"
// revisions the same way as ParseVersion.
func NewConstraint(c string) (*semver.Constraints, error) {
	return semver.NewConstraint(canonicalizeSemverText(c))
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
