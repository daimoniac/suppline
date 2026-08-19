// Package semverutil wraps Masterminds semver for image tag version parsing,
// shared by the tasks API and runtime image-usage filtering.
package semverutil

import (
	"regexp"
	"strconv"
	"strings"

	semver "github.com/Masterminds/semver/v3"
)

// bitnamiRevisionSuffix matches Bitnami-style image revisions (...-rN).
// SemVer treats "r16" as an alphanumeric prerelease identifier and compares
// lexicographically ("r16" < "r9"), which disagrees with Bitnami's numeric
// revision ordering. Rewriting to a numeric identifier preserves intent.
var bitnamiRevisionSuffix = regexp.MustCompile(`-r(\d+)`)

// prereleaseIdentifier matches the identifiers that mark a real pre-release
// ("rc", "rc1", "beta.2", ...). Image tags carry many other suffixes that are
// distribution flavors of a released version ("-management", "-alpine",
// "-debian-12-r9"), which SemVer cannot tell apart from a pre-release.
var prereleaseIdentifier = regexp.MustCompile(`(?i)^(alpha|beta|rc|pre|preview|dev|snapshot|nightly|canary|next|milestone|unstable)\d*$`)

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

// IsFlavorSuffix reports whether the SemVer pre-release segment of v is a
// distribution flavor ("4.1.3-management", "0.17.2-debian-12-r9") rather than a
// real pre-release ("1.2.3-rc.1", "1.2.3-0"). Flavor tags ship the released
// version, so range checks must not exclude them.
func IsFlavorSuffix(v *semver.Version) bool {
	if v == nil {
		return false
	}
	pre := v.Prerelease()
	if pre == "" {
		return false
	}

	allNumeric := true
	for _, token := range strings.FieldsFunc(pre, func(r rune) bool { return r == '.' || r == '-' }) {
		if prereleaseIdentifier.MatchString(token) {
			return false
		}
		if _, err := strconv.ParseUint(token, 10, 64); err != nil {
			allNumeric = false
		}
	}
	// A purely numeric suffix is the conventional "lowest pre-release" marker.
	return !allNumeric
}

// Satisfies reports whether v falls inside c.
//
// SemVer keeps pre-release versions out of ranges with stable bounds, which
// would put a flavor tag such as "4.1.3-management" outside ">=4.1.1". Those
// tags are retried against their release core, so only real pre-releases keep
// the strict SemVer exclusion.
func Satisfies(c *semver.Constraints, v *semver.Version) bool {
	if c == nil || v == nil {
		return false
	}
	if c.Check(v) {
		return true
	}
	if !IsFlavorSuffix(v) {
		return false
	}
	return c.Check(semver.New(v.Major(), v.Minor(), v.Patch(), "", ""))
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
