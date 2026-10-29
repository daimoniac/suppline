// Package semverutil wraps Masterminds semver for image tag version parsing,
// shared by the mirror, the tasks API, and runtime image-usage filtering.
// Range membership and tag order use one numeric key: major, minor, patch,
// then any further numeric build segments (15.8.1.060), then the prerelease.
package semverutil

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	semver "github.com/Masterminds/semver/v3"
)

// versionAfterSepRe finds a version preceded by a dash or underscore, with an
// optional v/V prefix. "alpine-v18.10.0" and "alpine3.18-x86_64-v17.8.0" both
// resolve to the software version. A bare fragment such as "alpine3.18" has
// no separator and is left unchanged.
var versionAfterSepRe = regexp.MustCompile(`[-_][vV]?\d+\.\d`)

func versionText(tag string) string {
	if loc := versionAfterSepRe.FindStringIndex(tag); loc != nil {
		return tag[loc[0]+1:]
	}
	return tag
}

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

// fourPartVersion matches a numeric fourth component, as in "15.8.1.060".
var fourPartVersion = regexp.MustCompile(`\d+\.\d+\.\d+\.\d+`)

func canonicalizeSemverText(s string) string {
	return bitnamiRevisionSuffix.ReplaceAllString(s, ".$1")
}

// ParseVersion parses a tag as a semver version, or returns nil if it is not valid.
// A dash- or underscore-separated prefix is stripped first. A numeric fourth
// component is kept as build metadata so it orders above the same patch and
// below the next one. Bitnami "-rN" suffixes are canonicalized so r16 > r9.
func ParseVersion(tag string) (*semver.Version, bool) {
	if tag == "" {
		return nil, false
	}
	text := canonicalizeSemverText(versionText(tag))
	segs, rest, ok := splitNumericPrefix(text)
	if !ok {
		return nil, false
	}
	for len(segs) < 3 {
		segs = append(segs, 0)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%d.%d.%d", segs[0], segs[1], segs[2])
	if rest != "" {
		b.WriteString(rest)
	}
	if len(segs) > 3 {
		b.WriteByte('+')
		for i, n := range segs[3:] {
			if i > 0 {
				b.WriteByte('.')
			}
			b.WriteString(strconv.FormatUint(n, 10))
		}
	}
	v, err := semver.NewVersion(b.String())
	if err != nil {
		return nil, false
	}
	return v, true
}

// splitNumericPrefix reads a leading v-prefixed run of numeric dot segments.
// "15.8.1.060" is [15 8 1 60] with an empty remainder. "26.10.0.133078-community"
// keeps "-community". A non-numeric start is not a version.
func splitNumericPrefix(s string) (segs []uint64, rest string, ok bool) {
	if s == "" {
		return nil, "", false
	}
	if s[0] == 'v' || s[0] == 'V' {
		s = s[1:]
	}
	i := 0
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		j := i
		for j < len(s) && s[j] >= '0' && s[j] <= '9' {
			j++
		}
		n, err := strconv.ParseUint(s[i:j], 10, 64)
		if err != nil {
			return nil, "", false
		}
		segs = append(segs, n)
		if j >= len(s) {
			return segs, "", true
		}
		if s[j] != '.' || j+1 >= len(s) || s[j+1] < '0' || s[j+1] > '9' {
			return segs, s[j:], true
		}
		i = j + 1
	}
	return nil, s, false
}

// Compare orders two parsed tags: numeric segments, padded with zero, then prerelease.
// 15.8.1 < 15.8.1.060 < 15.8.2, and a Bitnami r16 sorts after r9.
func Compare(a, b *semver.Version) int {
	if a == nil && b == nil {
		return 0
	}
	if a == nil {
		return -1
	}
	if b == nil {
		return 1
	}
	if cmp := compareSegments(segments(a), segments(b)); cmp != 0 {
		return cmp
	}
	return a.Compare(b)
}

func segments(v *semver.Version) []uint64 {
	out := []uint64{v.Major(), v.Minor(), v.Patch()}
	if md := v.Metadata(); md != "" {
		for _, part := range strings.Split(md, ".") {
			n, err := strconv.ParseUint(part, 10, 64)
			if err != nil {
				break
			}
			out = append(out, n)
		}
	}
	return out
}

func compareSegments(a, b []uint64) int {
	n := len(a)
	if len(b) > n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		var ai, bi uint64
		if i < len(a) {
			ai = a[i]
		}
		if i < len(b) {
			bi = b[i]
		}
		if ai < bi {
			return -1
		}
		if ai > bi {
			return 1
		}
	}
	return 0
}

// Constraint is one semver range string. Clauses joined by "||" are OR.
// A clause that contains a fourth numeric component is ordered with Compare.
// Every other clause uses Masterminds, including prerelease inclusion such as ">=26.2.0-0".
type Constraint struct {
	clauses []constraintClause
}

type constraintClause struct {
	text string
	mc   *semver.Constraints
	own  bool
}

// NewConstraint parses a semver constraint. Bitnami "-rN" revisions are
// canonicalized the same way as ParseVersion.
func NewConstraint(c string) (*Constraint, error) {
	parts := strings.Split(c, "||")
	out := &Constraint{clauses: make([]constraintClause, 0, len(parts))}
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			return nil, fmt.Errorf("improper constraint: %s", c)
		}
		text := canonicalizeSemverText(part)
		clause := constraintClause{text: text, own: fourPartVersion.MatchString(part)}
		if clause.own {
			if err := validateOwn(text); err != nil {
				return nil, err
			}
		} else {
			mc, err := semver.NewConstraint(text)
			if err != nil {
				return nil, err
			}
			clause.mc = mc
		}
		out.clauses = append(out.clauses, clause)
	}
	return out, nil
}

func validateOwn(text string) error {
	for _, token := range strings.Fields(text) {
		op, rest := splitOp(token)
		if _, ok := ParseVersion(rest); !ok {
			return fmt.Errorf("improper constraint: %s", token)
		}
		if op != ">=" && op != ">" && op != "<=" && op != "<" && op != "=" && op != "~" && op != "^" {
			return fmt.Errorf("improper constraint: %s", token)
		}
	}
	return nil
}

func splitOp(token string) (string, string) {
	for _, op := range []string{">=", "<=", "!=", ">", "<", "="} {
		if strings.HasPrefix(token, op) {
			return op, strings.TrimSpace(token[len(op):])
		}
	}
	if strings.HasPrefix(token, "~") || strings.HasPrefix(token, "^") {
		return token[:1], strings.TrimSpace(token[1:])
	}
	return "=", token
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
func Satisfies(c *Constraint, v *semver.Version) bool {
	if c == nil || v == nil {
		return false
	}
	for _, clause := range c.clauses {
		if clauseSatisfies(clause, v) {
			return true
		}
	}
	return false
}

func clauseSatisfies(clause constraintClause, v *semver.Version) bool {
	if clause.own {
		if checkOwn(clause.text, v) {
			return true
		}
		if !IsFlavorSuffix(v) {
			return false
		}
		return checkOwn(clause.text, semver.New(v.Major(), v.Minor(), v.Patch(), "", v.Metadata()))
	}
	return checkVersion(clause.mc, v)
}

func checkVersion(c *semver.Constraints, v *semver.Version) bool {
	if c.Check(v) {
		return true
	}
	if !IsFlavorSuffix(v) {
		return false
	}
	return c.Check(semver.New(v.Major(), v.Minor(), v.Patch(), "", ""))
}

// checkOwn compares a fourth-component constraint with Compare.
// A real prerelease fails a stable bound; flavors are retried by the caller.
func checkOwn(text string, v *semver.Version) bool {
	if v.Prerelease() != "" {
		return false
	}
	for _, token := range strings.Fields(text) {
		if !ownToken(token, v) {
			return false
		}
	}
	return true
}

func ownToken(token string, v *semver.Version) bool {
	op, rest := splitOp(token)
	switch op {
	case "~":
		return ownToken(">="+rest, v) && belowNextMinor(rest, v)
	case "^":
		return ownToken(">="+rest, v) && belowCaret(rest, v)
	case "!=":
		bound, ok := ParseVersion(rest)
		return ok && Compare(v, bound) != 0
	}
	bound, ok := ParseVersion(rest)
	if !ok {
		return false
	}
	cmp := Compare(v, bound)
	switch op {
	case ">=":
		return cmp >= 0
	case ">":
		return cmp > 0
	case "<=":
		return cmp <= 0
	case "<":
		return cmp < 0
	default:
		return cmp == 0
	}
}

func belowNextMinor(rest string, v *semver.Version) bool {
	bound, ok := ParseVersion(rest)
	if !ok {
		return false
	}
	upper, ok := ParseVersion(fmt.Sprintf("%d.%d.0", bound.Major(), bound.Minor()+1))
	return ok && Compare(v, upper) < 0
}

func belowCaret(rest string, v *semver.Version) bool {
	bound, ok := ParseVersion(rest)
	if !ok {
		return false
	}
	var upperText string
	switch {
	case bound.Major() > 0:
		upperText = fmt.Sprintf("%d.0.0", bound.Major()+1)
	case bound.Minor() > 0:
		upperText = fmt.Sprintf("0.%d.0", bound.Minor()+1)
	default:
		upperText = fmt.Sprintf("0.0.%d", bound.Patch()+1)
	}
	upper, ok := ParseVersion(upperText)
	return ok && Compare(v, upper) < 0
}

// MaxVersion returns the greatest version in the slice, or nil if empty.
func MaxVersion(versions []*semver.Version) *semver.Version {
	var max *semver.Version
	for _, v := range versions {
		if v == nil {
			continue
		}
		if max == nil || Compare(v, max) > 0 {
			max = v
		}
	}
	return max
}
