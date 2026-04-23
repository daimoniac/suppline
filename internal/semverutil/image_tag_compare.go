package semverutil

import (
	"strconv"
	"strings"

	semver "github.com/Masterminds/semver/v3"
)

// toComparableIntSegments returns an integer slice for ordering image tags. It accepts:
// 1) Strict SemVer 2.0 (major.minor.patch only from Masterminds), or
// 2) Dot-separated non-negative decimal integers (e.g. Postgres build 15.8.1.060, 16.0.0.0).
func toComparableIntSegments(s string) ([]int, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, false
	}
	orig := s
	if strings.HasPrefix(s, "v") || strings.HasPrefix(s, "V") {
		s = s[1:]
	}
	// 1) Strict semver core (1.2.3) — not four-part 1.2.3.4
	if v, err := semver.NewVersion(orig); err == nil {
		return []int{int(v.Major()), int(v.Minor()), int(v.Patch())}, true
	}
	// 2) All-decimal-segment form (e.g. 15.8.1.060)
	parts := strings.Split(s, ".")
	if len(parts) < 1 {
		return nil, false
	}
	out := make([]int, 0, len(parts))
	for _, p := range parts {
		if p == "" {
			return nil, false
		}
		for i := 0; i < len(p); i++ {
			if p[i] < '0' || p[i] > '9' {
				return nil, false
			}
		}
		n, err := strconv.Atoi(p)
		if err != nil {
			return nil, false
		}
		out = append(out, n)
	}
	return out, true
}

// compareIntSlicesPadded returns -1, 0, 1 in dictionary order (longer = higher when prefix-equal and extra > 0).
func compareIntSlicesPadded(a, b []int) int {
	n := len(a)
	if len(b) > n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		ai, bi := 0, 0
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

// CompareImageTagOrder returns -1 (a < b), 0 (equal), 1 (a > b) when a and b are orderable; otherwise ok is false.
func CompareImageTagOrder(a, b string) (int, bool) {
	sa, oka := toComparableIntSegments(a)
	sb, okb := toComparableIntSegments(b)
	if !oka || !okb {
		return 0, false
	}
	return compareIntSlicesPadded(sa, sb), true
}

// ImageTagIsStrictlyGreater returns true if tag a sorts strictly after b under CompareImageTagOrder.
func ImageTagIsStrictlyGreater(a, b string) bool {
	cmp, ok := CompareImageTagOrder(a, b)
	return ok && cmp > 0
}

// MaxImageTagInList returns the tag that sorts last under CompareImageTagOrder, or "" if the list is empty.
func MaxImageTagInList(tags []string) string {
	if len(tags) == 0 {
		return ""
	}
	best := tags[0]
	for i := 1; i < len(tags); i++ {
		t := tags[i]
		if cmp, ok := CompareImageTagOrder(t, best); ok && cmp > 0 {
			best = t
		}
	}
	return best
}

// MinImageTagInList returns the tag that sorts first under CompareImageTagOrder, or "" if the list is empty.
func MinImageTagInList(tags []string) string {
	if len(tags) == 0 {
		return ""
	}
	best := tags[0]
	for i := 1; i < len(tags); i++ {
		t := tags[i]
		if cmp, ok := CompareImageTagOrder(t, best); ok && cmp < 0 {
			best = t
		}
	}
	return best
}
