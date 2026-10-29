package semverutil

// CompareImageTagOrder returns -1 (a < b), 0 (equal), 1 (a > b) when a and b are orderable; otherwise ok is false.
// Ordering is Compare on ParseVersion, the same order range checks and task sorts use.
func CompareImageTagOrder(a, b string) (int, bool) {
	va, oka := ParseVersion(a)
	vb, okb := ParseVersion(b)
	if !oka || !okb {
		return 0, false
	}
	return Compare(va, vb), true
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
