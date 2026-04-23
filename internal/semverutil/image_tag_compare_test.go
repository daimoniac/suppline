package semverutil

import "testing"

func TestCompareImageTagOrder_postgresBuild(t *testing.T) {
	cmp, ok := CompareImageTagOrder("15.8.1.060", "15.8.1.061")
	if !ok || cmp >= 0 {
		t.Fatalf("15.8.1.060 < 15.8.1.061: got ok=%v cmp=%d", ok, cmp)
	}
	cmp, ok = CompareImageTagOrder("15.8.1.061", "15.8.1.060")
	if !ok || cmp <= 0 {
		t.Fatalf("15.8.1.061 > 15.8.1.060: got ok=%v cmp=%d", ok, cmp)
	}
	// 15.8.1 (semver) vs four-part
	cmp, ok = CompareImageTagOrder("15.8.1.060", "15.8.1")
	if !ok || cmp <= 0 {
		t.Fatalf("15.8.1.060 > 15.8.1: got ok=%v cmp=%d", ok, cmp)
	}
}

func TestMaxImageTagInList_mixedInUse(t *testing.T) {
	tags := []string{"15.8.1", "15.8.1.050", "15.8.1.060"}
	if m := MaxImageTagInList(tags); m != "15.8.1.060" {
		t.Fatalf("expected 15.8.1.060, got %q", m)
	}
}

func TestMinImageTagInList(t *testing.T) {
	tags := []string{"1.30", "1.29.8", "1.29.5", "1.29.7"}
	if m := MinImageTagInList(tags); m != "1.29.5" {
		t.Fatalf("expected 1.29.5, got %q", m)
	}
}

func TestImageTagIsStrictlyGreater_fourPart(t *testing.T) {
	if !ImageTagIsStrictlyGreater("16.0.0.0", "15.8.1.060") {
		t.Fatal("16.0.0.0 should be > 15.8.1.060")
	}
}
