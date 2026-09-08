package statestore

import (
	"strings"
	"testing"
)

func TestCurrentArtifactTagBindingJoinShape(t *testing.T) {
	if got := strings.Count(currentArtifactTagBindingJoin, "MAX(a2.id)"); got != 1 {
		t.Fatalf("MAX(a2.id) count=%d, want 1", got)
	}
	for _, want := range []string{
		"GROUP BY a2.repository_id, a2.tag",
		"a.repository_id = latest.repository_id",
		"a.tag IS NOT DISTINCT FROM latest.tag",
		"a.id = latest.max_id",
	} {
		if !strings.Contains(currentArtifactTagBindingJoin, want) {
			t.Fatalf("current binding join missing %q", want)
		}
	}
	if strings.Contains(currentArtifactTagBindingJoin, "?") {
		t.Fatal("current binding join must not introduce placeholders")
	}
}
