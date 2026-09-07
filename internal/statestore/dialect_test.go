package statestore

import "testing"

func TestRewritePlaceholders(t *testing.T) {
	got := rewritePlaceholders("SELECT id FROM t WHERE a = ? AND b = ?")
	want := "SELECT id FROM t WHERE a = $1 AND b = $2"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}
