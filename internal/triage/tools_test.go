package triage

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadFileRejectsSymlinkEscape(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "secret.txt"), []byte("token"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "secret.txt"), filepath.Join(root, "link.txt")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "app.yaml"), []byte("kind: Deployment\ningress: internal\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	roots := Roots{Checkouts: []CheckoutRoot{{Name: "infra", Dir: root}}, MaxFileBytes: 1024}
	if _, err := roots.ReadFile("infra", "link.txt", 1, 5); err == nil {
		t.Fatal("symlink escape was readable")
	}
	got, err := roots.Line("infra", "app.yaml", 2)
	if err != nil {
		t.Fatal(err)
	}
	if got != "ingress: internal" {
		t.Fatalf("line = %q", got)
	}
}
