package triage

import (
	"os"
	"path/filepath"
	"testing"
)

func TestBackupRotation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "suppline.yml")
	write := func(body string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("v1")
	if err := WriteLocal(path, 2, []byte("v2")); err != nil {
		t.Fatal(err)
	}
	if err := WriteLocal(path, 2, []byte("v3")); err != nil {
		t.Fatal(err)
	}
	if err := WriteLocal(path, 2, []byte("v4")); err != nil {
		t.Fatal(err)
	}
	got := func(name string) string {
		t.Helper()
		data, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		return string(data)
	}
	if got(path) != "v4" {
		t.Fatalf("current = %s", got(path))
	}
	if got(path+".bak.1") != "v3" || got(path+".bak.2") != "v2" {
		t.Fatalf("backups bak1=%s bak2=%s", got(path+".bak.1"), got(path+".bak.2"))
	}
	if _, err := os.Stat(path + ".bak.3"); !os.IsNotExist(err) {
		t.Fatal("retention did not drop bak.3")
	}
}
