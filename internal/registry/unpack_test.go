package registry

import (
	"archive/tar"
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestUntarKeepsFilesInsideDest(t *testing.T) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	body := []byte("hello\n")
	if err := tw.WriteHeader(&tar.Header{Name: "opt/bin/start.sh", Mode: 0o644, Size: int64(len(body))}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(body); err != nil {
		t.Fatal(err)
	}
	if err := tw.WriteHeader(&tar.Header{Name: "../outside-unpack-test", Mode: 0o644, Size: 1}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	link := "opt/bin/start.sh"
	if err := tw.WriteHeader(&tar.Header{Name: "opt/bin/start-link", Typeflag: tar.TypeLink, Linkname: link}); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	dest := t.TempDir()
	if err := untarLimited(&buf, dest, extractLimits{maxTotal: 1 << 20, maxFile: 1 << 20}); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(dest, "opt", "bin", "start.sh"))
	if err != nil || string(got) != "hello\n" {
		t.Fatalf("start.sh %q %v", got, err)
	}
	linked, err := os.ReadFile(filepath.Join(dest, "opt", "bin", "start-link"))
	if err != nil || string(linked) != "hello\n" {
		t.Fatalf("hardlink %q %v", linked, err)
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(dest), "outside-unpack-test")); err == nil {
		t.Fatal("tar path escaped the destination")
	}
}
