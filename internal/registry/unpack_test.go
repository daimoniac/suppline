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

func TestUntarSkipsOversizedFilesAndListsThem(t *testing.T) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	write := func(name string, body []byte) {
		t.Helper()
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(body))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(body); err != nil {
			t.Fatal(err)
		}
	}
	big := append([]byte("\x7fELF"), bytes.Repeat([]byte("x"), 60)...)
	write("manager", big)
	write("etc/os-release", []byte("ID=alpine\n"))
	if err := tw.WriteHeader(&tar.Header{Name: "usr/bin/manager-link", Typeflag: tar.TypeLink, Linkname: "manager"}); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	dest := t.TempDir()
	if err := untarLimited(&buf, dest, extractLimits{maxTotal: 1 << 20, maxFile: 32}); err != nil {
		t.Fatalf("an oversized file must not fail the unpack: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dest, "manager")); !os.IsNotExist(err) {
		t.Fatalf("oversized file was written: %v", err)
	}
	if got, err := os.ReadFile(filepath.Join(dest, "etc", "os-release")); err != nil || string(got) != "ID=alpine\n" {
		t.Fatalf("os-release %q %v", got, err)
	}
	manifest, err := os.ReadFile(filepath.Join(dest, SkippedFilesManifest))
	if err != nil {
		t.Fatal(err)
	}
	want := "manager\t64\t1\nusr/bin/manager-link\t64\t1\n"
	if string(manifest) != want {
		t.Fatalf("manifest = %q, want %q", manifest, want)
	}
}
