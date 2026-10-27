package triage

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestImageGrepAbsence(t *testing.T) {
	cache := filepath.Join(os.TempDir(), "suppline-image", "sha256_abc111")
	if err := os.RemoveAll(cache); err != nil {
		t.Fatal(err)
	}
	src := imageFixture(t)
	unpack := &copyUnpacker{src: src}
	roots := &Roots{Image: newImageFS(unpack, "hostingmaloonde/cubebackup_workspace", "sha256:abc111")}
	pub := newPublicSource()
	job := Job{Repository: "hostingmaloonde/cubebackup_workspace", PackageName: "github.com/labstack/echo/v4", Digest: "sha256:abc111"}
	out, err := imageGrep(context.Background(), roots, pub, job, "Proxy|ProxyWithConfig|proxyRaw|proxyHTTP", ".")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "grep_id: g1") || !strings.Contains(out, "citable: absence") || !strings.Contains(out, "matches: 0") {
		t.Fatalf("echo absence: %s", out)
	}
	verdict := modelVerdict{
		Verdict: "not_affected", Justification: "code_not_reachable", Reasoning: "proxy is not linked",
		Evidence: []modelEvidence{{GrepID: "g1"}},
	}
	if err := verifyEvidence(*roots, pub, job, &verdict); err != nil {
		t.Fatal(err)
	}
	if len(verdict.Evidence) != 1 || verdict.Evidence[0].Pattern == "" {
		t.Fatalf("evidence = %+v", verdict.Evidence)
	}

	linked, err := imageGrep(context.Background(), roots, pub, job, "GzipWithConfig", ".")
	if err != nil || !strings.Contains(linked, "middleware.GzipWithConfig") || strings.Contains(linked, "citable: absence") {
		t.Fatalf("linked symbol: %s %v", linked, err)
	}
	if unpack.calls != 1 {
		t.Fatalf("unpack calls = %d", unpack.calls)
	}

	libc, err := imageGrep(context.Background(), roots, pub, Job{PackageName: "libc6", Digest: "sha256:abc111"}, "gets", ".")
	if err != nil || !strings.Contains(libc, "citable: no") || !strings.Contains(libc, "libc.so.6") {
		t.Fatalf("libc: %s %v", libc, err)
	}
	rejected := modelVerdict{
		Verdict: "not_affected", Justification: "code_not_reachable", Reasoning: "no gets",
		Evidence: []modelEvidence{{GrepID: "g3"}},
	}
	if err := verifyEvidence(*roots, pub, Job{PackageName: "libc6"}, &rejected); err == nil || !strings.Contains(err.Error(), "is not absence") {
		t.Fatalf("libc absence: %v", err)
	}

	kernel, err := imageGrep(context.Background(), roots, pub, Job{PackageName: "linux-libc-dev", Digest: "sha256:abc111"}, "copy_from_user", ".")
	if err != nil || !strings.Contains(kernel, "citable: no") || !strings.Contains(kernel, "workload rule") {
		t.Fatalf("kernel: %s %v", kernel, err)
	}
}

func TestPackageStemMatchesNativeLibrary(t *testing.T) {
	if got := packageStem("github.com/labstack/echo/v4"); got != "echo" {
		t.Fatalf("echo stem %q", got)
	}
	if got := packageStem("libc6"); got != "libc" {
		t.Fatalf("libc stem %q", got)
	}
	if got := packageStem("libssl3t64"); got != "libssl" {
		t.Fatalf("ssl stem %q", got)
	}
	if !nativeFileMatchesPackage("usr/lib/x86_64-linux-gnu/libc.so.6", "libc") {
		t.Fatal("libc.so.6")
	}
	if nativeFileMatchesPackage("usr/lib/x86_64-linux-gnu/libc.so.6", "echo") {
		t.Fatal("echo matched libc")
	}
	if !nativeFileMatchesPackage("usr/lib/x86_64-linux-gnu/libssl.so.3", "libssl") {
		t.Fatal("libssl.so.3")
	}
}

func imageFixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	bin := filepath.Join(dir, "opt", "cubebackup", "bin")
	lib := filepath.Join(dir, "usr", "lib")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(lib, 0o755); err != nil {
		t.Fatal(err)
	}
	script := "#!/bin/sh\nexec /opt/cubebackup/bin/cbsrv\n"
	if err := os.WriteFile(filepath.Join(bin, "start.sh"), []byte(script), 0o644); err != nil {
		t.Fatal(err)
	}
	goBin := append([]byte{0x7f, 'E', 'L', 'F'}, []byte(goBuildInfoMagic)...)
	goBin = append(goBin, []byte("github.com/labstack/echo/v4/middleware.GzipWithConfig\x00")...)
	if err := os.WriteFile(filepath.Join(bin, "cbackup"), goBin, 0o755); err != nil {
		t.Fatal(err)
	}
	libc := []byte{0x7f, 'E', 'L', 'F', 0, 1, 2, 3}
	if err := os.WriteFile(filepath.Join(lib, "libc.so.6"), libc, 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

type copyUnpacker struct {
	src   string
	calls int
}

func (c *copyUnpacker) UnpackImage(_ context.Context, _, _, dest string) error {
	c.calls++
	return filepath.WalkDir(c.src, func(full string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(c.src, full)
		if err != nil {
			return err
		}
		target := filepath.Join(dest, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		raw, err := os.ReadFile(full)
		if err != nil {
			return err
		}
		return os.WriteFile(target, raw, 0o644)
	})
}
