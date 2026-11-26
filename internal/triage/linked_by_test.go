package triage

import (
	"context"
	"debug/elf"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/daimoniac/suppline/internal/registry"
)

// The argocd case: only git's HTTP helpers reach libbrotlidec, through libcurl.
func TestLinkClosureFollowsLibraries(t *testing.T) {
	files := []elfInfo{
		{path: "usr/lib/libbrotlidec.so.1.1.0", soname: "libbrotlidec.so.1", needed: []string{"libbrotlicommon.so.1"}},
		{path: "usr/lib/libcurl-gnutls.so.4.8.0", soname: "libcurl-gnutls.so.4", needed: []string{"libbrotlidec.so.1", "libc.so.6"}},
		{path: "usr/lib/git-core/git-remote-http", soname: "git-remote-http", needed: []string{"libcurl-gnutls.so.4"}, exe: true},
		{path: "usr/bin/argocd", soname: "argocd", exe: true},
		{path: "usr/lib/libfreetype.so.6", soname: "libfreetype.so.6", needed: []string{"libz.so.1"}},
	}
	loaders, providers := linkClosure(files, "libbrotlidec")
	if !reflect.DeepEqual(providers, []string{"libbrotlidec.so.1"}) {
		t.Fatalf("providers = %v", providers)
	}
	var got []string
	for _, l := range loaders {
		got = append(got, l.info.path+" via "+l.via)
	}
	want := []string{
		"usr/lib/git-core/git-remote-http via libcurl-gnutls.so.4",
		"usr/lib/libcurl-gnutls.so.4.8.0 via libbrotlidec.so.1",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("loaders = %v\nwant %v", got, want)
	}
}

func TestFileContainsAcrossChunkBoundary(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bin")
	data := make([]byte, 3<<20)
	copy(data[1<<20-4:], "libbrotlidec.so") // straddles the first chunk
	copy(data[2<<20+10:], "BrotliDecoderDecompress")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	name, sym := fileContains(path, []byte("libbrotlidec.so"), []byte("BrotliDecoderDecompress"))
	if !name || !sym {
		t.Fatalf("name=%v sym=%v", name, sym)
	}
	if name, sym := fileContains(path, []byte("libxml2.so"), nil); name || sym {
		t.Fatalf("absent name found: name=%v sym=%v", name, sym)
	}
}

// dynamicBinary returns a system executable that links libc dynamically.
func dynamicBinary(t *testing.T) string {
	t.Helper()
	for _, path := range []string{"/bin/sh", "/usr/bin/env", "/bin/ls", "/usr/bin/true"} {
		resolved, err := filepath.EvalSymlinks(path)
		if err != nil {
			continue
		}
		ef, err := elf.Open(resolved)
		if err != nil {
			continue
		}
		libs, _ := ef.ImportedLibraries()
		ef.Close()
		for _, lib := range libs {
			if strings.HasPrefix(lib, "libc.so") {
				return resolved
			}
		}
	}
	t.Skip("no dynamically linked system binary to use as a fixture")
	return ""
}

func linkedImage(t *testing.T, digest string, skipped bool) *Roots {
	t.Helper()
	cache := filepath.Join(os.TempDir(), "suppline-image", sanitizeDigest(digest))
	if err := os.RemoveAll(cache); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(cache) })
	src := t.TempDir()
	raw, err := os.ReadFile(dynamicBinary(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(src, "usr/bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "usr/bin/tool"), raw, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "README"), []byte("libc.so.6 is named here but this is no ELF\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if skipped {
		if err := os.WriteFile(filepath.Join(src, registry.SkippedFilesManifest), []byte("opt/app/server\t90000000\t1\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return &Roots{Image: newImageFS(&copyUnpacker{src: src}, "hostingmaloonde/tool", digest)}
}

func TestLinkedByListsLoadersAndRecordsThem(t *testing.T) {
	roots := linkedImage(t, "sha256:linked1", false)
	pub := newPublicSource()
	job := Job{CVEID: "CVE-2026-1", PackageName: "libc6", Digest: "sha256:linked1"}
	pub.setPhase(job.CVEID)

	out, err := linkedBy(context.Background(), roots, pub, job, "libc", "")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "usr/bin/tool:1:executable loads libc via libc.so") || !strings.Contains(out, "citable: rows") || !strings.Contains(out, "not_checked: 0") {
		t.Fatalf("loader of libc:\n%s", out)
	}
	if strings.Contains(out, "README") {
		t.Fatalf("a non-ELF file was listed:\n%s", out)
	}

	absent, err := linkedBy(context.Background(), roots, pub, job, "libbrotlidec", "BrotliDecoderDecompress")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(absent, "citable: absence") || !strings.Contains(absent, "loaders: 0") {
		t.Fatalf("nothing loads libbrotlidec:\n%s", absent)
	}
	verdict := modelVerdict{Verdict: "not_affected", Justification: "code_not_reachable", Evidence: []modelEvidence{{GrepID: "g2"}}}
	if err := verifyEvidence(*roots, pub, job, &verdict); err != nil {
		t.Fatalf("an absence from a fully checked image backs code_not_reachable: %v", err)
	}
	if got := verdict.Evidence[0].Pattern; got != linkedPrefix+"libbrotlidec|BrotliDecoderDecompress" {
		t.Fatalf("recorded pattern %q", got)
	}
}

// A file the unpack left out could load the library, so nothing found is not
// absence.
func TestLinkedBySkippedFileIsNotAbsence(t *testing.T) {
	roots := linkedImage(t, "sha256:linked2", true)
	pub := newPublicSource()
	job := Job{CVEID: "CVE-2026-2", Digest: "sha256:linked2"}
	pub.setPhase(job.CVEID)
	out, err := linkedBy(context.Background(), roots, pub, job, "libbrotlidec", "")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "citable: absence") || !strings.Contains(out, "not_checked: 1") || !strings.Contains(out, "opt/app/server:1:not checked: file not unpacked, 90000000 bytes") {
		t.Fatalf("skipped file must block absence:\n%s", out)
	}
}

func TestLinkedByRejectsNonLibraryNames(t *testing.T) {
	for _, name := range []string{"", "brotli", "../etc/passwd", "lib brotli"} {
		if _, err := linkedBy(context.Background(), &Roots{}, newPublicSource(), Job{}, name, ""); err == nil {
			t.Fatalf("%q accepted", name)
		}
	}
}
