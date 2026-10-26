package triage

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
)

const imageCheckoutName = "image"

const (
	maxImageSearchBytes = 64 << 20
	goBuildInfoMagic    = "\xff Go buildinf:"
)

// imageUnpacker writes the scanned image's filesystem into dest.
type imageUnpacker interface {
	UnpackImage(ctx context.Context, repository, digest, dest string) error
}

// imageFS is one scanned image, unpacked once into dir.
type imageFS struct {
	unpack imageUnpacker
	repo   string
	digest string
	dir    string

	mu    sync.Mutex
	ready bool
	err   error
}

func newImageFS(unpack imageUnpacker, repository, digest string) *imageFS {
	repository = strings.TrimSpace(repository)
	digest = strings.TrimSpace(digest)
	if unpack == nil || repository == "" || digest == "" {
		return nil
	}
	return &imageFS{
		unpack: unpack,
		repo:   repository,
		digest: digest,
		dir:    filepath.Join(os.TempDir(), "suppline-image", sanitizeDigest(digest)),
	}
}

func (f *imageFS) extract(ctx context.Context) (string, error) {
	if f == nil {
		return "", fmt.Errorf("image checkout is unavailable")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return "", f.err
	}
	if f.ready {
		return f.dir, nil
	}
	marker := filepath.Join(f.dir, ".extracted")
	if _, err := os.Stat(marker); err == nil {
		f.ready = true
		return f.dir, nil
	}
	if err := os.RemoveAll(f.dir); err != nil {
		f.err = err
		return "", f.err
	}
	if err := os.MkdirAll(f.dir, 0o755); err != nil {
		f.err = err
		return "", f.err
	}
	if err := f.unpack.UnpackImage(ctx, f.repo, f.digest, f.dir); err != nil {
		_ = os.RemoveAll(f.dir)
		f.err = err
		return "", f.err
	}
	if err := os.WriteFile(filepath.Join(f.dir, ".extracted"), []byte("ok\n"), 0o644); err != nil {
		f.err = err
		return "", f.err
	}
	f.ready = true
	return f.dir, nil
}

func (r *Roots) mountImage(ctx context.Context) error {
	if r == nil || r.Image == nil {
		return fmt.Errorf("image checkout is unavailable")
	}
	dir, err := r.Image.extract(ctx)
	if err != nil {
		return err
	}
	for i := range r.Checkouts {
		if r.Checkouts[i].Name == imageCheckoutName {
			r.Checkouts[i].Dir = dir
			return nil
		}
	}
	r.Checkouts = append(r.Checkouts, CheckoutRoot{
		Name:    imageCheckoutName,
		Dir:     dir,
		Exclude: []string{".extracted"},
		Paths:   []string{"."},
	})
	return nil
}

func imageGrep(ctx context.Context, roots *Roots, pub *publicSource, job Job, pattern, rel string) (string, error) {
	if roots == nil {
		return "", fmt.Errorf("image checkout is unavailable")
	}
	if err := roots.mountImage(ctx); err != nil {
		return "", err
	}
	root, err := roots.checkout(imageCheckoutName)
	if err != nil {
		return "", err
	}
	rows, absence, skipped, note, err := grepImageDir(root.Dir, pattern, rel, job.PackageName)
	if err != nil {
		return "", err
	}
	id := pub.recordImageGrep(imageCheckoutName, pattern, rel, job.Digest, rows, absence)
	if id == "" {
		return "", fmt.Errorf("grep was not recorded")
	}
	return formatImageGrep(id, job.Digest, pattern, rel, rows, absence, skipped, note), nil
}

func grepImageDir(dir, pattern, rel, packageName string) (rows string, absence bool, skipped []string, note string, err error) {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return "", false, nil, "", fmt.Errorf("invalid pattern: %w", err)
	}
	start := dir
	if cleanRel(rel) != "." {
		start, err = safePath(dir, rel)
		if err != nil {
			return "", false, nil, "", err
		}
	}
	var matches []string
	var native []string
	oversized := false
	walkErr := filepath.WalkDir(start, func(full string, d os.DirEntry, walkErr error) error {
		if walkErr != nil || len(matches) >= maxToolMatches {
			return nil
		}
		if d.IsDir() {
			if d.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		relPath, err := filepath.Rel(dir, full)
		if err != nil {
			return nil
		}
		relPath = filepath.ToSlash(relPath)
		if relPath == ".extracted" || deniedName(relPath) {
			return nil
		}
		info, err := d.Info()
		if err != nil || !info.Mode().IsRegular() {
			return nil
		}
		if info.Size() > maxImageSearchBytes {
			if elfFile(full) {
				native = append(native, relPath)
				oversized = true
			}
			return nil
		}
		raw, err := os.ReadFile(full)
		if err != nil {
			return nil
		}
		switch {
		case isGoBinary(raw):
			found, err := goSymbolMatches(relPath, raw, re)
			if err != nil {
				return err
			}
			matches = append(matches, found...)
		case isELF(raw):
			native = append(native, relPath)
		default:
			if isBinary(raw) || isSecretDocument(raw) {
				return nil
			}
			found, err := textMatches(relPath, raw, re)
			if err != nil {
				return err
			}
			matches = append(matches, found...)
		}
		if len(matches) > maxToolMatches {
			matches = matches[:maxToolMatches]
		}
		return nil
	})
	if walkErr != nil {
		return "", false, nil, "", walkErr
	}
	absence, note = imageAbsence(packageName, matches, native, oversized)
	return strings.Join(matches, "\n"), absence, native, note, nil
}

func imageAbsence(packageName string, matches, native []string, oversized bool) (bool, string) {
	if len(matches) > 0 {
		return false, ""
	}
	if kernelPackage(packageName) {
		return false, "kernel package; use the workload rule"
	}
	if oversized {
		return false, "a native file was too large to search"
	}
	if stem := packageStem(packageName); stem != "" {
		for _, file := range native {
			if nativeFileMatchesPackage(file, stem) {
				return false, "a skipped native file belongs to the package"
			}
		}
	}
	return true, ""
}

func packageStem(name string) string {
	base := strings.TrimSpace(name)
	if i := strings.LastIndex(base, "/"); i >= 0 {
		parent := base[:i]
		last := base[i+1:]
		if versionToken(last) && parent != "" {
			if j := strings.LastIndex(parent, "/"); j >= 0 {
				base = parent[j+1:]
			} else {
				base = parent
			}
		} else {
			base = last
		}
	}
	base = strings.ToLower(base)
	base = strings.TrimSuffix(base, "t64")
	base = strings.TrimRight(base, "0123456789.")
	if len(base) < 3 {
		return ""
	}
	return base
}

func versionToken(s string) bool {
	s = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(s)), "v")
	if s == "" {
		return false
	}
	for _, r := range s {
		if r != '.' && (r < '0' || r > '9') {
			return false
		}
	}
	return true
}

func nativeFileMatchesPackage(file, stem string) bool {
	base := strings.ToLower(path.Base(file))
	if i := strings.Index(base, ".so"); i >= 0 {
		base = base[:i]
	}
	base = strings.TrimRight(base, "0123456789.-_")
	return base == stem || base == "lib"+stem
}

func isGoBinary(raw []byte) bool {
	return bytes.Contains(raw, []byte(goBuildInfoMagic))
}

func isELF(raw []byte) bool {
	return len(raw) >= 4 && raw[0] == 0x7f && raw[1] == 'E' && raw[2] == 'L' && raw[3] == 'F'
}

func elfFile(full string) bool {
	f, err := os.Open(full)
	if err != nil {
		return false
	}
	defer f.Close()
	var hdr [4]byte
	n, err := f.Read(hdr[:])
	return err == nil && isELF(hdr[:n])
}

func goSymbolMatches(rel string, raw []byte, re *regexp.Regexp) ([]string, error) {
	indexes := re.FindAllIndex(raw, maxToolMatches)
	var lines []string
	seen := map[string]struct{}{}
	for _, span := range indexes {
		snippet := printableWindow(raw, span[0], span[1])
		if snippet == "" {
			continue
		}
		redacted, err := Redact(rel, snippet)
		if err != nil {
			return nil, err
		}
		redacted = strings.TrimSpace(redacted)
		if redacted == "" {
			continue
		}
		if _, ok := seen[redacted]; ok {
			continue
		}
		seen[redacted] = struct{}{}
		lines = append(lines, fmt.Sprintf("%s:1:%s", rel, oneLine(redacted, 160)))
		if len(lines) >= maxToolMatches {
			break
		}
	}
	return lines, nil
}

func textMatches(rel string, raw []byte, re *regexp.Regexp) ([]string, error) {
	text, err := Redact(rel, string(raw))
	if err != nil {
		return nil, err
	}
	var lines []string
	for i, line := range strings.Split(text, "\n") {
		if !re.MatchString(line) {
			continue
		}
		lines = append(lines, fmt.Sprintf("%s:%d:%s", rel, i+1, oneLine(line, 200)))
		if len(lines) >= maxToolMatches {
			break
		}
	}
	return lines, nil
}

func printableWindow(raw []byte, start, end int) string {
	lo := start
	for lo > 0 && start-lo < 80 && raw[lo-1] >= 32 && raw[lo-1] < 127 {
		lo--
	}
	hi := end
	for hi < len(raw) && hi-end < 80 && raw[hi] >= 32 && raw[hi] < 127 {
		hi++
	}
	return strings.TrimSpace(string(raw[lo:hi]))
}

func formatImageGrep(id, digest, pattern, rel, rows string, absence bool, skipped []string, note string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "grep_id: %s\nrepo: %s\ncommit: %s\npattern: %s\npath: %s\nmatches: %d\nsearched: scripts, source, go\nskipped_native: %d\nabsence: %t\n",
		id, imageCheckoutName, strings.TrimSpace(digest), pattern, cleanRel(rel), matchCount(rows), len(skipped), absence)
	if note != "" {
		fmt.Fprintf(&b, "note: %s\n", note)
	}
	if !absence && strings.TrimSpace(rows) == "" {
		limit := len(skipped)
		if limit > 8 {
			limit = 8
		}
		for _, file := range skipped[:limit] {
			fmt.Fprintf(&b, "skipped: %s\n", file)
		}
	}
	if strings.TrimSpace(rows) != "" {
		b.WriteString(rows)
		if !strings.HasSuffix(rows, "\n") {
			b.WriteByte('\n')
		}
	}
	return b.String()
}

func sanitizeDigest(digest string) string {
	var b strings.Builder
	for _, r := range digest {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '_', r == '-':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	if b.Len() == 0 {
		return "image"
	}
	return b.String()
}
