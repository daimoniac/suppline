package triage

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
)

const maxToolMatches = 40

// CheckoutRoot is one gitops checkout the agent is allowed to read.
type CheckoutRoot struct {
	Name    string
	Dir     string
	Include []string
	Exclude []string
	// Public is an upstream checkout fetched for this triage, not a gitops repo.
	Public bool
}

// Roots executes read-only tools inside checkout directories.
type Roots struct {
	Checkouts    []CheckoutRoot
	MaxFileBytes int
}

func (r Roots) ListDir(repo, rel string) (string, error) {
	root, err := r.checkout(repo)
	if err != nil {
		return "", err
	}
	dir, err := safePath(root.Dir, rel)
	if err != nil {
		return "", err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", err
	}
	var lines []string
	for _, entry := range entries {
		name := entry.Name()
		if name == ".git" {
			continue
		}
		child := name
		if rel != "" && rel != "." {
			child = path.Join(filepath.ToSlash(rel), name)
		}
		if deniedPath(child, root.Exclude) || !allowedPath(child, root.Include) {
			continue
		}
		suffix := ""
		if entry.IsDir() {
			suffix = "/"
		}
		lines = append(lines, name+suffix)
		if len(lines) >= maxToolMatches {
			lines = append(lines, "... truncated, use grep")
			break
		}
	}
	return strings.Join(lines, "\n"), nil
}

func (r Roots) ReadFile(repo, rel string, start, end int) (string, error) {
	root, err := r.checkout(repo)
	if err != nil {
		return "", err
	}
	rel = filepath.ToSlash(rel)
	if deniedPath(rel, root.Exclude) || !allowedPath(rel, root.Include) || deniedName(rel) {
		return "", fmt.Errorf("path is excluded")
	}
	full, err := safePath(root.Dir, rel)
	if err != nil {
		return "", err
	}
	info, err := os.Stat(full)
	if err != nil {
		return "", err
	}
	if info.Size() > int64(r.maxBytes()) {
		return "", fmt.Errorf("file exceeds %d bytes", r.maxBytes())
	}
	raw, err := os.ReadFile(full)
	if err != nil {
		return "", err
	}
	if isBinary(raw) || isSecretDocument(raw) {
		return "", fmt.Errorf("path is excluded")
	}
	text, err := Redact(rel, string(raw))
	if err != nil {
		return "", err
	}
	lines := strings.Split(text, "\n")
	if start < 1 {
		start = 1
	}
	if end < start {
		end = start + 199
	}
	if end-start > 199 {
		end = start + 199
	}
	if start > len(lines) {
		return "", fmt.Errorf("start line %d is past end of file (%d)", start, len(lines))
	}
	if end > len(lines) {
		end = len(lines)
	}
	var b strings.Builder
	for i := start; i <= end; i++ {
		fmt.Fprintf(&b, "%d|%s\n", i, lines[i-1])
	}
	return b.String(), nil
}

func (r Roots) Grep(repo, pattern, rel string) (string, error) {
	root, err := r.checkout(repo)
	if err != nil {
		return "", err
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return "", fmt.Errorf("invalid pattern: %w", err)
	}
	startDir := root.Dir
	if rel != "" && rel != "." {
		startDir, err = safePath(root.Dir, rel)
		if err != nil {
			return "", err
		}
	}
	var lines []string
	err = filepath.WalkDir(startDir, func(full string, d os.DirEntry, walkErr error) error {
		if walkErr != nil || len(lines) >= maxToolMatches {
			return nil
		}
		if d.IsDir() {
			if d.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		relPath, err := filepath.Rel(root.Dir, full)
		if err != nil {
			return nil
		}
		relPath = filepath.ToSlash(relPath)
		if deniedPath(relPath, root.Exclude) || !allowedPath(relPath, root.Include) || deniedName(relPath) {
			return nil
		}
		info, err := d.Info()
		if err != nil || info.Size() > int64(r.maxBytes()) {
			return nil
		}
		raw, err := os.ReadFile(full)
		if err != nil || isBinary(raw) || isSecretDocument(raw) {
			return nil
		}
		text, err := Redact(relPath, string(raw))
		if err != nil {
			return err
		}
		for i, line := range strings.Split(text, "\n") {
			if re.MatchString(line) {
				lines = append(lines, fmt.Sprintf("%s:%d:%s", relPath, i+1, line))
				if len(lines) >= maxToolMatches {
					break
				}
			}
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	return strings.Join(lines, "\n"), nil
}

// Line returns one 1-based line of a redacted file, for evidence checks.
func (r Roots) Line(repo, rel string, line int) (string, error) {
	text, err := r.ReadFile(repo, rel, line, line)
	if err != nil {
		return "", err
	}
	_, value, ok := strings.Cut(strings.TrimRight(text, "\n"), "|")
	if !ok {
		return "", fmt.Errorf("line %d not found", line)
	}
	return value, nil
}

func (r Roots) public(repo string) bool {
	root, err := r.checkout(repo)
	return err == nil && root.Public
}

func (r Roots) checkout(repo string) (CheckoutRoot, error) {
	if repo == "" && len(r.Checkouts) == 1 {
		return r.Checkouts[0], nil
	}
	for _, checkout := range r.Checkouts {
		if checkout.Name == repo {
			return checkout, nil
		}
	}
	return CheckoutRoot{}, fmt.Errorf("unknown repository %q", repo)
}

func (r Roots) maxBytes() int {
	if r.MaxFileBytes > 0 {
		return r.MaxFileBytes
	}
	return 32 * 1024
}

func safePath(root, rel string) (string, error) {
	rel = filepath.Clean(rel)
	if rel == "." {
		rel = ""
	}
	if filepath.IsAbs(rel) || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return "", fmt.Errorf("path escapes checkout")
	}
	rootAbs, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", err
	}
	full := filepath.Join(rootAbs, rel)
	resolved, err := filepath.EvalSymlinks(full)
	if err != nil {
		if !os.IsNotExist(err) {
			return "", err
		}
		parent := filepath.Dir(full)
		resolvedParent, perr := filepath.EvalSymlinks(parent)
		if perr != nil {
			return "", err
		}
		if !within(rootAbs, resolvedParent) {
			return "", fmt.Errorf("path escapes checkout")
		}
		return full, nil
	}
	if !within(rootAbs, resolved) {
		return "", fmt.Errorf("path escapes checkout")
	}
	return resolved, nil
}

func within(root, candidate string) bool {
	return candidate == root || strings.HasPrefix(candidate, root+string(os.PathSeparator))
}

func deniedPath(rel string, extra []string) bool {
	if deniedName(rel) {
		return true
	}
	for _, pattern := range extra {
		if globMatch(pattern, rel) {
			return true
		}
	}
	return false
}

func deniedName(rel string) bool {
	slash := "/" + filepath.ToSlash(rel)
	base := strings.ToLower(path.Base(rel))
	if strings.Contains(slash, "/.git/") || base == ".git" {
		return true
	}
	if strings.Contains(base, ".sops.") || strings.HasSuffix(base, ".sops") || strings.Contains(base, ".enc.") || strings.HasSuffix(base, ".enc") {
		return true
	}
	if strings.Contains(base, "sealedsecret") || strings.Contains(base, "sealed-secret") {
		return true
	}
	return false
}

func isSecretDocument(raw []byte) bool {
	text := string(raw)
	return strings.Contains(text, "kind: Secret") || strings.Contains(text, "kind: SealedSecret")
}

func isBinary(raw []byte) bool {
	n := len(raw)
	if n > 8000 {
		n = 8000
	}
	return strings.ContainsRune(string(raw[:n]), 0)
}

func allowedPath(rel string, include []string) bool {
	if len(include) == 0 {
		return true
	}
	for _, pattern := range include {
		if globMatch(pattern, rel) {
			return true
		}
	}
	return false
}

func globMatch(pattern, name string) bool {
	pattern = strings.TrimPrefix(filepath.ToSlash(pattern), "./")
	name = filepath.ToSlash(name)
	if strings.Contains(pattern, "**") {
		parts := strings.SplitN(pattern, "**", 2)
		prefix := strings.Trim(parts[0], "/")
		suffix := strings.TrimPrefix(parts[1], "/")
		if prefix != "" && name != prefix && !strings.HasPrefix(name, prefix+"/") {
			return false
		}
		rest := name
		if prefix != "" && strings.HasPrefix(name, prefix+"/") {
			rest = strings.TrimPrefix(name, prefix+"/")
		}
		if suffix == "" || suffix == "*" {
			return true
		}
		if strings.HasPrefix(suffix, "*.") {
			return strings.HasSuffix(rest, strings.TrimPrefix(suffix, "*")) || strings.HasSuffix(name, strings.TrimPrefix(suffix, "*"))
		}
		ok, _ := path.Match(suffix, path.Base(name))
		return ok
	}
	ok, _ := path.Match(pattern, name)
	if ok {
		return true
	}
	ok, _ = path.Match(pattern, path.Base(name))
	return ok
}
