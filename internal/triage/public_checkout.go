package triage

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const (
	ociImageSource   = "org.opencontainers.image.source"
	ociImageRevision = "org.opencontainers.image.revision"
)

var fullCommit = regexp.MustCompile(`^[0-9a-fA-F]{40}$`)

// gitAllowFileURL lets tests clone a local fixture. Production checkouts only
// build https://github.com URLs.
var gitAllowFileURL bool

type imageLabeler interface {
	ImageLabels(ctx context.Context, repository, digest string) (map[string]string, error)
}

type publicCheckouts struct {
	base  string
	pub   *publicSource
	clone func(ctx context.Context, dir, remote, sha, rel string) error
}

func formatImageLabels(labels map[string]string) string {
	source := strings.TrimSpace(labels[ociImageSource])
	revision := strings.TrimSpace(labels[ociImageRevision])
	if source == "" && revision == "" {
		return "image has no org.opencontainers.image.source or revision label\n"
	}
	var b strings.Builder
	if source == "" {
		b.WriteString("source: absent\n")
	} else {
		fmt.Fprintf(&b, "source: %s\n", oneLine(source, 300))
		if owner, repo, ok := parseGitHubSource(source); ok {
			fmt.Fprintf(&b, "owner: %s\nrepo: %s\n", owner, repo)
		}
	}
	if revision == "" {
		b.WriteString("revision: absent\n")
	} else {
		fmt.Fprintf(&b, "revision: %s\n", oneLine(revision, 80))
	}
	return b.String()
}

func parseGitHubSource(raw string) (string, string, bool) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || !strings.EqualFold(parsed.Hostname(), "github.com") {
		return "", "", false
	}
	parts := strings.Split(strings.Trim(parsed.Path, "/"), "/")
	if len(parts) < 2 {
		return "", "", false
	}
	repo := strings.TrimSuffix(parts[1], ".git")
	if !githubNamePattern.MatchString(parts[0]) || !githubNamePattern.MatchString(repo) {
		return "", "", false
	}
	return parts[0], repo, true
}

func (p *publicSource) resolveCommit(ctx context.Context, owner, repo, ref string) (string, error) {
	ref = strings.TrimSpace(ref)
	if fullCommit.MatchString(ref) {
		return strings.ToLower(ref), nil
	}
	if !githubRefPattern.MatchString(ref) || strings.Contains(ref, "..") {
		return "", fmt.Errorf("ref is not a branch, tag, or commit")
	}
	if p == nil {
		p = newPublicSource()
	}
	rawURL := strings.TrimRight(p.github, "/") + "/repos/" + url.PathEscape(owner) + "/" + url.PathEscape(repo) + "/commits/" + url.PathEscape(ref)
	body, status, err := p.get(ctx, rawURL)
	if err != nil {
		return "", err
	}
	if status != 200 {
		return "", fmt.Errorf("commit %s status %d", ref, status)
	}
	var payload struct {
		SHA string `json:"sha"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return "", fmt.Errorf("decode commit: %w", err)
	}
	if !fullCommit.MatchString(payload.SHA) {
		return "", fmt.Errorf("commit %s did not resolve", ref)
	}
	return strings.ToLower(payload.SHA), nil
}

func (c *publicCheckouts) Checkout(ctx context.Context, roots *Roots, owner, repo, ref, rel string) (string, error) {
	if c == nil {
		return "", fmt.Errorf("public checkout is unavailable")
	}
	if roots == nil {
		return "", fmt.Errorf("public checkout is unavailable")
	}
	owner, repo, ref, rel, err := cleanGitHubPath(owner, repo, ref, rel)
	if err != nil {
		return "", err
	}
	if rel == "" {
		return "", fmt.Errorf("path is required")
	}
	pub := c.pub
	if pub == nil {
		pub = newPublicSource()
	}
	sha, err := pub.resolveCommit(ctx, owner, repo, ref)
	if err != nil {
		return "", err
	}
	base := c.base
	if strings.TrimSpace(base) == "" {
		base = os.TempDir()
	}
	dir := filepath.Join(base, "public", owner, repo, sha)
	remote := "https://github.com/" + owner + "/" + repo + ".git"
	clone := c.clone
	if clone == nil {
		clone = cloneWithGit
	}
	if err := clone(ctx, dir, remote, sha, rel); err != nil {
		return "", err
	}
	name := owner + "/" + repo
	replaced := false
	for i := range roots.Checkouts {
		if roots.Checkouts[i].Name == name {
			roots.Checkouts[i].Dir = dir
			roots.Checkouts[i].Public = true
			roots.Checkouts[i].SHA = sha
			replaced = true
			break
		}
	}
	if !replaced {
		roots.Checkouts = append(roots.Checkouts, CheckoutRoot{Name: name, Dir: dir, Public: true, SHA: sha})
	}
	return fmt.Sprintf("checked out %s@%s\npath: %s\nuse grep and read_file with repo %s\n", name, sha, rel, name), nil
}

func cloneWithGit(ctx context.Context, dir, remote, sha, rel string) error {
	parsed, err := url.Parse(remote)
	if err != nil {
		return err
	}
	fileProto := false
	switch parsed.Scheme {
	case "https":
		if !strings.EqualFold(parsed.Hostname(), "github.com") || parsed.User != nil {
			return fmt.Errorf("only https://github.com checkouts are allowed")
		}
	case "file":
		if !gitAllowFileURL {
			return fmt.Errorf("only https://github.com checkouts are allowed")
		}
		fileProto = true
	default:
		return fmt.Errorf("only https://github.com checkouts are allowed")
	}
	if !fullCommit.MatchString(sha) {
		return fmt.Errorf("checkout ref must be a full commit")
	}
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	if head, err := gitOutput(ctx, dir, "rev-parse", "HEAD"); err == nil && strings.TrimSpace(head) == sha {
		info, statErr := os.Stat(filepath.Join(dir, rel))
		if statErr == nil && info.IsDir() {
			return nil
		}
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	if _, err := os.Stat(filepath.Join(dir, ".git")); err != nil {
		if err := os.RemoveAll(dir); err != nil {
			return err
		}
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
		if err := runGit(ctx, dir, fileProto, "init"); err != nil {
			return err
		}
		if err := runGit(ctx, dir, fileProto, "remote", "add", "origin", remote); err != nil {
			return err
		}
	}
	fetch := []string{"fetch", "--depth", "1", "--filter=blob:none", "origin", sha}
	if err := runGit(ctx, dir, fileProto, fetch...); err != nil {
		if err := runGit(ctx, dir, fileProto, "fetch", "--depth", "1", "origin", sha); err != nil {
			return err
		}
	}
	if rel != "." {
		if err := runGit(ctx, dir, fileProto, "sparse-checkout", "set", "--cone", rel); err != nil {
			return err
		}
	}
	if err := runGit(ctx, dir, fileProto, "checkout", "--detach", "FETCH_HEAD"); err != nil {
		return err
	}
	head, err := gitOutput(ctx, dir, "rev-parse", "HEAD")
	if err != nil {
		return err
	}
	if strings.TrimSpace(head) != sha {
		return fmt.Errorf("checkout resolved to %s", strings.TrimSpace(head))
	}
	if rel == "." {
		info, err := os.Stat(dir)
		if err != nil || !info.IsDir() {
			return fmt.Errorf("path . is not in the checkout")
		}
		return nil
	}
	info, err := os.Stat(filepath.Join(dir, rel))
	if err != nil || !info.IsDir() {
		return fmt.Errorf("path %s is not in the checkout", rel)
	}
	return nil
}

func runGit(ctx context.Context, dir string, fileProto bool, args ...string) error {
	if _, err := exec.LookPath("git"); err != nil {
		return fmt.Errorf("git is not installed")
	}
	prefix := []string{"-C", dir, "-c", "credential.helper=", "-c", "core.hooksPath=/dev/null", "-c", "submodule.recurse=false"}
	if fileProto {
		prefix = append(prefix, "-c", "protocol.file.allow=always")
	} else {
		prefix = append(prefix, "-c", "protocol.file.allow=never")
	}
	cmd := exec.CommandContext(ctx, "git", append(prefix, args...)...)
	cmd.Env = gitEnviron()
	out, err := cmd.CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if len(msg) > 400 {
			msg = msg[:400]
		}
		return fmt.Errorf("git %s: %s", args[0], msg)
	}
	return nil
}

func gitOutput(ctx context.Context, dir string, args ...string) (string, error) {
	if _, err := os.Stat(filepath.Join(dir, ".git")); err != nil {
		return "", err
	}
	cmd := exec.CommandContext(ctx, "git", append([]string{"-C", dir}, args...)...)
	cmd.Env = gitEnviron()
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return string(out), nil
}

func gitEnviron() []string {
	return []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + os.TempDir(),
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL=" + os.DevNull,
		"GIT_TERMINAL_PROMPT=0",
		"GIT_CONFIG_COUNT=0",
		"LC_ALL=C",
	}
}
