package triage

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestPublicCheckoutResolvesCommitAndRecordsCall(t *testing.T) {
	const sha = "0123456789abcdef0123456789abcdef01234567"
	labels := formatImageLabels(map[string]string{
		ociImageSource:   "https://github.com/supabase/supabase.git",
		ociImageRevision: "7996410",
	})
	for _, want := range []string{"owner: supabase", "repo: supabase", "revision: 7996410"} {
		if !strings.Contains(labels, want) {
			t.Fatalf("labels missing %q\n%s", want, labels)
		}
	}
	if !strings.Contains(formatImageLabels(nil), "no org.opencontainers.image.source") {
		t.Fatal("absent labels")
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/repos/supabase/supabase/commits/7996410" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"sha": sha})
	}))
	t.Cleanup(srv.Close)
	parsed, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	pub := &publicSource{
		client:   srv.Client(),
		hosts:    map[string]struct{}{parsed.Hostname(): {}},
		insecure: true,
		github:   srv.URL,
	}
	var remote string
	upstream := &publicCheckouts{
		base: t.TempDir(),
		pub:  pub,
		clone: func(ctx context.Context, dir, gotRemote, gotSHA, rel string) error {
			remote = gotRemote
			if gotSHA != sha || rel != "apps/studio" {
				return errString("clone " + gotSHA + " " + rel)
			}
			if err := os.MkdirAll(filepath.Join(dir, rel), 0o755); err != nil {
				return err
			}
			return os.WriteFile(filepath.Join(dir, rel, "call.ts"), []byte("DOMPurify.sanitize(value)\n"), 0o644)
		},
	}
	roots := Roots{}
	out, err := upstream.Checkout(context.Background(), &roots, "supabase", "supabase", "7996410", "apps/studio")
	if err != nil {
		t.Fatal(err)
	}
	if remote != "https://github.com/supabase/supabase.git" || !strings.Contains(out, "supabase/supabase@"+sha) {
		t.Fatalf("remote %s output %s", remote, out)
	}
	if !roots.public("supabase/supabase") {
		t.Fatal("checkout was not marked public")
	}
	grepped, err := roots.Grep("supabase/supabase", "DOMPurify", "apps/studio")
	if err != nil {
		t.Fatal(err)
	}
	pub.rememberGrep("supabase/supabase", grepped)
	verdict := modelVerdict{
		Verdict:       "not_affected",
		Justification: "code_not_reachable",
		Evidence: []modelEvidence{{
			Repo: "supabase/supabase", Path: "apps/studio/call.ts", Line: 1, Quote: "DOMPurify.sanitize(value)",
		}},
	}
	if err := verifyEvidence(roots, pub, Job{}, verdict); err != nil {
		t.Fatal(err)
	}
	if _, err := upstream.Checkout(context.Background(), &roots, "supabase", "supabase", "main", ""); err == nil {
		t.Fatal("accepted an empty path")
	}
	if err := cloneWithGit(context.Background(), t.TempDir(), "file:///tmp/not-a-repo", sha, "apps/studio"); err == nil {
		t.Fatal("accepted a file URL")
	}
}

func TestCloneWithGitSparsePath(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip(err)
	}
	gitAllowFileURL = true
	t.Cleanup(func() { gitAllowFileURL = false })

	src := t.TempDir()
	gitCmd(t, "init", "-b", "main", src)
	if err := os.MkdirAll(filepath.Join(src, "apps", "studio"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "apps", "studio", "call.ts"), []byte("DOMPurify.sanitize(value)\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(src, "apps", "other"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "apps", "other", "skip.ts"), []byte("nope\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitCmd(t, "-C", src, "add", "apps/studio/call.ts", "apps/other/skip.ts")
	gitCmd(t, "-C", src, "commit", "-m", "init")
	sha := strings.TrimSpace(gitCmd(t, "-C", src, "rev-parse", "HEAD"))
	bare := filepath.Join(t.TempDir(), "bare.git")
	gitCmd(t, "clone", "--bare", src, bare)
	gitCmd(t, "-C", bare, "config", "uploadpack.allowReachableSHA1InWant", "true")
	gitCmd(t, "-C", bare, "config", "uploadpack.allowFilter", "true")

	dest := filepath.Join(t.TempDir(), "co")
	if err := cloneWithGit(context.Background(), dest, "file://"+bare, sha, "apps/studio"); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(filepath.Join(dest, "apps", "studio", "call.ts"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "DOMPurify.sanitize(value)") {
		t.Fatalf("checked out file: %s", body)
	}
	if _, err := os.Stat(filepath.Join(dest, "apps", "other", "skip.ts")); err == nil {
		t.Fatal("sparse checkout included a sibling directory")
	}
}

func gitCmd(t *testing.T, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=test",
		"GIT_AUTHOR_EMAIL=test@example.com",
		"GIT_COMMITTER_NAME=test",
		"GIT_COMMITTER_EMAIL=test@example.com",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %s", args, out)
	}
	return string(out)
}

type errString string

func (e errString) Error() string { return string(e) }
