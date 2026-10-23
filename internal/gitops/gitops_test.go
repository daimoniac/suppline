package gitops

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
)

func TestCommitFilePushRetryAndRejection(t *testing.T) {
	bare := filepath.Join(t.TempDir(), "bare.git")
	branch := seedBare(t, bare)
	manager := &Manager{Base: t.TempDir()}
	spec := Spec{Name: "config", URL: bare, Branch: branch, AuthorName: "suppline-triage", AuthorEmail: "triage@suppline.local"}
	ctx := context.Background()

	var conflicts int
	manager.BeforePush = func() error {
		if conflicts > 0 {
			return nil
		}
		conflicts++
		pushExtra(t, bare, branch, "README.md", "other\n")
		return nil
	}
	sha, err := manager.CommitFile(ctx, spec, "suppline.yml", func(current []byte) ([]byte, error) {
		return append(current, []byte("\n# triaged\n")...), nil
	}, "chore(vex): auto-triage CVE-1 for app")
	if err != nil {
		t.Fatal(err)
	}
	if sha == "" || conflicts != 1 {
		t.Fatalf("sha=%s conflicts=%d", sha, conflicts)
	}
	body := fileAtHEAD(t, bare, "suppline.yml")
	if !contains(body, "# triaged") || !contains(fileAtHEAD(t, bare, "README.md"), "other") {
		t.Fatalf("retry did not keep both edits\n%s", body)
	}

	rejected := &Manager{Base: t.TempDir()}
	nonBare := t.TempDir()
	if _, err := git.PlainClone(nonBare, false, &git.CloneOptions{URL: bare}); err != nil {
		t.Fatal(err)
	}
	_, err = rejected.CommitFile(ctx, Spec{URL: nonBare, Branch: branch}, "suppline.yml", func(current []byte) ([]byte, error) {
		return append(current, []byte("\n# no\n")...), nil
	}, "chore(vex): should fail")
	var pushErr *PushError
	if !errors.As(err, &pushErr) {
		t.Fatalf("expected push rejection, got %v", err)
	}
}

func seedBare(t *testing.T, bare string) string {
	t.Helper()
	src := t.TempDir()
	repo, err := git.PlainInit(src, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "suppline.yml"), []byte("version: 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	worktree, err := repo.Worktree()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := worktree.Add("suppline.yml"); err != nil {
		t.Fatal(err)
	}
	if _, err := worktree.Commit("init", &git.CommitOptions{Author: signature()}); err != nil {
		t.Fatal(err)
	}
	head, err := repo.Head()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := git.PlainClone(bare, true, &git.CloneOptions{URL: src}); err != nil {
		t.Fatal(err)
	}
	return head.Name().Short()
}

func pushExtra(t *testing.T, bare, branch, name, body string) {
	t.Helper()
	dir := t.TempDir()
	repo, err := git.PlainClone(dir, false, &git.CloneOptions{URL: bare, ReferenceName: plumbing.NewBranchReferenceName(branch), SingleBranch: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	worktree, err := repo.Worktree()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := worktree.Add(name); err != nil {
		t.Fatal(err)
	}
	if _, err := worktree.Commit("side", &git.CommitOptions{Author: signature()}); err != nil {
		t.Fatal(err)
	}
	if err := repo.Push(&git.PushOptions{}); err != nil {
		t.Fatal(err)
	}
}

func fileAtHEAD(t *testing.T, bare, name string) string {
	t.Helper()
	repo, err := git.PlainOpen(bare)
	if err != nil {
		t.Fatal(err)
	}
	head, err := repo.Head()
	if err != nil {
		t.Fatal(err)
	}
	commit, err := repo.CommitObject(head.Hash())
	if err != nil {
		t.Fatal(err)
	}
	file, err := commit.File(name)
	if err != nil {
		t.Fatal(err)
	}
	body, err := file.Contents()
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func signature() *object.Signature {
	return &object.Signature{Name: "test", Email: "test@example.com", When: time.Now().UTC()}
}

func contains(s, sub string) bool {
	return len(sub) == 0 || (len(s) >= len(sub) && (s == sub || len(s) > 0 && indexOf(s, sub) >= 0))
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
