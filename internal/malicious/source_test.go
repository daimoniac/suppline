package malicious

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"

	"github.com/daimoniac/suppline/internal/gitops"
)

type upstream struct {
	t    *testing.T
	dir  string
	repo *git.Repository
}

func newUpstream(t *testing.T) *upstream {
	t.Helper()
	dir := t.TempDir()
	repo, err := git.PlainInit(dir, false)
	if err != nil {
		t.Fatal(err)
	}
	return &upstream{t: t, dir: dir, repo: repo}
}

func (u *upstream) write(path, content string) {
	u.t.Helper()
	full := filepath.Join(u.dir, path)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		u.t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
		u.t.Fatal(err)
	}
}

func (u *upstream) move(from, to string) {
	u.t.Helper()
	if err := os.MkdirAll(filepath.Dir(filepath.Join(u.dir, to)), 0o755); err != nil {
		u.t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(u.dir, from), filepath.Join(u.dir, to)); err != nil {
		u.t.Fatal(err)
	}
}

func (u *upstream) commit(message string) string {
	u.t.Helper()
	worktree, err := u.repo.Worktree()
	if err != nil {
		u.t.Fatal(err)
	}
	if err := worktree.AddWithOptions(&git.AddOptions{All: true}); err != nil {
		u.t.Fatal(err)
	}
	hash, err := worktree.Commit(message, &git.CommitOptions{
		Author: &object.Signature{Name: "test", Email: "test@example.com", When: time.Now()},
	})
	if err != nil {
		u.t.Fatal(err)
	}
	return hash.String()
}

func (u *upstream) branch() string {
	u.t.Helper()
	head, err := u.repo.Head()
	if err != nil {
		u.t.Fatal(err)
	}
	return head.Name().Short()
}

func osvJSON(id, ecosystem, name, summary string) string {
	return `{"id":"` + id + `","summary":"` + summary + `","affected":[{"package":{"ecosystem":"` + ecosystem + `","name":"` + name + `"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"}]}]}]}`
}

func keys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func TestSourceSyncLoadAndDiff(t *testing.T) {
	ctx := context.Background()
	up := newUpstream(t)
	up.write("README.md", "upstream")
	up.write("osv/malicious/npm/a/MAL-1.json", osvJSON("MAL-1", "npm", "a", "first"))
	up.write("osv/malicious/pypi/b/MAL-2.json", osvJSON("MAL-2", "PyPI", "b", "second"))
	up.write("osv/malicious/vscode/x/MAL-9.json", osvJSON("MAL-9", "VSCode", "x", "ignored"))
	first := up.commit("first")

	source := NewSource(up.dir, up.branch(), gitops.Auth{}, t.TempDir(), nil, nil)
	result, err := source.Sync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Previous.IsZero() || result.Current.String() != first {
		t.Fatalf("unexpected first sync %+v", result)
	}
	entries, err := source.LoadAll(ctx, result.Current)
	if err != nil {
		t.Fatal(err)
	}
	if got := keys(entries); len(got) != 2 || got[0] != "osv/malicious/npm/a/MAL-1.json" || got[1] != "osv/malicious/pypi/b/MAL-2.json" {
		t.Fatalf("unexpected entries %v", got)
	}

	// Unchanged upstream: same commit, nothing to diff.
	again, err := source.Sync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if again.Previous != again.Current {
		t.Fatalf("expected no change, got %+v", again)
	}

	up.write("osv/malicious/npm/a/MAL-1.json", osvJSON("MAL-1", "npm", "a", "updated"))
	up.write("osv/malicious/npm/c/MAL-3.json", osvJSON("MAL-3", "npm", "c", "third"))
	up.write("osv/malicious/npm/d/MAL-4.json", "{broken")
	up.move("osv/malicious/pypi/b/MAL-2.json", "osv/withdrawn/pypi/b/MAL-2.json")
	second := up.commit("second")

	result, err = source.Sync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if result.Previous.String() != first || result.Current.String() != second {
		t.Fatalf("unexpected second sync %+v", result)
	}
	changed, removed, err := source.Diff(ctx, result.Previous, result.Current)
	if err != nil {
		t.Fatal(err)
	}
	if got := keys(changed); len(got) != 2 || got[0] != "osv/malicious/npm/a/MAL-1.json" || got[1] != "osv/malicious/npm/c/MAL-3.json" {
		t.Fatalf("unexpected changed %v", got)
	}
	if changed["osv/malicious/npm/a/MAL-1.json"].Summary != "updated" {
		t.Fatalf("modified entry not reread")
	}
	if len(removed) != 1 || removed[0] != "osv/malicious/pypi/b/MAL-2.json" {
		t.Fatalf("unexpected removed %v", removed)
	}
}

func TestSourceReclonesBrokenClone(t *testing.T) {
	ctx := context.Background()
	up := newUpstream(t)
	up.write("osv/malicious/npm/a/MAL-1.json", osvJSON("MAL-1", "npm", "a", "first"))
	head := up.commit("first")

	dir := t.TempDir()
	source := NewSource(up.dir, up.branch(), gitops.Auth{}, dir, nil, nil)
	if _, err := source.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	// Drop the refs so the clone has no usable tip.
	if err := os.RemoveAll(filepath.Join(dir, "repo.git", "refs")); err != nil {
		t.Fatal(err)
	}
	_ = os.Remove(filepath.Join(dir, "repo.git", "packed-refs"))

	result, err := source.Sync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Previous.IsZero() || result.Current.String() != head {
		t.Fatalf("expected a fresh clone, got %+v", result)
	}
}

func TestSourceCloneFailure(t *testing.T) {
	source := NewSource(filepath.Join(t.TempDir(), "missing"), "main", gitops.Auth{}, t.TempDir(), nil, nil)
	if _, err := source.Sync(context.Background()); err == nil {
		t.Fatal("expected clone error")
	}
}
