package configedit

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"

	"github.com/daimoniac/suppline/internal/config"
	"github.com/daimoniac/suppline/internal/gitops"
	"github.com/daimoniac/suppline/internal/policy/catalog"
	"github.com/daimoniac/suppline/internal/triage/yamledit"
	"github.com/daimoniac/suppline/internal/types"
)

const editorYAML = `version: 1
sync:
  - source: upstream/app
    target: registry.local/app
    type: repository
    tags:
      semverRange: [">=1.0.0"]
    x-vex:
      - id: CVE-2026-1
        state: not_affected
        justification: code_not_reachable
  - source: upstream/other
    target: registry.local/other
    type: repository
`

type recordingRequeuer struct {
	calls [][]string
}

func (r *recordingRequeuer) RequeueRepositories(_ context.Context, repositories []string) (int, error) {
	r.calls = append(r.calls, append([]string(nil), repositories...))
	return len(repositories), nil
}

type blockingRequeuer struct {
	release chan struct{}
	ctxErr  error
}

func (r *blockingRequeuer) RequeueRepositories(ctx context.Context, repositories []string) (int, error) {
	<-r.release
	r.ctxErr = ctx.Err()
	return len(repositories), nil
}

func localEditor(t *testing.T) (*Editor, string, *catalog.ConfigCatalog, *recordingRequeuer) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "suppline.yml")
	if err := os.WriteFile(path, []byte(editorYAML), 0o644); err != nil {
		t.Fatal(err)
	}
	parsed, err := config.ParseRegsync(path)
	if err != nil {
		t.Fatal(err)
	}
	running := catalog.NewConfigCatalog(parsed)
	requeue := &recordingRequeuer{}
	return New(Target{LocalPath: path, Retention: 2}, running, requeue, nil), path, running, requeue
}

func removeVEX(ids ...string) Change {
	return Change{
		Message: "chore(config): remove unused VEX statements",
		File: func(current []byte) ([]byte, error) {
			next, _, err := yamledit.RemoveVEXStatements(current, ids)
			return next, err
		},
		Running: func(running *catalog.ConfigCatalog) error {
			_, err := running.RemoveVEXIDs(ids)
			return err
		},
	}
}

func setSemver(target string, ranges ...string) Change {
	return Change{
		Message: "chore(config): update semver ranges",
		File: func(current []byte) ([]byte, error) {
			next, _, err := yamledit.SetSemverRanges(current, []yamledit.SemverRangeUpdate{{Target: target, Ranges: ranges}})
			return next, err
		},
		Running: func(running *catalog.ConfigCatalog) error {
			_, err := running.SetSemverRanges(target, ranges)
			return err
		},
	}
}

func TestEditorLocalEditWritesRefreshesAndRequeues(t *testing.T) {
	editor, path, running, requeue := localEditor(t)

	result, err := editor.Apply(context.Background(), removeVEX("CVE-2026-1"))
	if err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	if result.Mode != ModeLocal || result.Commit != "" {
		t.Errorf("result = %+v, want a local write without commit", result)
	}

	body, _ := os.ReadFile(path)
	if strings.Contains(string(body), "CVE-2026-1") {
		t.Errorf("file still holds the removed statement:\n%s", body)
	}
	if _, err := os.Stat(path + ".bak.1"); err != nil {
		t.Errorf("no backup written: %v", err)
	}
	if got := running.ResolveEvidence("registry.local/app").VEXStatements; len(got) != 0 {
		t.Errorf("running evidence = %+v, want none", got)
	}
	// Removing an effective statement changes app's decision, and only app's.
	editor.WaitRequeues()
	if len(requeue.calls) != 1 || strings.Join(requeue.calls[0], ",") != "registry.local/app" {
		t.Errorf("requeued %v, want [[registry.local/app]]", requeue.calls)
	}
	if strings.Join(result.Requeue, ",") != "registry.local/app" {
		t.Errorf("Requeue = %v, want [registry.local/app]", result.Requeue)
	}
}

// A semver range changes what is mirrored, not any policy or VEX decision,
// so nothing is rescanned.
func TestEditorEditWithoutDecisionChangeDoesNotRequeue(t *testing.T) {
	editor, path, running, requeue := localEditor(t)

	if _, err := editor.Apply(context.Background(), setSemver("registry.local/app", ">=2.0.0")); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	body, _ := os.ReadFile(path)
	if !strings.Contains(string(body), ">=2.0.0") {
		t.Errorf("file not updated:\n%s", body)
	}
	if got := running.Current().Sync[0].Tags.SemverRange; len(got) != 1 || got[0] != ">=2.0.0" {
		t.Errorf("running semverRange = %v", got)
	}
	editor.WaitRequeues()
	if len(requeue.calls) != 0 {
		t.Errorf("requeued %v, want nothing", requeue.calls)
	}
}

func TestEditorFailedWriteLeavesRunningConfig(t *testing.T) {
	editor, path, running, requeue := localEditor(t)
	before := running.Current()

	_, err := editor.Apply(context.Background(), setSemver("registry.local/missing", ">=2.0.0"))
	if err == nil {
		t.Fatal("Apply() for an unknown target returned nil error")
	}
	if !errors.Is(err, yamledit.ErrNoMatch) {
		t.Logf("error = %v", err)
	}
	if running.Current() != before {
		t.Error("running configuration changed after a failed write")
	}
	if body, _ := os.ReadFile(path); string(body) != editorYAML {
		t.Errorf("file changed after a failed write:\n%s", body)
	}
	editor.WaitRequeues()
	if len(requeue.calls) != 0 {
		t.Errorf("requeued %v after a failed write", requeue.calls)
	}
}

func TestEditorRefreshFailureReportsWrittenEdit(t *testing.T) {
	editor, path, _, requeue := localEditor(t)
	change := removeVEX("CVE-2026-1")
	change.Running = func(*catalog.ConfigCatalog) error { return errors.New("boom") }

	_, err := editor.Apply(context.Background(), change)
	var refresh *RefreshError
	if !errors.As(err, &refresh) {
		t.Fatalf("Apply() error = %v, want *RefreshError", err)
	}
	if body, _ := os.ReadFile(path); strings.Contains(string(body), "CVE-2026-1") {
		t.Error("file was not written before the refresh failed")
	}
	editor.WaitRequeues()
	if len(requeue.calls) != 0 {
		t.Errorf("requeued %v after a failed refresh", requeue.calls)
	}
}

func TestEditorMode(t *testing.T) {
	if _, err := New(Target{}, nil, nil, nil).Mode(); err == nil {
		t.Error("Mode() without a path returned nil error")
	}
	if _, err := New(Target{LocalPath: filepath.Join(t.TempDir(), "missing", "suppline.yml")}, nil, nil, nil).Mode(); err == nil {
		t.Error("Mode() for an unwritable path returned nil error")
	}
	specErr := errors.New("environment variable GIT_TOKEN is empty")
	if _, err := New(Target{Repo: &RepoTarget{SpecErr: specErr}}, nil, nil, nil).Mode(); !errors.Is(err, specErr) {
		t.Errorf("Mode() = %v, want the spec error", err)
	}
}

func TestEditorGitEditCommitsAndRefreshes(t *testing.T) {
	bare := filepath.Join(t.TempDir(), "bare.git")
	branch := seedConfigRepo(t, bare)
	parsed, err := config.ParseRegsync(writeTemp(t, editorYAML))
	if err != nil {
		t.Fatal(err)
	}
	running := catalog.NewConfigCatalog(parsed)
	requeue := &recordingRequeuer{}
	editor := New(Target{Repo: &RepoTarget{
		Spec:        gitops.Spec{Name: "config", URL: bare, Branch: branch, AuthorName: "suppline", AuthorEmail: "suppline@local"},
		Path:        "suppline.yml",
		CheckoutDir: t.TempDir(),
	}}, running, requeue, nil)

	result, err := editor.Apply(context.Background(), Change{
		Message: "chore(vex): accept CVE-2026-2 for registry.local/other",
		File: func(current []byte) ([]byte, error) {
			return yamledit.UpsertManual(current, "registry.local/other", types.VEXStatement{
				ID: "CVE-2026-2", State: types.VEXStateNotAffected, Justification: types.VEXJustCodeNotReachable,
			})
		},
		Running: func(c *catalog.ConfigCatalog) error {
			return c.UpsertManualVEX("registry.local/other", types.VEXStatement{
				ID: "CVE-2026-2", State: types.VEXStateNotAffected, Justification: types.VEXJustCodeNotReachable,
			})
		},
	})
	if err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	if result.Mode != ModeGit || result.Commit == "" {
		t.Errorf("result = %+v, want a git commit", result)
	}
	if !strings.Contains(headFile(t, bare, "suppline.yml"), "CVE-2026-2") {
		t.Error("commit does not contain the statement")
	}
	editor.WaitRequeues()
	if len(requeue.calls) != 1 || requeue.calls[0][0] != "registry.local/other" {
		t.Errorf("requeued %v, want [[registry.local/other]]", requeue.calls)
	}
}

func writeTemp(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "suppline.yml")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func seedConfigRepo(t *testing.T, bare string) string {
	t.Helper()
	src := t.TempDir()
	repo, err := git.PlainInit(src, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "suppline.yml"), []byte(editorYAML), 0o644); err != nil {
		t.Fatal(err)
	}
	worktree, err := repo.Worktree()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := worktree.Add("suppline.yml"); err != nil {
		t.Fatal(err)
	}
	if _, err := worktree.Commit("init", &git.CommitOptions{Author: &object.Signature{Name: "t", Email: "t@local"}}); err != nil {
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

func headFile(t *testing.T, bare, name string) string {
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

// Removing a sync entry leaves nothing of it to rescan.
func TestEditorSyncRemovalDoesNotRequeueRemovedRepository(t *testing.T) {
	editor, path, running, requeue := localEditor(t)

	if _, err := editor.Apply(context.Background(), Change{
		Message: "chore(config): remove unused sync repositories",
		File: func(current []byte) ([]byte, error) {
			next, _, err := yamledit.RemoveSyncTargets(current, []string{"registry.local/other"})
			return next, err
		},
		Running: func(running *catalog.ConfigCatalog) error {
			_, err := running.RemoveSyncTargets([]string{"registry.local/other"})
			return err
		},
	}); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	if body, _ := os.ReadFile(path); strings.Contains(string(body), "registry.local/other") {
		t.Fatalf("entry not removed:\n%s", body)
	}
	if got := len(running.Current().Sync); got != 1 {
		t.Fatalf("running sync entries = %d, want 1", got)
	}
	editor.WaitRequeues()
	if len(requeue.calls) != 0 {
		t.Errorf("requeued %v, want nothing", requeue.calls)
	}
}

// A full scan queue blocks the requeue. The edit must still return, and the
// caller's context ending must not cancel the requeue.
func TestEditorApplyDoesNotWaitForRequeue(t *testing.T) {
	editor, _, _, _ := localEditor(t)
	blocking := &blockingRequeuer{release: make(chan struct{})}
	editor.requeue = blocking

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := editor.Apply(ctx, removeVEX("CVE-2026-1"))
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Apply() error = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Apply() waited for the requeue")
	}
	cancel()
	close(blocking.release)
	editor.WaitRequeues()
	if blocking.ctxErr != nil {
		t.Errorf("requeue context = %v, want not canceled", blocking.ctxErr)
	}
}
