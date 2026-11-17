// Package configedit changes suppline.yml and the running configuration as one
// step: it writes the file (a commit in the config repository, or the local
// file with backups), applies the same change to the running configuration,
// and requeues the repositories whose policy or VEX decision changed.
package configedit

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"

	"github.com/daimoniac/suppline/internal/gitops"
	"github.com/daimoniac/suppline/internal/policy/catalog"
)

// Modes reported by Editor.Mode.
const (
	ModeGit   = "git"
	ModeLocal = "local"
)

// Target says where edits are written.
type Target struct {
	// LocalPath is the file suppline was started with. It is written when Repo is nil.
	LocalPath string
	// Retention is how many .bak copies a local write keeps.
	Retention int
	// Repo, when set, commits the file to a git repository instead.
	Repo *RepoTarget
}

// RepoTarget is a config file inside a git repository.
type RepoTarget struct {
	Spec        gitops.Spec
	Path        string // file path inside the repository
	CheckoutDir string
	// SpecErr reports why Spec could not be built, such as missing credentials.
	SpecErr error
}

// Requeuer rescans the current images of repositories.
type Requeuer interface {
	RequeueRepositories(ctx context.Context, repositories []string) (int, error)
}

// Change is one edit. File rewrites the YAML document; Running applies the
// same change to the running configuration.
type Change struct {
	Message string
	File    func(current []byte) ([]byte, error)
	Running func(running *catalog.ConfigCatalog) error
}

// Result describes a written edit.
type Result struct {
	Mode   string
	Commit string // empty for a local write
	// Requeue lists the repositories whose decision changed. Their rescans
	// are queued in the background, so a full scan queue does not hold up
	// the edit.
	Requeue []string
}

// RefreshError means the file was written but the running configuration was
// not updated. The edit takes effect when the file is reloaded.
type RefreshError struct {
	Err error
}

func (e *RefreshError) Error() string {
	return fmt.Sprintf("config was written but the running configuration could not be refreshed: %v", e.Err)
}

func (e *RefreshError) Unwrap() error { return e.Err }

// GitManager returns the manager that owns the config repository checkout, or
// nil for local edits. Code that also pulls repositories under the same
// checkout directory should share it, so git work on one directory never overlaps.
func (e *Editor) GitManager() *gitops.Manager {
	if e == nil {
		return nil
	}
	return e.git
}

// Editor applies Changes. Edits run one at a time.
type Editor struct {
	target  Target
	git     *gitops.Manager
	running *catalog.ConfigCatalog
	requeue Requeuer
	log     *slog.Logger
	mu      sync.Mutex
	// requeues tracks background requeues, so tests can wait for them.
	requeues sync.WaitGroup
}

// New creates an Editor. requeue may be nil, for example in tests.
func New(target Target, running *catalog.ConfigCatalog, requeue Requeuer, log *slog.Logger) *Editor {
	if log == nil {
		log = slog.Default()
	}
	e := &Editor{target: target, running: running, requeue: requeue, log: log}
	if target.Repo != nil {
		e.git = &gitops.Manager{Base: target.Repo.CheckoutDir}
	}
	return e
}

// Mode reports where edits are written, or why editing is unavailable.
func (e *Editor) Mode() (string, error) {
	if e == nil {
		return "", errors.New("config editing is unavailable")
	}
	if e.target.Repo != nil {
		if e.target.Repo.SpecErr != nil {
			return "", e.target.Repo.SpecErr
		}
		return ModeGit, nil
	}
	if strings.TrimSpace(e.target.LocalPath) == "" {
		return "", errors.New("suppline config path is not set")
	}
	if err := Writable(e.target.LocalPath); err != nil {
		return "", err
	}
	return ModeLocal, nil
}

// Apply writes change to the file, then to the running configuration, then
// requeues the repositories whose decision changed. A failed write leaves
// everything as it was. A failed refresh returns the Result with a
// *RefreshError. Requeue failures are logged, not returned.
func (e *Editor) Apply(ctx context.Context, change Change) (Result, error) {
	mode, err := e.Mode()
	if err != nil {
		return Result{}, err
	}
	if strings.TrimSpace(change.Message) == "" {
		return Result{}, errors.New("commit message is required")
	}
	if change.File == nil {
		return Result{}, errors.New("config edit has no file change")
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	result := Result{Mode: mode}
	if mode == ModeGit {
		result.Commit, err = e.git.CommitFile(ctx, e.target.Repo.Spec, e.target.Repo.Path, change.File, change.Message)
	} else {
		err = e.writeLocal(change.File)
	}
	if err != nil {
		return Result{}, err
	}

	if e.running == nil || change.Running == nil {
		return result, nil
	}
	before := e.running.Current()
	if err := change.Running(e.running); err != nil {
		e.log.Error("config was written but the running configuration was not refreshed", "mode", mode, "commit", result.Commit, "error", err)
		return result, &RefreshError{Err: err}
	}
	changed := catalog.DecisionChanges(before, e.running.Current())
	if len(changed) == 0 || e.requeue == nil {
		return result, nil
	}
	result.Requeue = changed
	// Enqueue blocks while the scan queue is full. The edit is already
	// written, so the caller (often an HTTP request) must not wait for it,
	// and the request ending must not cancel it.
	requeueCtx := context.WithoutCancel(ctx)
	e.requeues.Add(1)
	go func() {
		defer e.requeues.Done()
		queued, err := e.requeue.RequeueRepositories(requeueCtx, changed)
		if err != nil {
			e.log.Error("config edit requeue incomplete", "repositories", changed, "queued", queued, "error", err)
			return
		}
		e.log.Info("config edit requeued images", "repositories", changed, "queued", queued)
	}()
	return result, nil
}

// WaitRequeues blocks until background requeues started by Apply finish.
func (e *Editor) WaitRequeues() {
	if e != nil {
		e.requeues.Wait()
	}
}

// writeLocal applies mutate to the local file. An unchanged document is not written.
func (e *Editor) writeLocal(mutate func([]byte) ([]byte, error)) error {
	current, err := os.ReadFile(e.target.LocalPath)
	if err != nil {
		return fmt.Errorf("read suppline config: %w", err)
	}
	updated, err := mutate(current)
	if err != nil {
		return err
	}
	if string(updated) == string(current) {
		return nil
	}
	return WriteLocal(e.target.LocalPath, e.target.Retention, updated)
}
