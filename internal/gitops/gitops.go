// Package gitops clones and updates git repositories for Triage.
package gitops

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/plumbing/transport"
	githttp "github.com/go-git/go-git/v5/plumbing/transport/http"
	gitssh "github.com/go-git/go-git/v5/plumbing/transport/ssh"
	"github.com/go-git/go-git/v5/storage/memory"
	"golang.org/x/crypto/ssh/knownhosts"
)

const pushAttempts = 3

// PushError is a push the remote rejected and that retrying will not fix,
// or a non-fast-forward rejection that survived every retry.
type PushError struct {
	Err    error
	Remote string
}

func (e *PushError) Error() string {
	if strings.TrimSpace(e.Remote) == "" {
		return fmt.Sprintf("git push rejected: %v", e.Err)
	}
	return fmt.Sprintf("git push rejected: %v: %s", e.Err, strings.TrimSpace(e.Remote))
}

func (e *PushError) Unwrap() error { return e.Err }

// Spec describes one remote repository.
type Spec struct {
	Name        string
	URL         string
	Branch      string
	Auth        Auth
	AuthorName  string
	AuthorEmail string
}

// Auth holds already-resolved credentials. An empty Auth is anonymous.
type Auth struct {
	Username   string
	Token      string
	PrivateKey []byte
	KnownHosts []byte
}

// Checkout is a local mirror of one repository at a known commit.
type Checkout struct {
	Name   string
	Dir    string
	SHA    string
	Branch string
}

// Snapshot is the local checkout HEAD, without contacting the remote.
type Snapshot struct {
	Cloned bool
	SHA    string
	Branch string
	When   time.Time
}

// Manager keeps shallow clones under Base.
type Manager struct {
	Base       string
	BeforePush func() error

	mu sync.Mutex
}

// Snapshot reads the local checkout for rawURL. A missing clone is not an error.
func (m *Manager) Snapshot(rawURL string) (Snapshot, error) {
	if m == nil || strings.TrimSpace(rawURL) == "" || m.Base == "" {
		return Snapshot{}, nil
	}
	repo, err := git.PlainOpen(filepath.Join(m.Base, dirName(rawURL)))
	if err != nil {
		if errors.Is(err, git.ErrRepositoryNotExists) || os.IsNotExist(err) {
			return Snapshot{}, nil
		}
		return Snapshot{}, err
	}
	return snapshotRepo(repo)
}

// CommitTime returns the author time of sha in the local checkout.
func (m *Manager) CommitTime(rawURL, sha string) (time.Time, bool) {
	if m == nil || strings.TrimSpace(rawURL) == "" || strings.TrimSpace(sha) == "" || m.Base == "" {
		return time.Time{}, false
	}
	repo, err := git.PlainOpen(filepath.Join(m.Base, dirName(rawURL)))
	if err != nil {
		return time.Time{}, false
	}
	commit, err := repo.CommitObject(plumbing.NewHash(sha))
	if err != nil {
		return time.Time{}, false
	}
	return commit.Author.When, true
}

func snapshotRepo(repo *git.Repository) (Snapshot, error) {
	head, err := repo.Head()
	if err != nil {
		return Snapshot{}, err
	}
	commit, err := repo.CommitObject(head.Hash())
	if err != nil {
		return Snapshot{}, err
	}
	branch := ""
	if head.Name().IsBranch() {
		branch = head.Name().Short()
	}
	return Snapshot{Cloned: true, SHA: head.Hash().String(), Branch: branch, When: commit.Author.When}, nil
}

// Pull fetches the remote branch and resets the local checkout to it.
func (m *Manager) Pull(ctx context.Context, spec Spec) (Checkout, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.syncLocked(ctx, spec)
}

// CommitFile fetches the remote, applies mutate to relPath, commits, and pushes.
// A non-fast-forward rejection is retried by reapplying mutate on the new HEAD.
func (m *Manager) CommitFile(ctx context.Context, spec Spec, relPath string, mutate func([]byte) ([]byte, error), message string) (string, error) {
	if strings.TrimSpace(relPath) == "" {
		return "", fmt.Errorf("config file path is required")
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	var last error
	for attempt := 1; attempt <= pushAttempts; attempt++ {
		checkout, err := m.syncLocked(ctx, spec)
		if err != nil {
			return "", err
		}
		full := filepath.Join(checkout.Dir, filepath.Clean(relPath))
		if filepath.IsAbs(relPath) || strings.HasPrefix(filepath.Clean(relPath), "..") {
			return "", fmt.Errorf("config path escapes the repository")
		}
		current, err := os.ReadFile(full)
		if err != nil {
			return "", fmt.Errorf("read %s: %w", relPath, err)
		}
		updated, err := mutate(current)
		if err != nil {
			return "", err
		}
		repo, err := git.PlainOpen(checkout.Dir)
		if err != nil {
			return "", fmt.Errorf("open checkout: %w", err)
		}
		if string(updated) == string(current) {
			return checkout.SHA, nil
		}
		if err := os.WriteFile(full, updated, 0o644); err != nil {
			return "", fmt.Errorf("write %s: %w", relPath, err)
		}
		hash, err := commitWorktree(repo, spec, relPath, message)
		if err != nil {
			return "", err
		}
		if m.BeforePush != nil {
			if err := m.BeforePush(); err != nil {
				return "", err
			}
		}
		auth, err := spec.Auth.transport(m.knownHostsPath(spec))
		if err != nil {
			return "", err
		}
		var progress bytes.Buffer
		err = repo.PushContext(ctx, &git.PushOptions{RemoteName: "origin", Auth: auth, Progress: &progress})
		if err == nil || errors.Is(err, git.NoErrAlreadyUpToDate) {
			return hash, nil
		}
		last = err
		if !isNonFastForward(err) || attempt == pushAttempts {
			return "", &PushError{Err: err, Remote: progress.String()}
		}
	}
	return "", &PushError{Err: last}
}

func (m *Manager) syncLocked(ctx context.Context, spec Spec) (Checkout, error) {
	if strings.TrimSpace(spec.URL) == "" {
		return Checkout{}, fmt.Errorf("git url is required")
	}
	if err := os.MkdirAll(m.Base, 0o750); err != nil {
		return Checkout{}, fmt.Errorf("create checkout dir: %w", err)
	}
	auth, err := spec.Auth.transport(m.knownHostsPath(spec))
	if err != nil {
		return Checkout{}, err
	}
	branch := spec.Branch
	if branch == "" {
		branch, err = defaultBranch(ctx, spec.URL, auth)
		if err != nil {
			return Checkout{}, err
		}
	}
	dir := filepath.Join(m.Base, dirName(spec.URL))
	if _, statErr := os.Stat(filepath.Join(dir, ".git")); statErr != nil {
		if err := os.RemoveAll(dir); err != nil {
			return Checkout{}, err
		}
		_, err = git.PlainCloneContext(ctx, dir, false, &git.CloneOptions{
			URL:           spec.URL,
			Auth:          auth,
			RemoteName:    "origin",
			ReferenceName: plumbing.NewBranchReferenceName(branch),
			SingleBranch:  true,
			Depth:         1,
		})
		if err != nil {
			return Checkout{}, fmt.Errorf("clone %s: %w", spec.URL, err)
		}
	}
	repo, err := git.PlainOpen(dir)
	if err != nil {
		return Checkout{}, fmt.Errorf("open %s: %w", dir, err)
	}
	refSpec := config.RefSpec(fmt.Sprintf("+refs/heads/%s:refs/remotes/origin/%s", branch, branch))
	err = repo.FetchContext(ctx, &git.FetchOptions{
		RemoteName: "origin",
		RefSpecs:   []config.RefSpec{refSpec},
		Auth:       auth,
		Depth:      1,
		Force:      true,
		Tags:       git.NoTags,
	})
	if err != nil && !errors.Is(err, git.NoErrAlreadyUpToDate) {
		return Checkout{}, fmt.Errorf("fetch %s: %w", spec.URL, err)
	}
	remoteRef, err := repo.Reference(plumbing.NewRemoteReferenceName("origin", branch), true)
	if err != nil {
		return Checkout{}, fmt.Errorf("remote branch %s: %w", branch, err)
	}
	worktree, err := repo.Worktree()
	if err != nil {
		return Checkout{}, err
	}
	if err := worktree.Reset(&git.ResetOptions{Commit: remoteRef.Hash(), Mode: git.HardReset}); err != nil {
		return Checkout{}, fmt.Errorf("reset %s: %w", spec.URL, err)
	}
	name := spec.Name
	if name == "" {
		name = nameFromURL(spec.URL)
	}
	return Checkout{Name: name, Dir: dir, SHA: remoteRef.Hash().String(), Branch: branch}, nil
}

func commitWorktree(repo *git.Repository, spec Spec, relPath, message string) (string, error) {
	worktree, err := repo.Worktree()
	if err != nil {
		return "", err
	}
	if _, err := worktree.Add(relPath); err != nil {
		return "", fmt.Errorf("stage %s: %w", relPath, err)
	}
	name := spec.AuthorName
	email := spec.AuthorEmail
	if name == "" {
		name = "suppline-triage"
	}
	if email == "" {
		email = "triage@suppline.local"
	}
	hash, err := worktree.Commit(message, &git.CommitOptions{
		Author: &object.Signature{Name: name, Email: email, When: time.Now().UTC()},
	})
	if err != nil {
		return "", fmt.Errorf("commit: %w", err)
	}
	return hash.String(), nil
}

func (a Auth) transport(knownHostsPath string) (transport.AuthMethod, error) {
	if len(a.PrivateKey) > 0 {
		if len(a.KnownHosts) == 0 {
			return nil, fmt.Errorf("ssh auth requires known_hosts")
		}
		if err := os.WriteFile(knownHostsPath, a.KnownHosts, 0o600); err != nil {
			return nil, fmt.Errorf("write known_hosts: %w", err)
		}
		callback, err := knownhosts.New(knownHostsPath)
		if err != nil {
			return nil, fmt.Errorf("parse known_hosts: %w", err)
		}
		user := a.Username
		if user == "" {
			user = "git"
		}
		keys, err := gitssh.NewPublicKeys(user, a.PrivateKey, "")
		if err != nil {
			return nil, fmt.Errorf("parse ssh private key: %w", err)
		}
		keys.HostKeyCallback = callback
		return keys, nil
	}
	if a.Token != "" {
		user := a.Username
		if user == "" {
			user = "git"
		}
		return &githttp.BasicAuth{Username: user, Password: a.Token}, nil
	}
	return nil, nil
}

func (m *Manager) knownHostsPath(spec Spec) string {
	return filepath.Join(m.Base, "known_hosts_"+dirName(spec.URL))
}

func defaultBranch(ctx context.Context, rawURL string, auth transport.AuthMethod) (string, error) {
	remote := git.NewRemote(memory.NewStorage(), &config.RemoteConfig{
		Name: "origin",
		URLs: []string{rawURL},
	})
	refs, err := remote.ListContext(ctx, &git.ListOptions{Auth: auth})
	if err != nil {
		return "", fmt.Errorf("list remote %s: %w", rawURL, err)
	}
	var headHash plumbing.Hash
	for _, ref := range refs {
		if ref.Name() != plumbing.HEAD {
			continue
		}
		if ref.Type() == plumbing.SymbolicReference && ref.Target() != "" {
			return ref.Target().Short(), nil
		}
		headHash = ref.Hash()
	}
	for _, ref := range refs {
		if ref.Name().IsBranch() && (headHash.IsZero() || ref.Hash() == headHash) {
			return ref.Name().Short(), nil
		}
	}
	return "", fmt.Errorf("remote %s has no default branch", rawURL)
}

func isNonFastForward(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, git.ErrNonFastForwardUpdate) {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "non-fast-forward") || strings.Contains(msg, "non fast-forward")
}

func dirName(rawURL string) string {
	sum := sha256.Sum256([]byte(rawURL))
	return hex.EncodeToString(sum[:10])
}

func nameFromURL(rawURL string) string {
	trimmed := strings.TrimSuffix(rawURL, ".git")
	trimmed = strings.TrimRight(trimmed, "/")
	if i := strings.LastIndex(trimmed, "/"); i >= 0 {
		trimmed = trimmed[i+1:]
	}
	if trimmed == "" {
		return "repo"
	}
	return trimmed
}

// NormalizeSecret turns a single-line env value with escaped newlines into PEM text.
func NormalizeSecret(value string) []byte {
	if !strings.Contains(value, "\n") && strings.Contains(value, `\n`) {
		value = strings.ReplaceAll(value, `\n`, "\n")
	}
	return []byte(value)
}
