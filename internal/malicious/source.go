package malicious

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-git/go-git/v5"
	gitconfig "github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/plumbing/transport"

	"github.com/daimoniac/suppline/internal/gitops"
)

const maliciousRoot = "osv/malicious"

// Source keeps a shallow, bare clone of the malicious-packages repository and
// reads OSV entries straight from git objects, without a worktree.
type Source struct {
	url        string
	ref        string
	auth       gitops.Auth
	dir        string
	ecosystems map[string]bool
	logger     *slog.Logger
}

// SyncResult says what a sync changed.
type SyncResult struct {
	// Previous is the commit indexed before this sync; zero after a fresh clone.
	Previous plumbing.Hash
	// Current is the commit now at the tip of the tracked branch.
	Current plumbing.Hash
}

// NewSource creates a source that clones url@ref into dir.
func NewSource(url, ref string, auth gitops.Auth, dir string, ecosystems []string, logger *slog.Logger) *Source {
	if ref == "" {
		ref = "main"
	}
	if len(ecosystems) == 0 {
		ecosystems = DefaultEcosystems
	}
	allowed := make(map[string]bool, len(ecosystems))
	for _, ecosystem := range ecosystems {
		allowed[ecosystem] = true
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Source{url: url, ref: ref, auth: auth, dir: dir, ecosystems: allowed, logger: logger}
}

func (s *Source) repoDir() string { return filepath.Join(s.dir, "repo.git") }

func (s *Source) remoteRef() plumbing.ReferenceName {
	return plumbing.NewRemoteReferenceName("origin", s.ref)
}

func (s *Source) transport() (transport.AuthMethod, error) {
	if err := os.MkdirAll(s.dir, 0o750); err != nil {
		return nil, fmt.Errorf("create malicious-packages dir: %w", err)
	}
	return s.auth.Transport(filepath.Join(s.dir, "known_hosts"))
}

// Sync fetches the tracked branch, cloning first when there is no usable
// clone. A fetch that fails on the existing clone (go-git shallow fetches do
// break now and then) is answered by cloning again; Previous is then zero.
func (s *Source) Sync(ctx context.Context) (SyncResult, error) {
	auth, err := s.transport()
	if err != nil {
		return SyncResult{}, err
	}
	repo, err := git.PlainOpen(s.repoDir())
	if err != nil {
		return s.clone(ctx, auth)
	}
	previous, err := s.tip(repo)
	if err != nil {
		s.logger.Warn("malicious-packages clone has no tip, cloning again", "error", err)
		return s.clone(ctx, auth)
	}
	if err := s.fetch(ctx, repo, auth); err != nil {
		if ctx.Err() != nil {
			return SyncResult{}, ctx.Err()
		}
		s.logger.Warn("malicious-packages fetch failed, cloning again", "error", err)
		return s.clone(ctx, auth)
	}
	current, err := s.tip(repo)
	if err != nil {
		return SyncResult{}, err
	}
	return SyncResult{Previous: previous, Current: current}, nil
}

func (s *Source) clone(ctx context.Context, auth transport.AuthMethod) (SyncResult, error) {
	if err := os.RemoveAll(s.repoDir()); err != nil {
		return SyncResult{}, fmt.Errorf("remove old clone: %w", err)
	}
	repo, err := git.PlainInitWithOptions(s.repoDir(), &git.PlainInitOptions{Bare: true})
	if err != nil {
		return SyncResult{}, fmt.Errorf("init clone: %w", err)
	}
	if _, err := repo.CreateRemote(&gitconfig.RemoteConfig{Name: "origin", URLs: []string{s.url}}); err != nil {
		return SyncResult{}, fmt.Errorf("add remote: %w", err)
	}
	if err := s.fetch(ctx, repo, auth); err != nil {
		_ = os.RemoveAll(s.repoDir())
		return SyncResult{}, fmt.Errorf("clone %s: %w", s.url, err)
	}
	current, err := s.tip(repo)
	if err != nil {
		return SyncResult{}, err
	}
	return SyncResult{Current: current}, nil
}

func (s *Source) fetch(ctx context.Context, repo *git.Repository, auth transport.AuthMethod) error {
	refSpec := gitconfig.RefSpec(fmt.Sprintf("+refs/heads/%s:%s", s.ref, s.remoteRef()))
	err := repo.FetchContext(ctx, &git.FetchOptions{
		RemoteName: "origin",
		RefSpecs:   []gitconfig.RefSpec{refSpec},
		Auth:       auth,
		Depth:      1,
		Force:      true,
		Tags:       git.NoTags,
	})
	if err != nil && !errors.Is(err, git.NoErrAlreadyUpToDate) {
		return fmt.Errorf("fetch %s: %w", s.url, err)
	}
	return nil
}

func (s *Source) tip(repo *git.Repository) (plumbing.Hash, error) {
	ref, err := repo.Reference(s.remoteRef(), true)
	if err != nil {
		return plumbing.ZeroHash, fmt.Errorf("branch %s: %w", s.ref, err)
	}
	return ref.Hash(), nil
}

func (s *Source) open() (*git.Repository, error) {
	repo, err := git.PlainOpen(s.repoDir())
	if err != nil {
		return nil, fmt.Errorf("open malicious-packages clone: %w", err)
	}
	return repo, nil
}

func commitTree(repo *git.Repository, commit plumbing.Hash) (*object.Tree, error) {
	c, err := repo.CommitObject(commit)
	if err != nil {
		return nil, fmt.Errorf("commit %s: %w", commit, err)
	}
	tree, err := c.Tree()
	if err != nil {
		return nil, fmt.Errorf("tree of %s: %w", commit, err)
	}
	return tree, nil
}

// LoadAll reads every entry of the configured ecosystems at commit, keyed by
// repository path. Records that fail to parse are skipped and logged.
func (s *Source) LoadAll(ctx context.Context, commit plumbing.Hash) (map[string]*Entry, error) {
	repo, err := s.open()
	if err != nil {
		return nil, err
	}
	root, err := commitTree(repo, commit)
	if err != nil {
		return nil, err
	}
	entries := make(map[string]*Entry)
	skipped := 0
	for ecosystem := range s.ecosystems {
		prefix := maliciousRoot + "/" + ecosystemDir(ecosystem)
		sub, err := root.Tree(prefix)
		if errors.Is(err, object.ErrDirectoryNotFound) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", prefix, err)
		}
		err = sub.Files().ForEach(func(file *object.File) error {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if !strings.HasSuffix(file.Name, ".json") {
				return nil
			}
			path := prefix + "/" + file.Name
			entry, err := readEntry(file.Reader)
			if err != nil {
				skipped++
				s.logger.Debug("skipping malicious-packages record", "path", path, "error", err)
				return nil
			}
			entries[path] = entry
			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("walk %s: %w", prefix, err)
		}
	}
	if skipped > 0 {
		s.logger.Warn("skipped unreadable malicious-packages records", "count", skipped)
	}
	return entries, nil
}

// Diff returns the entries added or modified between two commits, and the
// paths removed (which is how upstream withdraws an entry). Only paths of the
// configured ecosystems are reported.
func (s *Source) Diff(ctx context.Context, from, to plumbing.Hash) (map[string]*Entry, []string, error) {
	repo, err := s.open()
	if err != nil {
		return nil, nil, err
	}
	fromTree, err := commitTree(repo, from)
	if err != nil {
		return nil, nil, err
	}
	toTree, err := commitTree(repo, to)
	if err != nil {
		return nil, nil, err
	}
	changes, err := object.DiffTreeWithOptions(ctx, fromTree, toTree, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("diff %s..%s: %w", from, to, err)
	}
	changed := make(map[string]*Entry)
	var removed []string
	for _, change := range changes {
		if change.From.Name != "" && s.tracked(change.From.Name) && change.To.Name != change.From.Name {
			removed = append(removed, change.From.Name)
		}
		if change.To.Name == "" || !s.tracked(change.To.Name) {
			continue
		}
		blob, err := repo.BlobObject(change.To.TreeEntry.Hash)
		if err != nil {
			return nil, nil, fmt.Errorf("blob %s: %w", change.To.Name, err)
		}
		entry, err := readEntry(blob.Reader)
		if err != nil {
			s.logger.Debug("skipping malicious-packages record", "path", change.To.Name, "error", err)
			continue
		}
		changed[change.To.Name] = entry
	}
	return changed, removed, nil
}

func (s *Source) tracked(path string) bool {
	if !strings.HasSuffix(path, ".json") {
		return false
	}
	rest, ok := strings.CutPrefix(path, maliciousRoot+"/")
	if !ok {
		return false
	}
	dir, _, _ := strings.Cut(rest, "/")
	for ecosystem := range s.ecosystems {
		if ecosystemDir(ecosystem) == dir {
			return true
		}
	}
	return false
}

func readEntry(open func() (io.ReadCloser, error)) (*Entry, error) {
	reader, err := open()
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, err
	}
	return ParseEntry(data)
}
