package mirror

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/daimoniac/suppline/internal/config"
	"github.com/regclient/regclient/types/ref"
)

type targetNamespace struct {
	registry  string
	namespace string
	wanted    map[string]struct{}
}

func collectWantedTargetNamespaces(syncEntries []config.SyncEntry) (map[string]*targetNamespace, error) {
	out := map[string]*targetNamespace{}
	for _, s := range syncEntries {
		if s.Target == "" {
			continue
		}
		r, err := ref.New(s.Target)
		if err != nil {
			return nil, fmt.Errorf("parse target %q: %w", s.Target, err)
		}
		if r.Scheme != "reg" || r.Repository == "" {
			continue
		}
		nsName, repoName, ok := splitNamespaceRepo(r.Repository)
		if !ok {
			continue
		}
		key := r.Registry + "/" + nsName
		tn, ok := out[key]
		if !ok {
			tn = &targetNamespace{
				registry:  r.Registry,
				namespace: nsName,
				wanted:    map[string]struct{}{},
			}
			out[key] = tn
		}
		tn.wanted[repoName] = struct{}{}
	}
	return out, nil
}

func splitNamespaceRepo(repository string) (namespace, name string, ok bool) {
	parts := strings.Split(repository, "/")
	if len(parts) < 2 {
		return "", "", false
	}
	return parts[0], strings.Join(parts[1:], "/"), true
}

func selectOrphanRepos(present []string, wanted map[string]struct{}, namespace string, excludePatterns []string) ([]string, error) {
	orphans := []string{}
	for _, name := range present {
		if _, ok := wanted[name]; ok {
			continue
		}
		full := namespace + "/" + name
		excluded, _, err := matchesExclusionPattern(name, excludePatterns)
		if err != nil {
			return nil, err
		}
		if !excluded {
			excluded, _, err = matchesExclusionPattern(full, excludePatterns)
			if err != nil {
				return nil, err
			}
		}
		if excluded {
			continue
		}
		orphans = append(orphans, name)
	}
	return orphans, nil
}

func dockerHubCreds(creds []config.RegistryCredential) (user, pass string, err error) {
	for _, cred := range creds {
		switch cred.Registry {
		case "docker.io", "registry-1.docker.io", "https://index.docker.io/v1/", "index.docker.io":
			if cred.User != "" && (cred.Pass != "" || cred.Token != "") {
				pass = cred.Pass
				if pass == "" {
					pass = cred.Token
				}
				return cred.User, pass, nil
			}
		}
	}
	return "", "", fmt.Errorf("no Docker Hub credentials found in config creds for docker.io")
}

func (m *runner) newHubClient() (hubRepoAPI, error) {
	user, pass, err := dockerHubCreds(m.cfg.Creds)
	if err != nil {
		return nil, err
	}
	ua := m.cfg.Defaults.UserAgent
	if ua == "" {
		ua = userAgent
	}
	return newDockerHubClient(user, pass, ua), nil
}

func (m *runner) runCleanupRepos(ctx context.Context) error {
	if m.cfg.Defaults.CleanupRepos == nil || !*m.cfg.Defaults.CleanupRepos {
		m.log.Debug("cleanupRepos disabled")
		return nil
	}
	namespaces, err := collectWantedTargetNamespaces(m.cfg.Sync)
	if err != nil {
		return err
	}
	if len(namespaces) == 0 {
		m.log.Debug("no target namespaces for cleanupRepos")
		return nil
	}

	var errs []error
	for _, tn := range namespaces {
		if err := ctx.Err(); err != nil {
			return err
		}
		if tn.registry != "docker.io" && tn.registry != "registry-1.docker.io" {
			m.log.Warn("cleanupRepos only supports Docker Hub, skipping namespace",
				"registry", tn.registry, "namespace", tn.namespace)
			continue
		}
		hub := m.hub
		if hub == nil {
			var herr error
			hub, herr = m.newHubClient()
			if herr != nil {
				m.log.Error("failed creating Docker Hub client", "error", herr.Error())
				errs = append(errs, herr)
				continue
			}
		}
		if err := m.cleanupReposNamespace(ctx, hub, tn); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (m *runner) cleanupReposNamespace(ctx context.Context, hub hubRepoAPI, tn *targetNamespace) error {
	m.log.Info("running cleanupRepos", "registry", tn.registry, "namespace", tn.namespace, "wanted", len(tn.wanted))
	present, err := hub.listRepositories(ctx, tn.namespace)
	if err != nil {
		return err
	}
	orphans, err := selectOrphanRepos(present, tn.wanted, tn.namespace, m.cfg.Defaults.CleanupReposExclude)
	if err != nil {
		return err
	}
	var errs []error
	for _, name := range orphans {
		if err := ctx.Err(); err != nil {
			return err
		}
		full := tn.namespace + "/" + name
		m.log.Info("deleting repository", "repository", full)
		if err := hub.deleteRepository(ctx, tn.namespace, name); err != nil {
			m.log.Error("failed deleting repository", "repository", full, "error", err.Error())
			errs = append(errs, fmt.Errorf("delete %s: %w", full, err))
		}
	}
	return errors.Join(errs...)
}
