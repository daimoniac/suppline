package triage

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

const maxDependencyCheckouts = 5

type lockedPackage struct {
	Name    string
	Version string
}

// dependencySources reads the image commit's npm lockfile and checks out the
// vulnerable package's direct dependents. The package name comes from the job.
func dependencySources(ctx context.Context, roots *Roots, upstream *publicCheckouts, pub *publicSource, job Job, owner, repo, ref string) (string, error) {
	if kernelPackage(job.PackageName) {
		return fmt.Sprintf("package %s is a kernel package; lockfile lookup does not apply\n", job.PackageName), nil
	}
	pkg := strings.TrimSpace(job.PackageName)
	if pkg == "" {
		return "", fmt.Errorf("package name is empty")
	}
	if strings.TrimSpace(owner) == "" || strings.TrimSpace(repo) == "" || strings.TrimSpace(ref) == "" {
		return "", fmt.Errorf("owner, git_repo, and ref are required")
	}
	if pub == nil {
		pub = newPublicSource()
	}
	sha, err := pub.resolveCommit(ctx, owner, repo, ref)
	if err != nil {
		return "", err
	}
	dependents, fact, err := lockfileDependents(ctx, pub, owner, repo, sha, pkg)
	if err != nil {
		return "", err
	}
	if fact != "" {
		return fact, nil
	}
	if len(dependents) == 0 {
		return "no external dependents\n", nil
	}
	if len(dependents) > maxDependencyCheckouts {
		return fmt.Sprintf("too many direct dependents (%d); stayed under the cap of %d\n", len(dependents), maxDependencyCheckouts), nil
	}
	var b strings.Builder
	for _, dep := range dependents {
		meta, err := pub.npmPackage(ctx, dep.Name, dep.Version)
		if err != nil {
			return fmt.Sprintf("dependent %s@%s has no GitHub repository: %s\n", dep.Name, dep.Version, err.Error()), nil
		}
		path := meta.directory
		if path == "" {
			path = "."
		}
		revision := meta.gitHead
		if revision == "" {
			revision = dep.Version
		}
		if upstream == nil {
			return "", fmt.Errorf("public checkout is unavailable")
		}
		out, err := upstream.Checkout(ctx, roots, meta.owner, meta.repo, revision, path)
		if err != nil {
			return fmt.Sprintf("dependent %s@%s checkout failed: %s\n", dep.Name, dep.Version, err.Error()), nil
		}
		fmt.Fprintf(&b, "%s@%s\n%s", dep.Name, dep.Version, out)
	}
	return b.String(), nil
}

func lockfileDependents(ctx context.Context, pub *publicSource, owner, repo, sha, pkg string) ([]lockedPackage, string, error) {
	pnpm, pnpmErr := pub.githubRaw(ctx, owner, repo, sha, "pnpm-lock.yaml")
	if pnpmErr == nil {
		deps, err := pnpmDependents(pnpm, pkg)
		if err != nil {
			return nil, "unrecognized lockfile\n", nil
		}
		return deps, "", nil
	}
	npm, npmErr := pub.githubRaw(ctx, owner, repo, sha, "package-lock.json")
	if npmErr == nil {
		deps, err := npmDependents(npm, pkg)
		if err != nil {
			return nil, "unrecognized lockfile\n", nil
		}
		return deps, "", nil
	}
	if pnpmErr != nil && npmErr != nil {
		return nil, fmt.Sprintf("no pnpm-lock.yaml or package-lock.json at %s\n", sha), nil
	}
	return nil, "", nil
}

func pnpmDependents(data []byte, pkg string) ([]lockedPackage, error) {
	var doc map[string]any
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	found := map[string]lockedPackage{}
	walkPnpm(doc, pkg, found)
	return sortedLocked(found), nil
}

func walkPnpm(node any, pkg string, found map[string]lockedPackage) {
	switch value := node.(type) {
	case map[string]any:
		for key, child := range value {
			if deps, ok := child.(map[string]any); ok {
				if dependsOn(deps, pkg) {
					if name, version, ok := pnpmPackageKey(key); ok && name != pkg {
						found[name] = lockedPackage{Name: name, Version: version}
					}
				}
			}
			walkPnpm(child, pkg, found)
		}
	case []any:
		for _, child := range value {
			walkPnpm(child, pkg, found)
		}
	}
}

func dependsOn(node map[string]any, pkg string) bool {
	for _, key := range []string{"dependencies", "optionalDependencies", "devDependencies"} {
		raw, ok := node[key]
		if !ok {
			continue
		}
		deps, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		if _, ok := deps[pkg]; ok {
			return true
		}
	}
	return false
}

func pnpmPackageKey(key string) (name, version string, ok bool) {
	key = strings.TrimPrefix(strings.TrimSpace(key), "/")
	if cut := strings.IndexByte(key, '('); cut >= 0 {
		key = key[:cut]
	}
	at := strings.LastIndex(key, "@")
	if at <= 0 {
		return "", "", false
	}
	name, version = key[:at], key[at+1:]
	if name == "" || version == "" || strings.Contains(name, "/") && !strings.HasPrefix(name, "@") {
		return "", "", false
	}
	return name, version, true
}

func npmDependents(data []byte, pkg string) ([]lockedPackage, error) {
	var doc struct {
		Packages map[string]struct {
			Version      string            `json:"version"`
			Dependencies map[string]string `json:"dependencies"`
			Optional     map[string]string `json:"optionalDependencies"`
			Dev          map[string]string `json:"devDependencies"`
		} `json:"packages"`
	}
	if err := json.Unmarshal(data, &doc); err != nil || doc.Packages == nil {
		return nil, fmt.Errorf("unrecognized package-lock.json")
	}
	found := map[string]lockedPackage{}
	for path, meta := range doc.Packages {
		if _, ok := meta.Dependencies[pkg]; !ok {
			if _, ok = meta.Optional[pkg]; !ok {
				if _, ok = meta.Dev[pkg]; !ok {
					continue
				}
			}
		}
		name := npmPathName(path)
		if name == "" || name == pkg {
			continue
		}
		version := meta.Version
		if version == "" {
			continue
		}
		found[name] = lockedPackage{Name: name, Version: version}
	}
	return sortedLocked(found), nil
}

func npmPathName(path string) string {
	path = strings.Trim(path, "/")
	if path == "" {
		return ""
	}
	parts := strings.Split(path, "/")
	for i := len(parts) - 1; i >= 0; i-- {
		if parts[i] == "node_modules" && i+1 < len(parts) {
			if strings.HasPrefix(parts[i+1], "@") && i+2 < len(parts) {
				return parts[i+1] + "/" + parts[i+2]
			}
			return parts[i+1]
		}
	}
	return ""
}

func sortedLocked(found map[string]lockedPackage) []lockedPackage {
	names := make([]string, 0, len(found))
	for name := range found {
		names = append(names, name)
	}
	sort.Strings(names)
	out := make([]lockedPackage, 0, len(names))
	for _, name := range names {
		out = append(out, found[name])
	}
	return out
}

type npmMeta struct {
	owner     string
	repo      string
	directory string
	gitHead   string
}

func (p *publicSource) githubRaw(ctx context.Context, owner, repo, ref, path string) ([]byte, error) {
	if p == nil {
		p = newPublicSource()
	}
	base := p.raw
	if base == "" {
		base = "https://raw.githubusercontent.com"
	}
	rawURL := strings.TrimRight(base, "/") + "/" + url.PathEscape(owner) + "/" + url.PathEscape(repo) + "/" + url.PathEscape(ref) + "/" + pathEscapeSlash(path)
	body, status, err := p.getAcceptLimit(ctx, rawURL, "application/octet-stream", 8<<20)
	if err != nil {
		return nil, err
	}
	if status == 404 {
		return nil, fmt.Errorf("file %s was not found", path)
	}
	if status != 200 {
		return nil, fmt.Errorf("file %s status %d", path, status)
	}
	return body, nil
}

func (p *publicSource) npmPackage(ctx context.Context, name, version string) (npmMeta, error) {
	if p == nil {
		p = newPublicSource()
	}
	base := p.npm
	if base == "" {
		base = "https://registry.npmjs.org"
	}
	version = strings.TrimSpace(version)
	if cut := strings.IndexByte(version, '('); cut >= 0 {
		version = version[:cut]
	}
	rawURL := strings.TrimRight(base, "/") + "/" + url.PathEscape(name) + "/" + url.PathEscape(version)
	body, status, err := p.getAccept(ctx, rawURL, "application/json")
	if err != nil {
		return npmMeta{}, err
	}
	if status != 200 {
		return npmMeta{}, fmt.Errorf("npm registry status %d", status)
	}
	var doc struct {
		GitHead    string `json:"gitHead"`
		Repository any    `json:"repository"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return npmMeta{}, fmt.Errorf("decode npm package: %w", err)
	}
	repoURL, directory := npmRepository(doc.Repository)
	owner, repo, ok := parseGitHubSource(normalizeRepoURL(repoURL))
	if !ok {
		return npmMeta{}, fmt.Errorf("npm package %s has no GitHub repository", name)
	}
	head := strings.TrimSpace(doc.GitHead)
	if head != "" && !fullCommit.MatchString(head) {
		head = ""
	}
	return npmMeta{owner: owner, repo: repo, directory: strings.Trim(directory, "/"), gitHead: strings.ToLower(head)}, nil
}

func normalizeRepoURL(raw string) string {
	raw = strings.TrimSpace(raw)
	raw = strings.TrimPrefix(raw, "git+")
	if rest, ok := strings.CutPrefix(raw, "github:"); ok {
		return "https://github.com/" + rest
	}
	return raw
}

func npmRepository(raw any) (repoURL, directory string) {
	switch value := raw.(type) {
	case string:
		return value, ""
	case map[string]any:
		urlValue, _ := value["url"].(string)
		directory, _ = value["directory"].(string)
		return urlValue, directory
	default:
		return "", ""
	}
}

func kernelPackage(name string) bool {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "linux", "linux-libc-dev", "linux-headers", "kernel":
		return true
	default:
		return false
	}
}
