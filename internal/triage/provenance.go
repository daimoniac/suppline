package triage

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

const (
	attestationType      = "attestation-manifest"
	attestationRef       = "vnd.docker.reference.type"
	attestationDigestKey = "vnd.docker.reference.digest"
	inTotoMedia          = "application/vnd.in-toto+json"
)

var tagCommit = regexp.MustCompile(`(?i)(?:^|[^0-9a-f])sha-([0-9a-f]{7,40})(?:[^0-9a-f]|$)`)

// manifestSource reads an upstream image manifest and a blob. Tests substitute it.
type manifestSource interface {
	Manifest(ctx context.Context, ref string) ([]byte, error)
	Blob(ctx context.Context, ref, digest string) ([]byte, error)
}

type ociManifests struct{}

func (ociManifests) Manifest(ctx context.Context, ref string) ([]byte, error) {
	parsed, err := name.ParseReference(ref)
	if err != nil {
		return nil, err
	}
	desc, err := remote.Get(parsed, remote.WithContext(ctx))
	if err != nil {
		return nil, err
	}
	return desc.Manifest, nil
}

func (ociManifests) Blob(ctx context.Context, ref, digest string) ([]byte, error) {
	parsed, err := name.NewDigest(ref + "@" + digest)
	if err != nil {
		return nil, err
	}
	layer, err := remote.Layer(parsed, remote.WithContext(ctx))
	if err != nil {
		return nil, err
	}
	reader, err := layer.Compressed()
	if err != nil {
		reader, err = layer.Uncompressed()
		if err != nil {
			return nil, err
		}
	}
	defer reader.Close()
	return io.ReadAll(io.LimitReader(reader, 4<<20))
}

type commitHit struct {
	Owner string
	Repo  string
	SHA   string
}

// explainImageSource resolves the GitHub revision for the image being triaged.
// OCI labels win. Otherwise the upstream tag's SLSA provenance is read. A unique
// commit search of a -sha- tag is the last fallback.
func explainImageSource(ctx context.Context, images imageLabeler, pub *publicSource, manifests manifestSource, job Job) (string, error) {
	var b strings.Builder
	if images != nil && strings.TrimSpace(job.Repository) != "" && strings.TrimSpace(job.Digest) != "" {
		labels, err := images.ImageLabels(ctx, job.Repository, job.Digest)
		if err != nil {
			fmt.Fprintf(&b, "labels: %s\n", oneLine(err.Error(), 300))
		} else if _, _, _, ok := labeledRevision(labels); ok {
			return formatImageLabels(labels), nil
		} else {
			b.WriteString(formatImageLabels(labels))
		}
	}
	if strings.TrimSpace(job.Upstream) != "" && strings.TrimSpace(job.Tag) != "" {
		if manifests == nil {
			manifests = ociManifests{}
		}
		owner, repo, sha, err := readProvenance(ctx, manifests, job)
		if err == nil {
			fmt.Fprintf(&b, "provenance: https://github.com/%s/%s.git#%s\nowner: %s\nrepo: %s\nrevision: %s\n", owner, repo, sha, owner, repo, sha)
			return b.String(), nil
		}
		fmt.Fprintf(&b, "provenance: %s\n", oneLine(err.Error(), 300))
	}
	if prefix := tagCommitPrefix(job.Tag); prefix != "" && pub != nil {
		hit, ambiguous, err := pub.SearchCommits(ctx, prefix, job.Upstream)
		if err != nil {
			fmt.Fprintf(&b, "commit_search: %s\n", oneLine(err.Error(), 300))
		} else if hit.Repo != "" {
			fmt.Fprintf(&b, "commit_search: %s/%s@%s\nowner: %s\nrepo: %s\nrevision: %s\n", hit.Owner, hit.Repo, hit.SHA, hit.Owner, hit.Repo, hit.SHA)
			return b.String(), nil
		} else if len(ambiguous) > 0 {
			fmt.Fprintf(&b, "commit_search: ambiguous\ncandidates: %s\n", strings.Join(ambiguous, ", "))
		}
	}
	if b.Len() == 0 {
		return "", fmt.Errorf("image source is unavailable")
	}
	return b.String(), nil
}

func labeledRevision(labels map[string]string) (owner, repo, rev string, ok bool) {
	owner, repo, ok = parseGitHubSource(labels[ociImageSource])
	rev = strings.TrimSpace(labels[ociImageRevision])
	if !ok || rev == "" {
		return "", "", "", false
	}
	return owner, repo, rev, true
}

func tagCommitPrefix(tag string) string {
	match := tagCommit.FindStringSubmatch(tag)
	if match == nil {
		return ""
	}
	return strings.ToLower(match[1])
}

func readProvenance(ctx context.Context, manifests manifestSource, job Job) (owner, repo, sha string, err error) {
	source := strings.TrimSpace(job.Upstream)
	index, err := manifests.Manifest(ctx, source+":"+strings.TrimSpace(job.Tag))
	if err != nil {
		return "", "", "", err
	}
	attestDigest, err := attestationPointer(index, job.Platform, job.Digest)
	if err != nil {
		return "", "", "", err
	}
	attest, err := manifests.Manifest(ctx, source+"@"+attestDigest)
	if err != nil {
		return "", "", "", err
	}
	layer, err := attestationStatementDigest(attest)
	if err != nil {
		return "", "", "", err
	}
	statement, err := manifests.Blob(ctx, source, layer)
	if err != nil {
		return "", "", "", err
	}
	uri, err := parseConfigSourceURI(statement)
	if err != nil {
		return "", "", "", err
	}
	owner, repo, sha, ok := parseGitHubRevisionURI(uri)
	if !ok {
		return "", "", "", fmt.Errorf("provenance source is not a GitHub commit")
	}
	return owner, repo, sha, nil
}

type ociDescriptor struct {
	Digest      string            `json:"digest"`
	MediaType   string            `json:"mediaType"`
	Annotations map[string]string `json:"annotations"`
	Platform    struct {
		OS           string `json:"os"`
		Architecture string `json:"architecture"`
	} `json:"platform"`
	Layers    []ociDescriptor `json:"layers"`
	Manifests []ociDescriptor `json:"manifests"`
}

// attestationPointer returns the attestation manifest digest for the selected platform.
func attestationPointer(index []byte, platform, imageDigest string) (string, error) {
	var doc ociDescriptor
	if err := json.Unmarshal(index, &doc); err != nil {
		return "", fmt.Errorf("decode image index: %w", err)
	}
	osName, arch := splitPlatform(platform)
	imageDigest = strings.TrimSpace(imageDigest)
	chosen := ""
	matches := 0
	exact := false
	for _, manifest := range doc.Manifests {
		if manifest.Platform.OS != osName || manifest.Platform.Architecture != arch {
			continue
		}
		matches++
		if imageDigest != "" && manifest.Digest == imageDigest {
			chosen = manifest.Digest
			exact = true
			break
		}
		if chosen == "" {
			chosen = manifest.Digest
		}
	}
	if chosen == "" {
		return "", fmt.Errorf("no %s/%s manifest in the upstream index", osName, arch)
	}
	if matches > 1 && !exact {
		return "", fmt.Errorf("upstream index has more than one %s/%s manifest", osName, arch)
	}
	for _, manifest := range doc.Manifests {
		if manifest.Annotations[attestationRef] != attestationType {
			continue
		}
		if manifest.Annotations[attestationDigestKey] == chosen {
			return manifest.Digest, nil
		}
	}
	return "", fmt.Errorf("upstream index has no provenance attestation")
}

func attestationStatementDigest(manifest []byte) (string, error) {
	var doc ociDescriptor
	if err := json.Unmarshal(manifest, &doc); err != nil {
		return "", fmt.Errorf("decode attestation manifest: %w", err)
	}
	for _, layer := range doc.Layers {
		if layer.MediaType == inTotoMedia || strings.Contains(layer.Annotations["in-toto.io/predicate-type"], "slsa.dev/provenance") {
			if layer.Digest != "" {
				return layer.Digest, nil
			}
		}
	}
	return "", fmt.Errorf("attestation manifest has no provenance layer")
}

func splitPlatform(platform string) (string, string) {
	platform = strings.TrimSpace(platform)
	if platform == "" {
		return "linux", "amd64"
	}
	osName, arch, _ := strings.Cut(platform, "/")
	if osName == "" {
		osName = "linux"
	}
	if arch == "" {
		arch = "amd64"
	}
	return osName, arch
}

func parseConfigSourceURI(doc []byte) (string, error) {
	var root any
	if err := json.Unmarshal(doc, &root); err != nil {
		return "", fmt.Errorf("decode provenance: %w", err)
	}
	if uri := findConfigSource(root); uri != "" {
		return uri, nil
	}
	return "", fmt.Errorf("provenance has no configSource")
}

func findConfigSource(node any) string {
	switch value := node.(type) {
	case map[string]any:
		if raw, ok := value["configSource"]; ok {
			if source, ok := raw.(map[string]any); ok {
				if uri, ok := source["uri"].(string); ok && strings.TrimSpace(uri) != "" {
					return uri
				}
			}
		}
		for _, child := range value {
			if uri := findConfigSource(child); uri != "" {
				return uri
			}
		}
	case []any:
		for _, child := range value {
			if uri := findConfigSource(child); uri != "" {
				return uri
			}
		}
	}
	return ""
}

func parseGitHubRevisionURI(raw string) (owner, repo, sha string, ok bool) {
	base, frag, found := strings.Cut(strings.TrimSpace(raw), "#")
	if !found {
		return "", "", "", false
	}
	owner, repo, ok = parseGitHubSource(base)
	if !ok || !fullCommit.MatchString(frag) {
		return "", "", "", false
	}
	return owner, repo, strings.ToLower(frag), true
}

// SearchCommits looks up a commit prefix. One repository is returned. Several
// repositories stay unresolved unless exactly one lines up with the catalog source.
func (p *publicSource) SearchCommits(ctx context.Context, prefix, sourceHint string) (commitHit, []string, error) {
	if p == nil {
		p = newPublicSource()
	}
	prefix = strings.ToLower(strings.TrimSpace(prefix))
	if prefix == "" {
		return commitHit{}, nil, fmt.Errorf("commit prefix is empty")
	}
	if githubToken() == "" {
		return commitHit{}, nil, fmt.Errorf("commit search requires SUPPLINE_GITHUB_TOKEN or GITHUB_TOKEN")
	}
	rawURL := strings.TrimRight(p.github, "/") + "/search/commits?per_page=10&q=" + url.QueryEscape("hash:"+prefix)
	body, status, err := p.getAccept(ctx, rawURL, "application/vnd.github+json")
	if err != nil {
		return commitHit{}, nil, err
	}
	if status != 200 {
		return commitHit{}, nil, fmt.Errorf("commit search status %d", status)
	}
	var payload struct {
		Items []struct {
			SHA        string `json:"sha"`
			Repository struct {
				FullName string `json:"full_name"`
			} `json:"repository"`
		} `json:"items"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return commitHit{}, nil, fmt.Errorf("decode commit search: %w", err)
	}
	byRepo := map[string]commitHit{}
	for _, item := range payload.Items {
		if !strings.HasPrefix(strings.ToLower(item.SHA), prefix) || !fullCommit.MatchString(item.SHA) {
			continue
		}
		owner, repo, ok := strings.Cut(item.Repository.FullName, "/")
		if !ok || owner == "" || repo == "" {
			continue
		}
		byRepo[item.Repository.FullName] = commitHit{Owner: owner, Repo: repo, SHA: strings.ToLower(item.SHA)}
	}
	if len(byRepo) == 0 {
		return commitHit{}, nil, fmt.Errorf("commit %s was not found", prefix)
	}
	if len(byRepo) == 1 {
		for _, hit := range byRepo {
			return hit, nil, nil
		}
	}
	var lined []commitHit
	var names []string
	for name, hit := range byRepo {
		names = append(names, name)
		if sourceLinesUp(name, sourceHint) {
			lined = append(lined, hit)
		}
	}
	sort.Strings(names)
	if len(lined) == 1 {
		return lined[0], nil, nil
	}
	return commitHit{}, names, nil
}

func sourceLinesUp(fullName, source string) bool {
	owner, repo, ok := strings.Cut(fullName, "/")
	if !ok {
		return false
	}
	hintOwner, hintName := imageNameParts(source)
	if hintOwner == "" || hintName == "" {
		return false
	}
	owner, repo = strings.ToLower(owner), strings.ToLower(repo)
	hintOwner, hintName = strings.ToLower(hintOwner), strings.ToLower(hintName)
	if owner != hintOwner {
		return false
	}
	return repo == hintName || strings.Contains(repo, hintName) || strings.Contains(hintName, repo)
}

func imageNameParts(source string) (owner, name string) {
	source = strings.TrimSpace(source)
	source = strings.TrimPrefix(source, "https://")
	source = strings.TrimPrefix(source, "http://")
	parts := strings.Split(strings.Trim(source, "/"), "/")
	if len(parts) >= 2 && strings.Contains(parts[0], ".") {
		parts = parts[1:]
	}
	if len(parts) < 2 {
		return "", ""
	}
	return parts[0], parts[len(parts)-1]
}
