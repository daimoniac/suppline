package registry

import (
	"context"
	"fmt"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/suppline/suppline/internal/config"
	"github.com/suppline/suppline/internal/errors"
)

// Client defines the interface for interacting with container registries
type Client interface {
	// ListRepositories returns all repositories in the registry
	ListRepositories(ctx context.Context) ([]string, error)

	// ListTags returns all tags for a repository
	ListTags(ctx context.Context, repo string) ([]string, error)

	// GetDigest returns the digest for a specific tag
	GetDigest(ctx context.Context, repo, tag string) (string, error)

	// GetManifest retrieves image manifest by digest
	GetManifest(ctx context.Context, repo, digest string) (*Manifest, error)
}

// Manifest represents a container image manifest
type Manifest struct {
	Digest       string
	MediaType    string
	Config       ConfigDescriptor
	Layers       []LayerDescriptor
	Annotations  map[string]string
	Architecture string
	OS           string
}

// ConfigDescriptor describes the image config
type ConfigDescriptor struct {
	Digest    string
	MediaType string
	Size      int64
}

// LayerDescriptor describes an image layer
type LayerDescriptor struct {
	Digest    string
	MediaType string
	Size      int64
}

// clientImpl implements the Client interface using go-containerregistry
type clientImpl struct {
	regsyncConfig *config.RegsyncConfig
	authConfig    map[string]authn.Authenticator
	remoteOpts    []remote.Option
}

// NewClient creates a new registry client configured with credentials from regsync config
func NewClient(regsyncConfig *config.RegsyncConfig) (Client, error) {
	if regsyncConfig == nil {
		return nil, errors.NewPermanent(fmt.Errorf("regsync config is required"))
	}

	client := &clientImpl{
		regsyncConfig: regsyncConfig,
		authConfig:    make(map[string]authn.Authenticator),
		remoteOpts:    []remote.Option{},
	}

	// Configure authentication for each registry
	for _, cred := range regsyncConfig.Creds {
		if cred.User != "" && cred.Pass != "" {
			client.authConfig[cred.Registry] = &authn.Basic{
				Username: cred.User,
				Password: cred.Pass,
			}
		}
	}

	return client, nil
}

// normalizeRegistry normalizes registry names to handle Docker Hub aliases
func normalizeRegistry(registry string) []string {
	// Docker Hub has multiple aliases that should be treated as the same
	if registry == "index.docker.io" || registry == "docker.io" || registry == "registry-1.docker.io" {
		return []string{"index.docker.io", "docker.io", "registry-1.docker.io"}
	}
	return []string{registry}
}

// getAuthForRegistry returns the authenticator for a specific registry
func (c *clientImpl) getAuthForRegistry(registry string) authn.Authenticator {
	// Try all normalized registry names
	for _, normalizedReg := range normalizeRegistry(registry) {
		if auth, ok := c.authConfig[normalizedReg]; ok {
			return auth
		}
	}
	return authn.Anonymous
}

// parseImageRef parses a repository string into registry and repository components
func parseImageRef(repo string) (registry, repository string, err error) {
	// Handle different formats:
	// - "docker.io/library/nginx" -> registry: docker.io, repo: library/nginx
	// - "gcr.io/project/image" -> registry: gcr.io, repo: project/image
	// - "myregistry.com:5000/org/image" -> registry: myregistry.com:5000, repo: org/image
	// - "nginx" -> registry: docker.io, repo: library/nginx (default)

	parts := strings.SplitN(repo, "/", 2)
	
	// Check if first part looks like a registry (contains . or :)
	if len(parts) == 2 && (strings.Contains(parts[0], ".") || strings.Contains(parts[0], ":")) {
		registry = parts[0]
		repository = parts[1]
	} else {
		// Default to Docker Hub
		registry = "docker.io"
		if len(parts) == 1 {
			// Single name like "nginx" -> "library/nginx"
			repository = "library/" + parts[0]
		} else {
			repository = repo
		}
	}

	return registry, repository, nil
}

// ListRepositories returns all repositories in the registry
// Note: This implementation focuses on target repositories from regsync config
// as full registry enumeration is not always supported by all registries
func (c *clientImpl) ListRepositories(ctx context.Context) ([]string, error) {
	// Return target repositories from regsync config
	// Full registry catalog enumeration is registry-specific and not always available
	targets := c.regsyncConfig.GetTargetRepositories()
	if len(targets) == 0 {
		return nil, errors.NewPermanent(fmt.Errorf("no target repositories configured in regsync"))
	}
	return targets, nil
}

// ListTags returns all tags for a repository
func (c *clientImpl) ListTags(ctx context.Context, repo string) ([]string, error) {
	registry, repository, err := parseImageRef(repo)
	if err != nil {
		return nil, errors.NewPermanent(fmt.Errorf("failed to parse repository: %w", err))
	}

	// Construct repository reference
	repoRef := fmt.Sprintf("%s/%s", registry, repository)
	ref, err := name.NewRepository(repoRef)
	if err != nil {
		return nil, errors.NewPermanent(fmt.Errorf("failed to create repository reference: %w", err))
	}

	// Get authenticator for this registry
	auth := c.getAuthForRegistry(registry)

	// List tags
	tags, err := remote.List(ref, remote.WithAuth(auth), remote.WithContext(ctx))
	if err != nil {
		// Network/registry errors are typically transient
		return nil, errors.NewTransient(fmt.Errorf("failed to list tags for %s: %w", repo, err))
	}

	// Filter out .sig and .att artifacts (Sigstore signatures and attestations)
	// These are not container images and should not be scanned
	filteredTags := make([]string, 0, len(tags))
	for _, tag := range tags {
		if !strings.HasSuffix(tag, ".sig") && !strings.HasSuffix(tag, ".att") {
			filteredTags = append(filteredTags, tag)
		}
	}

	return filteredTags, nil
}

// GetDigest returns the digest for a specific tag
func (c *clientImpl) GetDigest(ctx context.Context, repo, tag string) (string, error) {
	registry, repository, err := parseImageRef(repo)
	if err != nil {
		return "", errors.NewPermanent(fmt.Errorf("failed to parse repository: %w", err))
	}

	// Construct image reference
	imageRef := fmt.Sprintf("%s/%s:%s", registry, repository, tag)
	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return "", errors.NewPermanent(fmt.Errorf("failed to parse image reference: %w", err))
	}

	// Get authenticator for this registry
	auth := c.getAuthForRegistry(registry)

	// Get image descriptor to retrieve digest
	desc, err := remote.Get(ref, remote.WithAuth(auth), remote.WithContext(ctx))
	if err != nil {
		// Network/registry errors are typically transient
		return "", errors.NewTransient(fmt.Errorf("failed to get image descriptor for %s: %w", imageRef, err))
	}

	return desc.Digest.String(), nil
}

// GetManifest retrieves image manifest by digest
func (c *clientImpl) GetManifest(ctx context.Context, repo, digest string) (*Manifest, error) {
	registry, repository, err := parseImageRef(repo)
	if err != nil {
		return nil, errors.NewPermanent(fmt.Errorf("failed to parse repository: %w", err))
	}

	// Construct image reference with digest
	imageRef := fmt.Sprintf("%s/%s@%s", registry, repository, digest)
	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return nil, errors.NewPermanent(fmt.Errorf("failed to parse image reference: %w", err))
	}

	// Get authenticator for this registry
	auth := c.getAuthForRegistry(registry)

	// Get image descriptor
	desc, err := remote.Get(ref, remote.WithAuth(auth), remote.WithContext(ctx))
	if err != nil {
		// Network/registry errors are typically transient
		return nil, errors.NewTransient(fmt.Errorf("failed to get image descriptor for %s: %w", imageRef, err))
	}

	// Get image to access manifest details
	img, err := desc.Image()
	if err != nil {
		// Descriptor conversion errors are typically transient
		return nil, errors.NewTransient(fmt.Errorf("failed to get image from descriptor: %w", err))
	}

	// Get config file for architecture and OS info
	configFile, err := img.ConfigFile()
	if err != nil {
		return nil, errors.NewTransient(fmt.Errorf("failed to get config file: %w", err))
	}

	// Get manifest
	rawManifest, err := img.RawManifest()
	if err != nil {
		return nil, errors.NewTransient(fmt.Errorf("failed to get raw manifest: %w", err))
	}

	// Get layers
	layers, err := img.Layers()
	if err != nil {
		return nil, errors.NewTransient(fmt.Errorf("failed to get layers: %w", err))
	}

	// Build layer descriptors
	layerDescs := make([]LayerDescriptor, 0, len(layers))
	for _, layer := range layers {
		layerDigest, err := layer.Digest()
		if err != nil {
			continue
		}
		layerSize, err := layer.Size()
		if err != nil {
			continue
		}
		layerMediaType, err := layer.MediaType()
		if err != nil {
			continue
		}

		layerDescs = append(layerDescs, LayerDescriptor{
			Digest:    layerDigest.String(),
			MediaType: string(layerMediaType),
			Size:      layerSize,
		})
	}

	// Get config descriptor
	configHash, err := img.ConfigName()
	if err != nil {
		return nil, errors.NewTransient(fmt.Errorf("failed to get config hash: %w", err))
	}

	manifest := &Manifest{
		Digest:       desc.Digest.String(),
		MediaType:    string(desc.MediaType),
		Architecture: configFile.Architecture,
		OS:           configFile.OS,
		Config: ConfigDescriptor{
			Digest:    configHash.String(),
			MediaType: string(desc.MediaType),
			Size:      int64(len(rawManifest)),
		},
		Layers:      layerDescs,
		Annotations: make(map[string]string),
	}

	return manifest, nil
}
