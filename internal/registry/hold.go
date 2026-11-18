package registry

import (
	"context"
	"encoding/json"
	stderrors "errors"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/daimoniac/suppline/internal/errors"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

// Hold annotations on the index a hold tag points at. The registry is the
// durable record of a Held digest; suppline's database only caches it.
const (
	HoldAnnotationFirstSeen = "dev.suppline.hold.first-seen"
	HoldAnnotationSource    = "dev.suppline.hold.source"
	HoldAnnotationTags      = "dev.suppline.hold.tags"
)

// holdTagRe matches the tag that keeps a Held digest from registry GC.
var holdTagRe = regexp.MustCompile(`^sha256-([0-9a-f]{64})\.hold$`)

// Hold is the registry record of one Held digest.
type Hold struct {
	Digest    string
	FirstSeen time.Time
	// Source is the upstream repository the digest was first seen in.
	Source string
	// Tags are the tags the digest is a candidate for, sorted.
	Tags []string
}

// HoldTag is the tag that keeps digest from registry GC while it is held.
func HoldTag(digest string) string {
	return strings.Replace(digest, ":", "-", 1) + ".hold"
}

// HoldTagDigest returns the digest a hold tag protects, or false when tag is
// not a hold tag.
func HoldTagDigest(tag string) (string, bool) {
	m := holdTagRe.FindStringSubmatch(tag)
	if m == nil {
		return "", false
	}
	return "sha256:" + m[1], true
}

// rawIndex pushes a prepared image index as-is.
type rawIndex []byte

func (r rawIndex) RawManifest() ([]byte, error) { return r, nil }

func (r rawIndex) MediaType() (types.MediaType, error) { return types.OCIImageIndex, nil }

// PutHold points the hold tag of h.Digest at an index that references the
// digest and records h in annotations. Because the tagged index references
// the digest, registry GC keeps the digest while it is held.
func (c *clientImpl) PutHold(ctx context.Context, repo string, h Hold) error {
	digestRef, opts, err := c.holdRef(ctx, repo, h.Digest)
	if err != nil {
		return err
	}
	desc, err := remote.Head(digestRef, opts...)
	if err != nil {
		return errors.ClassifyRegistryError(fmt.Errorf("failed to read held digest %s@%s: %w", repo, h.Digest, err))
	}
	tags := append([]string(nil), h.Tags...)
	sort.Strings(tags)
	index := v1.IndexManifest{
		SchemaVersion: 2,
		MediaType:     types.OCIImageIndex,
		Manifests: []v1.Descriptor{{
			MediaType: desc.MediaType,
			Digest:    desc.Digest,
			Size:      desc.Size,
		}},
		Annotations: map[string]string{
			HoldAnnotationFirstSeen: h.FirstSeen.UTC().Format(time.RFC3339),
			HoldAnnotationSource:    h.Source,
			HoldAnnotationTags:      strings.Join(tags, ","),
		},
	}
	raw, err := json.Marshal(index)
	if err != nil {
		return fmt.Errorf("encode hold index: %w", err)
	}
	tagRef, err := name.NewTag(digestRef.Context().String()+":"+HoldTag(h.Digest), c.nameOptions(digestRef.RegistryStr())...)
	if err != nil {
		return errors.NewPermanentf("failed to parse hold tag reference: %w", err)
	}
	if err := remote.Put(tagRef, rawIndex(raw), opts...); err != nil {
		return errors.ClassifyRegistryError(fmt.Errorf("failed to write hold tag %s: %w", tagRef, err))
	}
	return nil
}

// ListHolds reads every hold tag of repo. A hold tag whose index cannot be
// read or carries no first-seen annotation is skipped: suppline did not write
// it, or it was changed by hand.
func (c *clientImpl) ListHolds(ctx context.Context, repo string) ([]Hold, error) {
	repoRef, opts, err := c.repositoryRef(ctx, repo)
	if err != nil {
		return nil, err
	}
	tags, err := remote.List(repoRef, opts...)
	if err != nil {
		return nil, errors.ClassifyRegistryError(fmt.Errorf("failed to list tags for %s: %w", repo, err))
	}
	var holds []Hold
	for _, tag := range tags {
		digest, ok := HoldTagDigest(tag)
		if !ok {
			continue
		}
		hold, err := c.readHold(repoRef.Tag(tag), digest, opts)
		if err != nil {
			return nil, err
		}
		if hold != nil {
			holds = append(holds, *hold)
		}
	}
	return holds, nil
}

func (c *clientImpl) readHold(tagRef name.Tag, digest string, opts []remote.Option) (*Hold, error) {
	desc, err := remote.Get(tagRef, opts...)
	if err != nil {
		return nil, errors.ClassifyRegistryError(fmt.Errorf("failed to read hold tag %s: %w", tagRef, err))
	}
	var index v1.IndexManifest
	if err := json.Unmarshal(desc.Manifest, &index); err != nil {
		return nil, nil
	}
	firstSeen, err := time.Parse(time.RFC3339, index.Annotations[HoldAnnotationFirstSeen])
	if err != nil {
		return nil, nil
	}
	hold := &Hold{
		Digest:    digest,
		FirstSeen: firstSeen.UTC(),
		Source:    index.Annotations[HoldAnnotationSource],
	}
	if tags := index.Annotations[HoldAnnotationTags]; tags != "" {
		hold.Tags = strings.Split(tags, ",")
	}
	return hold, nil
}

// DeleteHold removes the hold tag of digest. It deletes the tag where the
// registry allows that, and otherwise the index the tag names, which untags
// it. The held digest itself stays either way. A missing hold tag is not an
// error.
func (c *clientImpl) DeleteHold(ctx context.Context, repo, digest string) error {
	repoRef, opts, err := c.repositoryRef(ctx, repo)
	if err != nil {
		return err
	}
	tagRef := repoRef.Tag(HoldTag(digest))
	desc, err := remote.Head(tagRef, opts...)
	if err != nil {
		var terr *transport.Error
		if stderrors.As(err, &terr) && terr.StatusCode == http.StatusNotFound {
			return nil
		}
		return errors.ClassifyRegistryError(fmt.Errorf("failed to read hold tag of %s@%s: %w", repo, digest, err))
	}
	if desc.Digest.String() == digest {
		// Never delete the held image itself through a hand-made hold tag.
		return errors.NewPermanentf("hold tag of %s@%s names the held digest, not a hold index", repo, digest)
	}
	if err := remote.Delete(tagRef, opts...); err == nil {
		return nil
	}
	if err := remote.Delete(repoRef.Digest(desc.Digest.String()), opts...); err != nil {
		return errors.ClassifyRegistryError(fmt.Errorf("failed to delete hold tag of %s@%s: %w", repo, digest, err))
	}
	return nil
}

func (c *clientImpl) repositoryRef(ctx context.Context, repo string) (name.Repository, []remote.Option, error) {
	registry, repository, err := parseImageRef(repo)
	if err != nil {
		return name.Repository{}, nil, errors.NewPermanentf("failed to parse repository: %w", err)
	}
	repoRef, err := name.NewRepository(registry+"/"+repository, c.nameOptions(registry)...)
	if err != nil {
		return name.Repository{}, nil, errors.NewPermanentf("failed to create repository reference: %w", err)
	}
	opts := append([]remote.Option{remote.WithAuth(c.getAuthForRegistry(registry)), remote.WithContext(ctx)}, c.remoteOpts...)
	return repoRef, opts, nil
}

func (c *clientImpl) holdRef(ctx context.Context, repo, digest string) (name.Digest, []remote.Option, error) {
	repoRef, opts, err := c.repositoryRef(ctx, repo)
	if err != nil {
		return name.Digest{}, nil, err
	}
	return repoRef.Digest(digest), opts, nil
}
