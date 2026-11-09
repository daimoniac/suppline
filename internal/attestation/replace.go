package attestation

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/match"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

const (
	annotationBundlePredicate = "dev.sigstore.bundle.predicateType"
	annotationPredicateType   = "predicateType"
	annotationCreated         = "org.opencontainers.image.created"

	predicateVuln = "https://cosign.sigstore.dev/attestation/vuln/v1"
)

// sameKindCleaner removes attestations of one predicate from a registry.
// Tests substitute it. Production leaves it nil and talks to the registry.
type sameKindCleaner interface {
	listSameKind(ctx context.Context, digest name.Digest, predicate string) ([]string, error)
	deletePrevious(ctx context.Context, digest name.Digest, predicate string, previous []string, listed bool) error
}

// canonicalPredicate maps a cosign --type value to the predicate type stored on the attestation.
func canonicalPredicate(cosignType string) string {
	switch cosignType {
	case "vuln":
		return predicateVuln
	case "cyclonedx":
		return "https://cyclonedx.org/bom"
	case "spdx", "spdxjson":
		return "https://spdx.dev/Document"
	default:
		return cosignType
	}
}

func predicateOf(desc v1.Descriptor) string {
	if desc.Annotations == nil {
		return ""
	}
	if predicate := desc.Annotations[annotationBundlePredicate]; predicate != "" {
		return predicate
	}
	return desc.Annotations[annotationPredicateType]
}

func sameKindDigests(descs []v1.Descriptor, predicate string) []string {
	var out []string
	seen := map[string]struct{}{}
	for _, desc := range descs {
		if predicateOf(desc) != predicate {
			continue
		}
		digest := desc.Digest.String()
		if digest == "" {
			continue
		}
		if _, ok := seen[digest]; ok {
			continue
		}
		seen[digest] = struct{}{}
		out = append(out, digest)
	}
	return out
}

// staleSameKind returns snapshot digests that are still listed.
// A digest listed now but absent from the snapshot is the attestation just written, so
// every still-present snapshot digest is removed. When the new digest is not visible,
// one listed digest is kept so a reused attestation is not deleted.
func staleSameKind(previous, current []string) []string {
	if len(current) == 0 {
		return nil
	}
	present := map[string]struct{}{}
	for _, digest := range current {
		present[digest] = struct{}{}
	}
	var stale []string
	for _, digest := range previous {
		if _, ok := present[digest]; ok {
			stale = append(stale, digest)
		}
	}
	if len(present) > len(stale) {
		return stale
	}
	keep := current[len(current)-1]
	filtered := stale[:0]
	for _, digest := range stale {
		if digest != keep {
			filtered = append(filtered, digest)
		}
	}
	return filtered
}

func allButNewest(descs []v1.Descriptor, predicate string) []string {
	var matched []v1.Descriptor
	for _, desc := range descs {
		if predicateOf(desc) == predicate && desc.Digest.String() != "" {
			matched = append(matched, desc)
		}
	}
	if len(matched) <= 1 {
		return nil
	}
	newest := 0
	for i := 1; i < len(matched); i++ {
		if createdOf(matched[i]) >= createdOf(matched[newest]) {
			newest = i
		}
	}
	var out []string
	for i, desc := range matched {
		if i == newest {
			continue
		}
		out = append(out, desc.Digest.String())
	}
	return out
}

func createdOf(desc v1.Descriptor) string {
	if desc.Annotations == nil {
		return ""
	}
	return desc.Annotations[annotationCreated]
}

// attestReplacingSameKind writes one attestation, then deletes older attestations of that
// predicate for the image. Other predicates are left alone. Cleanup failure does not fail
// the attest: the new attestation is already published, and failing here would retry and
// publish another one.
func (a *SigstoreAttestor) attestReplacingSameKind(ctx context.Context, operation, cosignType, predicatePath, imageRef string) error {
	predicate := canonicalPredicate(cosignType)
	digest, digestErr := parseImageDigest(imageRef)
	var previous []string
	listed := false
	if digestErr == nil {
		var listErr error
		previous, listErr = a.listSameKind(ctx, digest, predicate)
		listed = listErr == nil
		if listErr != nil {
			a.logger.Warn("could not list attestations to replace",
				"image_ref", imageRef,
				"predicate", predicate,
				"error", listErr)
		}
	}

	if _, err := a.runCosignAttest(ctx, operation, a.attestArgs(cosignType, predicatePath, imageRef)...); err != nil {
		return err
	}
	if digestErr != nil {
		a.logger.Debug("skipping attestation cleanup; image ref has no digest", "image_ref", imageRef)
		return nil
	}
	if err := a.deletePrevious(ctx, digest, predicate, previous, listed); err != nil {
		a.logger.Warn("failed to delete previous attestations",
			"image_ref", imageRef,
			"predicate", predicate,
			"error", err)
	}
	return nil
}

func (a *SigstoreAttestor) listSameKind(ctx context.Context, digest name.Digest, predicate string) ([]string, error) {
	if a.cleaner != nil {
		return a.cleaner.listSameKind(ctx, digest, predicate)
	}
	return listSameKind(ctx, digest, predicate)
}

func (a *SigstoreAttestor) deletePrevious(ctx context.Context, digest name.Digest, predicate string, previous []string, listed bool) error {
	if a.cleaner != nil {
		return a.cleaner.deletePrevious(ctx, digest, predicate, previous, listed)
	}
	return deletePreviousAttestations(ctx, a, digest, predicate, previous, listed)
}

func parseImageDigest(imageRef string) (name.Digest, error) {
	var opts []name.Option
	if allowHTTPRegistry() {
		opts = append(opts, name.Insecure)
	}
	return name.NewDigest(imageRef, opts...)
}

func remoteOptions(ctx context.Context) []remote.Option {
	return []remote.Option{
		remote.WithContext(ctx),
		remote.WithAuthFromKeychain(authn.DefaultKeychain),
	}
}

func listSameKind(ctx context.Context, digest name.Digest, predicate string) ([]string, error) {
	descs, err := referrerDescriptors(ctx, digest)
	if err != nil {
		return nil, err
	}
	return sameKindDigests(descs, predicate), nil
}

func referrerDescriptors(ctx context.Context, digest name.Digest) ([]v1.Descriptor, error) {
	index, err := remote.Referrers(digest, remoteOptions(ctx)...)
	if err != nil {
		return nil, err
	}
	manifest, err := index.IndexManifest()
	if err != nil {
		return nil, err
	}
	return manifest.Manifests, nil
}

func deletePreviousAttestations(ctx context.Context, a *SigstoreAttestor, digest name.Digest, predicate string, previous []string, listed bool) error {
	var errs []error
	var stale []string
	current, err := referrerDescriptors(ctx, digest)
	if err != nil && listed {
		// The snapshot was taken before this write, so it does not include the new attestation.
		a.logger.Warn("could not re-list attestations; deleting the pre-attest snapshot",
			"image", digest.String(),
			"predicate", predicate,
			"error", err)
		stale = previous
	} else if err != nil {
		return err
	} else if listed {
		stale = staleSameKind(previous, sameKindDigests(current, predicate))
	} else {
		stale = allButNewest(current, predicate)
	}

	// Rewrite a referrers fallback tag before deleting blobs. A failed rewrite leaves the
	// tag pointing at those blobs, so deleting them would strand the index.
	if err := dropFallbackDescriptors(ctx, digest, stale); err != nil {
		errs = append(errs, err)
	} else {
		for _, old := range stale {
			ref := digest.Context().Digest(old)
			delErr := remote.Delete(ref, remoteOptions(ctx)...)
			if delErr != nil && !isNotFound(delErr) {
				errs = append(errs, fmt.Errorf("delete %s: %w", old, delErr))
				continue
			}
			if delErr == nil {
				a.logger.Info("deleted previous attestation",
					"image", digest.String(),
					"predicate", predicate,
					"digest", old)
			}
		}
	}
	// Bundle mode publishes the new attestation as a referrer. The classic .att tag is then
	// only historical, so drop this predicate from it. Classic mode just rewrote that tag
	// with --replace, and stripping it would delete the attestation we just wrote.
	if useNewBundleFormat() {
		if err := stripClassicAttestation(ctx, digest, predicate); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func dropFallbackDescriptors(ctx context.Context, digest name.Digest, drop []string) error {
	if len(drop) == 0 {
		return nil
	}
	tag := fallbackTag(digest)
	index, err := remote.Index(tag, remoteOptions(ctx)...)
	if isNotFound(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read referrers tag %s: %w", tag.String(), err)
	}
	manifest, err := index.IndexManifest()
	if err != nil {
		return err
	}
	dropSet := map[string]struct{}{}
	var hashes []v1.Hash
	for _, old := range drop {
		dropSet[old] = struct{}{}
		hash, err := v1.NewHash(old)
		if err != nil {
			return err
		}
		hashes = append(hashes, hash)
	}
	remaining := 0
	for _, desc := range manifest.Manifests {
		if _, ok := dropSet[desc.Digest.String()]; !ok {
			remaining++
		}
	}
	if remaining == len(manifest.Manifests) {
		return nil
	}
	if remaining == 0 {
		return ignoreNotFound(remote.Delete(tag, remoteOptions(ctx)...))
	}
	return remote.WriteIndex(tag, mutate.RemoveManifests(index, match.Digests(hashes...)), remoteOptions(ctx)...)
}

func stripClassicAttestation(ctx context.Context, digest name.Digest, predicate string) error {
	tag := classicAttTag(digest)
	desc, err := remote.Get(tag, remoteOptions(ctx)...)
	if isNotFound(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read %s: %w", tag.String(), err)
	}
	switch desc.MediaType {
	case types.OCIImageIndex, types.DockerManifestList:
		return stripClassicIndex(ctx, tag, desc, predicate)
	default:
		return stripClassicImage(ctx, tag, desc, predicate)
	}
}

func stripClassicIndex(ctx context.Context, tag name.Tag, desc *remote.Descriptor, predicate string) error {
	index, err := desc.ImageIndex()
	if err != nil {
		return err
	}
	manifest, err := index.IndexManifest()
	if err != nil {
		return err
	}
	var drop []v1.Hash
	for _, item := range manifest.Manifests {
		if predicateOf(item) == predicate {
			drop = append(drop, item.Digest)
		}
	}
	if len(drop) == 0 {
		return nil
	}
	if len(drop) == len(manifest.Manifests) {
		return ignoreNotFound(remote.Delete(tag, remoteOptions(ctx)...))
	}
	return remote.WriteIndex(tag, mutate.RemoveManifests(index, match.Digests(drop...)), remoteOptions(ctx)...)
}

func stripClassicImage(ctx context.Context, tag name.Tag, desc *remote.Descriptor, predicate string) error {
	manifest, err := desc.Image()
	if err != nil {
		return err
	}
	parsed, err := manifest.Manifest()
	if err != nil {
		return err
	}
	rewritten, changed, empty := manifestWithoutPredicate(parsed, predicate)
	if !changed {
		return nil
	}
	if empty {
		return ignoreNotFound(remote.Delete(tag, remoteOptions(ctx)...))
	}
	// Put the original manifest with this predicate's layers removed. The config and the
	// remaining layer blobs are already in the registry. Rebuilding the image would publish
	// a new config digest the registry has never seen.
	raw, err := json.Marshal(rewritten)
	if err != nil {
		return err
	}
	return remote.Put(tag, &rawManifest{mediaType: desc.MediaType, raw: raw}, remoteOptions(ctx)...)
}

func manifestWithoutPredicate(manifest *v1.Manifest, predicate string) (*v1.Manifest, bool, bool) {
	kept := make([]v1.Descriptor, 0, len(manifest.Layers))
	for _, layer := range manifest.Layers {
		if predicateOf(layer) == predicate {
			continue
		}
		kept = append(kept, layer)
	}
	if len(kept) == len(manifest.Layers) {
		return manifest, false, false
	}
	updated := *manifest
	updated.Layers = kept
	return &updated, true, len(kept) == 0
}

type rawManifest struct {
	mediaType types.MediaType
	raw       []byte
}

func (m *rawManifest) RawManifest() ([]byte, error) { return m.raw, nil }

func (m *rawManifest) MediaType() (types.MediaType, error) { return m.mediaType, nil }

func fallbackTag(digest name.Digest) name.Tag {
	return digest.Context().Tag(strings.Replace(digest.DigestStr(), ":", "-", 1))
}

func classicAttTag(digest name.Digest) name.Tag {
	return digest.Context().Tag(strings.Replace(digest.DigestStr(), ":", "-", 1) + ".att")
}

func isNotFound(err error) bool {
	var transportErr *transport.Error
	return errors.As(err, &transportErr) && transportErr.StatusCode == http.StatusNotFound
}

func ignoreNotFound(err error) error {
	if err == nil || isNotFound(err) {
		return nil
	}
	return err
}
