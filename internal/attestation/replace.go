package attestation

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
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

	PredicateVuln       = "https://cosign.sigstore.dev/attestation/vuln/v1"
	predicateVuln       = PredicateVuln
	PredicateBOM        = "https://cyclonedx.org/bom"
	predicateBOM        = PredicateBOM
	predicateCosignSign = "https://sigstore.dev/cosign/sign/v1"

	// maxSameKindPasses bounds the list/delete loop. One pass can leave the previous
	// newest in place when the attestation just written is not visible yet; the next
	// pass sees it and removes that survivor.
	maxSameKindPasses = 5
)

// sameKindCleaner removes attestations of one predicate from a registry.
// keepNewest retains the referrer with the latest created time. Tests substitute it.
// Production leaves it nil and talks to the registry.
type sameKindCleaner interface {
	collapse(ctx context.Context, digest name.Digest, predicate string, keepNewest bool) error
}

// canonicalPredicate maps a cosign --type value to the predicate type stored on the attestation.
func canonicalPredicate(cosignType string) string {
	switch cosignType {
	case "vuln":
		return predicateVuln
	case "cyclonedx":
		return predicateBOM
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
// predicate for the image. Cosign signature referrers are collapsed the same way. Other
// predicates are left alone. Cleanup failure does not fail the attest: the new attestation
// is already published, and failing here would retry and publish another one.
func (a *SigstoreAttestor) attestReplacingSameKind(ctx context.Context, operation, cosignType, predicatePath, imageRef string) error {
	predicate := canonicalPredicate(cosignType)
	digest, digestErr := parseImageDigest(imageRef)

	if _, err := a.runCosignAttest(ctx, operation, a.attestArgs(cosignType, predicatePath, imageRef)...); err != nil {
		return err
	}
	if digestErr != nil {
		a.logger.Debug("skipping attestation cleanup; image ref has no digest", "image_ref", imageRef)
		return nil
	}
	a.collapseSameKind(ctx, digest, predicate, true)
	// Referrers annotated as cosign signatures are historical attestations stored under the
	// wrong predicate. None of them is the attestation just written, so delete every one.
	if predicate != predicateCosignSign {
		a.collapseSameKind(ctx, digest, predicateCosignSign, false)
	}
	return nil
}

// DeleteReferrers removes every referrer of one predicate. A scan that no longer publishes
// that predicate uses this so old bundles do not stay for Kyverno to download.
func (a *SigstoreAttestor) DeleteReferrers(ctx context.Context, imageRef, predicate string) error {
	digest, err := parseImageDigest(imageRef)
	if err != nil {
		return nil
	}
	return collapseReferrers(ctx, a, digest, predicate, false)
}

func (a *SigstoreAttestor) collapseSameKind(ctx context.Context, digest name.Digest, predicate string, keepNewest bool) {
	var err error
	if a.cleaner != nil {
		err = a.cleaner.collapse(ctx, digest, predicate, keepNewest)
	} else {
		err = collapseReferrers(ctx, a, digest, predicate, keepNewest)
	}
	if err != nil {
		a.logger.Warn("failed to delete previous attestations",
			"image_ref", digest.String(),
			"predicate", predicate,
			"error", err)
	}
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

// loadReferrers and removeReferrers are the registry calls behind a collapse pass.
// Tests replace them.
var (
	loadReferrers   = referrerDescriptors
	removeReferrers = deleteReferrers
)

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

func collapseReferrers(ctx context.Context, a *SigstoreAttestor, digest name.Digest, predicate string, keepNewest bool) error {
	var errs []error
	seen := ""
	for pass := 0; pass < maxSameKindPasses; pass++ {
		current, err := loadReferrers(ctx, digest)
		if err != nil {
			return errors.Join(append(errs, err)...)
		}
		stale := sameKindDigests(current, predicate)
		if keepNewest {
			stale = allButNewest(current, predicate)
		}
		if len(stale) == 0 {
			break
		}
		keyParts := append([]string(nil), stale...)
		sort.Strings(keyParts)
		key := strings.Join(keyParts, ",")
		if key == seen {
			errs = append(errs, fmt.Errorf("still %d %s referrers after delete", len(stale), predicate))
			break
		}
		seen = key
		if err := removeReferrers(ctx, a, digest, predicate, stale); err != nil {
			errs = append(errs, err)
			break
		}
	}
	// Bundle mode publishes the new attestation as a referrer. The classic .att tag is then
	// only historical, so drop this predicate from it. Classic mode just rewrote that tag
	// with --replace, and stripping it would delete the attestation we just wrote.
	// Signature referrers are not stored in that tag.
	if useNewBundleFormat() && predicate != predicateCosignSign {
		if err := stripClassicAttestation(ctx, digest, predicate); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func deleteReferrers(ctx context.Context, a *SigstoreAttestor, digest name.Digest, predicate string, stale []string) error {
	var errs []error
	// Rewrite a referrers fallback tag before deleting blobs. A failed rewrite leaves the
	// tag pointing at those blobs, so deleting them would strand the index.
	if err := dropFallbackDescriptors(ctx, digest, stale); err != nil {
		return err
	}
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
