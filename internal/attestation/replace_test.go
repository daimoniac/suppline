package attestation

import (
	"context"
	"os"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
)

func TestCanonicalPredicate(t *testing.T) {
	if got := canonicalPredicate("vuln"); got != predicateVuln {
		t.Fatalf("vuln predicate = %s", got)
	}
	const scai = "https://in-toto.io/attestation/scai/attribute-report/v0.3"
	if got := canonicalPredicate(scai); got != scai {
		t.Fatalf("url predicate = %s", got)
	}
}

func TestSameKindDigestsIgnoresOtherPredicates(t *testing.T) {
	descs := []v1.Descriptor{
		{Digest: hash(t, 'a'), Annotations: map[string]string{annotationBundlePredicate: predicateVuln}},
		{Digest: hash(t, 'b'), Annotations: map[string]string{annotationPredicateType: "https://cyclonedx.org/bom"}},
		{Digest: hash(t, 'a'), Annotations: map[string]string{annotationBundlePredicate: predicateVuln}},
	}
	got := sameKindDigests(descs, predicateVuln)
	if len(got) != 1 || got[0] != hash(t, 'a').String() {
		t.Fatalf("digests = %#v", got)
	}
}

func TestStaleSameKindKeepsTheNewAttestation(t *testing.T) {
	previous := []string{"sha256:old1", "sha256:old2"}
	current := []string{"sha256:old1", "sha256:old2", "sha256:new"}
	got := staleSameKind(previous, current)
	if len(got) != 2 || got[0] != "sha256:old1" || got[1] != "sha256:old2" {
		t.Fatalf("stale = %#v", got)
	}
}

func TestStaleSameKindKeepsTheOnlyCopy(t *testing.T) {
	got := staleSameKind([]string{"sha256:only"}, []string{"sha256:only"})
	if len(got) != 0 {
		t.Fatalf("stale = %#v, want none", got)
	}
}

func TestAllButNewestUsesCreatedAnnotation(t *testing.T) {
	descs := []v1.Descriptor{
		{Digest: hash(t, 'a'), Annotations: map[string]string{annotationBundlePredicate: predicateVuln, annotationCreated: "2026-11-01T00:00:00Z"}},
		{Digest: hash(t, 'b'), Annotations: map[string]string{annotationBundlePredicate: predicateVuln, annotationCreated: "2026-11-09T00:00:00Z"}},
		{Digest: hash(t, 'c'), Annotations: map[string]string{annotationBundlePredicate: "https://cyclonedx.org/bom", annotationCreated: "2026-11-09T00:00:00Z"}},
	}
	got := allButNewest(descs, predicateVuln)
	if len(got) != 1 || got[0] != hash(t, 'a').String() {
		t.Fatalf("stale = %#v", got)
	}
}

func TestManifestWithoutPredicateKeepsOtherLayers(t *testing.T) {
	manifest := &v1.Manifest{
		SchemaVersion: 2,
		Config:        v1.Descriptor{Digest: hash(t, 'c')},
		Layers: []v1.Descriptor{
			{Digest: hash(t, 'a'), Annotations: map[string]string{annotationPredicateType: "https://cyclonedx.org/bom"}},
			{Digest: hash(t, 'b'), Annotations: map[string]string{annotationPredicateType: predicateVuln}},
		},
	}
	updated, changed, empty := manifestWithoutPredicate(manifest, "https://cyclonedx.org/bom")
	if !changed || empty || len(updated.Layers) != 1 || updated.Layers[0].Digest != hash(t, 'b') {
		t.Fatalf("updated = %#v changed=%v empty=%v", updated.Layers, changed, empty)
	}
	if updated.Config.Digest != hash(t, 'c') {
		t.Fatal("config digest changed")
	}
}

func TestManifestWithoutPredicateDeletesWhenLastLayer(t *testing.T) {
	manifest := &v1.Manifest{
		Layers: []v1.Descriptor{
			{Digest: hash(t, 'a'), Annotations: map[string]string{annotationPredicateType: predicateVuln}},
		},
	}
	_, changed, empty := manifestWithoutPredicate(manifest, predicateVuln)
	if !changed || !empty {
		t.Fatalf("changed=%v empty=%v", changed, empty)
	}
}

func TestAttestSBOMDeletesPreviousSameKind(t *testing.T) {
	fakeBinDir := writeFakeCosign(t, "#!/bin/sh\nexit 0\n")
	t.Setenv("PATH", fakeBinDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	cleaner := &recordingCleaner{list: []string{"sha256:old"}}
	attestor := testAttestor(t)
	attestor.cleaner = cleaner

	imageRef := "example.com/app@sha256:" + repeatHex('a')
	if err := attestor.AttestSBOM(context.Background(), imageRef, testSBOM(t)); err != nil {
		t.Fatalf("AttestSBOM: %v", err)
	}
	if cleaner.predicate != "https://cyclonedx.org/bom" {
		t.Fatalf("predicate = %s", cleaner.predicate)
	}
	if !cleaner.listed || len(cleaner.previous) != 1 || cleaner.previous[0] != "sha256:old" {
		t.Fatalf("previous = %#v listed=%v", cleaner.previous, cleaner.listed)
	}
}

func TestAttestSBOMSkipsCleanupWithoutDigest(t *testing.T) {
	fakeBinDir := writeFakeCosign(t, "#!/bin/sh\nexit 0\n")
	t.Setenv("PATH", fakeBinDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	cleaner := &recordingCleaner{}
	attestor := testAttestor(t)
	attestor.cleaner = cleaner
	if err := attestor.AttestSBOM(context.Background(), "example.com/app:latest", testSBOM(t)); err != nil {
		t.Fatalf("AttestSBOM: %v", err)
	}
	if cleaner.predicate != "" {
		t.Fatalf("cleanup ran for a tag ref: %#v", cleaner)
	}
}

func TestAttestSBOMStillAttestsWhenListingFails(t *testing.T) {
	fakeBinDir := writeFakeCosign(t, "#!/bin/sh\nexit 0\n")
	t.Setenv("PATH", fakeBinDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	cleaner := &recordingCleaner{listErr: os.ErrClosed}
	attestor := testAttestor(t)
	attestor.cleaner = cleaner
	imageRef := "example.com/app@sha256:" + repeatHex('c')
	if err := attestor.AttestSBOM(context.Background(), imageRef, testSBOM(t)); err != nil {
		t.Fatalf("AttestSBOM: %v", err)
	}
	if cleaner.listed || cleaner.previous != nil {
		t.Fatalf("delete = %#v listed=%v", cleaner.previous, cleaner.listed)
	}
	if cleaner.deleteCalls != 1 {
		t.Fatalf("delete calls = %d", cleaner.deleteCalls)
	}
}

func TestAttestSBOMSkipsCleanupWhenCosignFails(t *testing.T) {
	fakeBinDir := writeFakeCosign(t, "#!/bin/sh\nexit 1\n")
	t.Setenv("PATH", fakeBinDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	cleaner := &recordingCleaner{list: []string{"sha256:old"}}
	attestor := testAttestor(t)
	attestor.cleaner = cleaner
	imageRef := "example.com/app@sha256:" + repeatHex('b')
	if err := attestor.AttestSBOM(context.Background(), imageRef, testSBOM(t)); err == nil {
		t.Fatal("expected cosign failure")
	}
	if cleaner.previous != nil {
		t.Fatalf("deleted after a failed attest: %#v", cleaner.previous)
	}
}

type recordingCleaner struct {
	list        []string
	listErr     error
	predicate   string
	previous    []string
	listed      bool
	deleteCalls int
}

func (r *recordingCleaner) listSameKind(_ context.Context, _ name.Digest, predicate string) ([]string, error) {
	r.predicate = predicate
	return r.list, r.listErr
}

func (r *recordingCleaner) deletePrevious(_ context.Context, _ name.Digest, predicate string, previous []string, listed bool) error {
	r.deleteCalls++
	r.predicate = predicate
	r.previous = append([]string(nil), previous...)
	r.listed = listed
	return nil
}

func hash(t *testing.T, seed byte) v1.Hash {
	t.Helper()
	digest, err := v1.NewHash("sha256:" + repeatHex(seed))
	if err != nil {
		t.Fatal(err)
	}
	return digest
}

func repeatHex(b byte) string {
	out := make([]byte, 64)
	for i := range out {
		out[i] = b
	}
	return string(out)
}
