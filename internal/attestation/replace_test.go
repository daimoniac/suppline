package attestation

import (
	"context"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

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

func TestAllButNewestIgnoresListOrder(t *testing.T) {
	descs := []v1.Descriptor{
		{Digest: hash(t, 'b'), Annotations: map[string]string{annotationBundlePredicate: predicateVuln, annotationCreated: "2026-11-09T00:00:00Z"}},
		{Digest: hash(t, 'a'), Annotations: map[string]string{annotationBundlePredicate: predicateVuln, annotationCreated: "2026-11-01T00:00:00Z"}},
	}
	got := allButNewest(descs, predicateVuln)
	if len(got) != 1 || got[0] != hash(t, 'a').String() {
		t.Fatalf("stale = %#v", got)
	}
}

func TestCollapseRelistsUntilOneRemains(t *testing.T) {
	const scai = "https://in-toto.io/attestation/scai/attribute-report/v0.3"
	older := v1.Descriptor{Digest: hash(t, 'a'), Annotations: map[string]string{annotationBundlePredicate: scai, annotationCreated: "2026-10-01T00:00:00Z"}}
	expired := v1.Descriptor{Digest: hash(t, 'b'), Annotations: map[string]string{annotationBundlePredicate: scai, annotationCreated: "2026-11-01T00:00:00Z"}}
	fresh := v1.Descriptor{Digest: hash(t, 'c'), Annotations: map[string]string{annotationBundlePredicate: scai, annotationCreated: "2026-11-10T00:00:00Z"}}
	lists := [][]v1.Descriptor{
		{older, expired},
		{expired, fresh},
		{fresh},
	}
	calls := 0
	prevLoad, prevRemove := loadReferrers, removeReferrers
	t.Cleanup(func() {
		loadReferrers = prevLoad
		removeReferrers = prevRemove
	})
	loadReferrers = func(context.Context, name.Digest) ([]v1.Descriptor, error) {
		i := calls
		if i >= len(lists) {
			i = len(lists) - 1
		}
		calls++
		return lists[i], nil
	}
	var deleted []string
	removeReferrers = func(_ context.Context, _ *SigstoreAttestor, _ name.Digest, predicate string, stale []string) error {
		if predicate != scai {
			t.Errorf("predicate = %s", predicate)
		}
		deleted = append(deleted, stale...)
		return nil
	}

	digest, err := name.NewDigest("example.com/app@sha256:" + repeatHex('d'))
	if err != nil {
		t.Fatal(err)
	}
	if err := collapseReferrers(context.Background(), classicAttestor(t), digest, scai, true, time.Time{}); err != nil {
		t.Fatal(err)
	}
	if calls != 3 {
		t.Fatalf("lists = %d, want 3", calls)
	}
	if len(deleted) != 2 || deleted[0] != older.Digest.String() || deleted[1] != expired.Digest.String() {
		t.Fatalf("deleted = %#v", deleted)
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

func TestCollapseDeletesEverySignatureReferrer(t *testing.T) {
	first := v1.Descriptor{Digest: hash(t, 'a'), Annotations: map[string]string{annotationBundlePredicate: predicateCosignSign, annotationCreated: "2026-04-11T00:00:00Z"}}
	second := v1.Descriptor{Digest: hash(t, 'b'), Annotations: map[string]string{annotationBundlePredicate: predicateCosignSign, annotationCreated: "2026-04-14T00:00:00Z"}}
	lists := [][]v1.Descriptor{{first, second}, {}}
	calls := 0
	prevLoad, prevRemove := loadReferrers, removeReferrers
	t.Cleanup(func() {
		loadReferrers = prevLoad
		removeReferrers = prevRemove
	})
	loadReferrers = func(context.Context, name.Digest) ([]v1.Descriptor, error) {
		i := calls
		if i >= len(lists) {
			i = len(lists) - 1
		}
		calls++
		return lists[i], nil
	}
	var deleted []string
	removeReferrers = func(_ context.Context, _ *SigstoreAttestor, _ name.Digest, predicate string, stale []string) error {
		if predicate != predicateCosignSign {
			t.Errorf("predicate = %s", predicate)
		}
		deleted = append(deleted, stale...)
		return nil
	}
	digest, err := name.NewDigest("example.com/app@sha256:" + repeatHex('e'))
	if err != nil {
		t.Fatal(err)
	}
	if err := collapseReferrers(context.Background(), classicAttestor(t), digest, predicateCosignSign, false, time.Time{}); err != nil {
		t.Fatal(err)
	}
	if len(deleted) != 2 {
		t.Fatalf("deleted = %#v", deleted)
	}
}

const scaiPredicate = "https://in-toto.io/attestation/scai/attribute-report/v0.3"

var stubMu sync.Mutex

// classicAttestor writes classic .att tags, so collapse never strips them.
func classicAttestor(t *testing.T) *SigstoreAttestor {
	t.Helper()
	return testAttestorWith(t, AttestationConfig{NewBundleFormat: false})
}

func stubRegistry(t *testing.T, lists [][]v1.Descriptor, exists func(string) bool) (calls *int, deleted *[]string) {
	t.Helper()
	prevLoad, prevRemove, prevExists, prevWaits := loadReferrers, removeReferrers, manifestExists, visibilityWaits
	t.Cleanup(func() {
		loadReferrers, removeReferrers, manifestExists, visibilityWaits = prevLoad, prevRemove, prevExists, prevWaits
	})
	visibilityWaits = []time.Duration{0, 0, 0}
	calls, deleted = new(int), new([]string)
	loadReferrers = func(context.Context, name.Digest) ([]v1.Descriptor, error) {
		stubMu.Lock()
		defer stubMu.Unlock()
		i := *calls
		if i >= len(lists) {
			i = len(lists) - 1
		}
		*calls++
		return lists[i], nil
	}
	removeReferrers = func(_ context.Context, _ *SigstoreAttestor, _ name.Digest, _ string, stale []string) error {
		stubMu.Lock()
		defer stubMu.Unlock()
		*deleted = append(*deleted, stale...)
		return nil
	}
	manifestExists = func(_ context.Context, ref name.Digest) (bool, error) {
		return exists(ref.DigestStr()), nil
	}
	return calls, deleted
}

func scaiReferrer(t *testing.T, seed byte, created time.Time) v1.Descriptor {
	return v1.Descriptor{Digest: hash(t, seed), Annotations: map[string]string{
		annotationBundlePredicate: scaiPredicate,
		annotationCreated:         created.UTC().Format(time.RFC3339),
	}}
}

// The registry lists a new referrer a few seconds after the push. Collapsing the first
// list, which holds only the older attestation, would keep that one and leave it behind.
func TestCollapseWaitsForTheNewAttestationToBeListed(t *testing.T) {
	started := time.Now()
	older := scaiReferrer(t, 'a', started.Add(-24*time.Hour))
	fresh := scaiReferrer(t, 'b', started)
	calls, deleted := stubRegistry(t, [][]v1.Descriptor{{older}, {older}, {older, fresh}, {fresh}}, func(string) bool { return false })

	digest, _ := name.NewDigest("example.com/app@sha256:" + repeatHex('d'))
	if err := collapseReferrers(context.Background(), classicAttestor(t), digest, scaiPredicate, true, started); err != nil {
		t.Fatal(err)
	}
	if len(*deleted) != 1 || (*deleted)[0] != older.Digest.String() {
		t.Fatalf("deleted = %v after %d lists, want the older attestation", *deleted, *calls)
	}
}

func TestCollapseReportsANewAttestationThatNeverAppears(t *testing.T) {
	started := time.Now()
	older := scaiReferrer(t, 'a', started.Add(-24*time.Hour))
	_, deleted := stubRegistry(t, [][]v1.Descriptor{{older}}, func(string) bool { return false })

	digest, _ := name.NewDigest("example.com/app@sha256:" + repeatHex('d'))
	err := collapseReferrers(context.Background(), classicAttestor(t), digest, scaiPredicate, true, started)
	if !errors.Is(err, errNotListedYet) {
		t.Fatalf("err = %v, want errNotListedYet", err)
	}
	if len(*deleted) != 0 {
		t.Fatalf("deleted %v while the new attestation was unlisted", *deleted)
	}
}

// Docker Hub can list the new attestation after the scan stopped waiting. A background
// retry then removes the older one.
func TestCollapseLaterDeletesOnceTheNewAttestationIsListed(t *testing.T) {
	started := time.Now()
	older := scaiReferrer(t, 'a', started.Add(-24*time.Hour))
	fresh := scaiReferrer(t, 'b', started)
	// Four lists without the new attestation exhaust the first collapse; the retry then sees it.
	lists := [][]v1.Descriptor{{older}, {older}, {older}, {older}, {older, fresh}, {fresh}}
	_, deleted := stubRegistry(t, lists, func(string) bool { return false })
	prev := laterWaits
	laterWaits = []time.Duration{time.Millisecond, time.Millisecond}
	t.Cleanup(func() { laterWaits = prev })

	attestor := classicAttestor(t)
	digest, _ := name.NewDigest("example.com/app@sha256:" + repeatHex('d'))
	attestor.collapseSameKind(context.Background(), digest, scaiPredicate, true, started)

	// The retry is done when it clears its in-flight marker.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		inFlight := false
		attestor.deferred.Range(func(any, any) bool { inFlight = true; return false })
		if !inFlight {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	stubMu.Lock()
	defer stubMu.Unlock()
	if len(*deleted) != 1 || (*deleted)[0] != older.Digest.String() {
		t.Fatalf("deleted = %v, want the older attestation", *deleted)
	}
}

// A list that keeps naming a manifest the registry no longer serves is a stale list.
func TestCollapseAcceptsDeletedManifestsStillListed(t *testing.T) {
	started := time.Now()
	older := scaiReferrer(t, 'a', started.Add(-24*time.Hour))
	fresh := scaiReferrer(t, 'b', started)
	stubRegistry(t, [][]v1.Descriptor{{older, fresh}}, func(string) bool { return false })

	digest, _ := name.NewDigest("example.com/app@sha256:" + repeatHex('d'))
	if err := collapseReferrers(context.Background(), classicAttestor(t), digest, scaiPredicate, true, started); err != nil {
		t.Fatalf("stale list reported as failure: %v", err)
	}
}

func TestCollapseReportsManifestsThatSurviveDelete(t *testing.T) {
	started := time.Now()
	older := scaiReferrer(t, 'a', started.Add(-24*time.Hour))
	fresh := scaiReferrer(t, 'b', started)
	stubRegistry(t, [][]v1.Descriptor{{older, fresh}}, func(string) bool { return true })

	digest, _ := name.NewDigest("example.com/app@sha256:" + repeatHex('d'))
	if err := collapseReferrers(context.Background(), classicAttestor(t), digest, scaiPredicate, true, started); err == nil {
		t.Fatal("expected an error when the manifest is still served")
	}
}

func TestAttestSBOMDeletesPreviousSameKind(t *testing.T) {
	fakeBinDir := writeFakeCosign(t, "#!/bin/sh\nexit 0\n")
	t.Setenv("PATH", fakeBinDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	cleaner := &recordingCleaner{}
	attestor := testAttestor(t)
	attestor.cleaner = cleaner

	imageRef := "example.com/app@sha256:" + repeatHex('a')
	if err := attestor.AttestSBOM(context.Background(), imageRef, testSBOM(t)); err != nil {
		t.Fatalf("AttestSBOM: %v", err)
	}
	if len(cleaner.calls) != 2 || cleaner.calls[0].predicate != "https://cyclonedx.org/bom" || !cleaner.calls[0].keepNewest {
		t.Fatalf("first collapse = %#v", cleaner.calls)
	}
	if cleaner.calls[1].predicate != predicateCosignSign || cleaner.calls[1].keepNewest {
		t.Fatalf("sign collapse = %#v", cleaner.calls[1])
	}
}

func TestAttestInSharedRepositoryKeepsSignatures(t *testing.T) {
	fakeBinDir := writeFakeCosign(t, "#!/bin/sh\nexit 0\n")
	t.Setenv("PATH", fakeBinDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	cleaner := &recordingCleaner{}
	attestor := testAttestor(t)
	attestor.cleaner = cleaner
	attestor.SetSharedRepositories(func(repository string) bool { return repository == "ci.example.com/app" })

	imageRef := "ci.example.com/app@sha256:" + repeatHex('a')
	if err := attestor.AttestSBOM(context.Background(), imageRef, testSBOM(t)); err != nil {
		t.Fatalf("AttestSBOM: %v", err)
	}
	if len(cleaner.calls) != 1 || cleaner.calls[0].predicate != "https://cyclonedx.org/bom" {
		t.Fatalf("shared repository collapses = %#v, want only the same kind", cleaner.calls)
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
	if len(cleaner.calls) != 0 {
		t.Fatalf("cleanup ran for a tag ref: %#v", cleaner.calls)
	}
}

func TestAttestSBOMStillAttestsWhenListingFails(t *testing.T) {
	fakeBinDir := writeFakeCosign(t, "#!/bin/sh\nexit 0\n")
	t.Setenv("PATH", fakeBinDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	cleaner := &recordingCleaner{err: os.ErrClosed}
	attestor := testAttestor(t)
	attestor.cleaner = cleaner
	imageRef := "example.com/app@sha256:" + repeatHex('c')
	if err := attestor.AttestSBOM(context.Background(), imageRef, testSBOM(t)); err != nil {
		t.Fatalf("AttestSBOM: %v", err)
	}
	if len(cleaner.calls) != 2 {
		t.Fatalf("calls = %#v", cleaner.calls)
	}
}

func TestAttestSBOMSkipsCleanupWhenCosignFails(t *testing.T) {
	fakeBinDir := writeFakeCosign(t, "#!/bin/sh\nexit 1\n")
	t.Setenv("PATH", fakeBinDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	cleaner := &recordingCleaner{}
	attestor := testAttestor(t)
	attestor.cleaner = cleaner
	imageRef := "example.com/app@sha256:" + repeatHex('b')
	if err := attestor.AttestSBOM(context.Background(), imageRef, testSBOM(t)); err == nil {
		t.Fatal("expected cosign failure")
	}
	if len(cleaner.calls) != 0 {
		t.Fatalf("collapsed after a failed attest: %#v", cleaner.calls)
	}
}

type collapseCall struct {
	predicate  string
	keepNewest bool
	since      time.Time
}

type recordingCleaner struct {
	calls []collapseCall
	err   error
}

func (r *recordingCleaner) collapse(_ context.Context, _ name.Digest, predicate string, keepNewest bool, since time.Time) error {
	r.calls = append(r.calls, collapseCall{predicate: predicate, keepNewest: keepNewest, since: since})
	return r.err
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

type blockingCleaner struct {
	release chan struct{}
	done    chan string
}

func (b *blockingCleaner) collapse(_ context.Context, _ name.Digest, predicate string, _ bool, _ time.Time) error {
	<-b.release
	b.done <- predicate
	return nil
}

// Cleanup waits for the registry to list the new attestation; the attest call,
// and the scan waiting on it, must not.
func TestAttestDoesNotWaitForCleanup(t *testing.T) {
	fakeBinDir := writeFakeCosign(t, "#!/bin/sh\nexit 0\n")
	t.Setenv("PATH", fakeBinDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	cleaner := &blockingCleaner{release: make(chan struct{}), done: make(chan string, 4)}
	attestor := testAttestor(t)
	attestor.inlineCleanup = false
	attestor.cleaner = cleaner

	imageRef := "example.com/app@sha256:" + repeatHex('a')
	returned := make(chan error, 1)
	go func() { returned <- attestor.AttestSBOM(context.Background(), imageRef, testSBOM(t)) }()
	select {
	case err := <-returned:
		if err != nil {
			t.Fatalf("AttestSBOM: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("AttestSBOM waited for cleanup")
	}

	close(cleaner.release)
	select {
	case predicate := <-cleaner.done:
		if predicate != "https://cyclonedx.org/bom" {
			t.Fatalf("first background collapse = %s", predicate)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("cleanup never ran")
	}
}
