package main

import (
	"io"
	"log/slog"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestParseDurationEnv(t *testing.T) {
	logger := testLogger()
	fallback := 30 * time.Second

	t.Run("unset uses fallback", func(t *testing.T) {
		t.Setenv("WATCH_FLUSH_INTERVAL", "")
		got := parseDurationEnv("WATCH_FLUSH_INTERVAL", fallback, logger)
		if got != fallback {
			t.Fatalf("expected fallback %v, got %v", fallback, got)
		}
	})

	t.Run("valid duration", func(t *testing.T) {
		t.Setenv("WATCH_FLUSH_INTERVAL", "15s")
		got := parseDurationEnv("WATCH_FLUSH_INTERVAL", fallback, logger)
		if got != 15*time.Second {
			t.Fatalf("expected 15s, got %v", got)
		}
	})

	t.Run("invalid duration uses fallback", func(t *testing.T) {
		t.Setenv("WATCH_FLUSH_INTERVAL", "nope")
		got := parseDurationEnv("WATCH_FLUSH_INTERVAL", fallback, logger)
		if got != fallback {
			t.Fatalf("expected fallback %v, got %v", fallback, got)
		}
	})
}

func TestInventoryBufferAddAndSnapshot(t *testing.T) {
	buffer := newInventoryBuffer()

	img1 := clusterImageInput{Namespace: "ns", ImageRef: "nginx", Tag: "1.25", Digest: "sha256:a"}
	img2 := clusterImageInput{Namespace: "ns", ImageRef: "busybox", Tag: "1.36", Digest: ""}

	if !buffer.Add(img1) {
		t.Fatalf("expected first add to be a change")
	}
	if buffer.Add(img1) {
		t.Fatalf("expected duplicate add to not be a change")
	}
	if !buffer.Add(img2) {
		t.Fatalf("expected second unique add to be a change")
	}

	got := buffer.Snapshot()
	if len(got) != 2 {
		t.Fatalf("expected 2 unique images, got %d", len(got))
	}
}

func TestInventoryBufferSnapshotPrefersDigestEntries(t *testing.T) {
	buffer := newInventoryBuffer()

	withoutDigest := clusterImageInput{Namespace: "staging", ImageRef: "hostingmaloonde/curlimages_curl", Tag: "8.16.0", Digest: ""}
	withDigestA := clusterImageInput{Namespace: "staging", ImageRef: "hostingmaloonde/curlimages_curl", Tag: "8.16.0", Digest: "sha256:a"}
	withDigestB := clusterImageInput{Namespace: "staging", ImageRef: "hostingmaloonde/curlimages_curl", Tag: "8.16.0", Digest: "sha256:b"}

	buffer.Add(withoutDigest)
	buffer.Add(withDigestA)
	buffer.Add(withDigestB)

	got := buffer.Snapshot()
	if len(got) != 2 {
		t.Fatalf("expected 2 digest-bearing entries, got %d", len(got))
	}

	seen := make(map[string]bool)
	for _, img := range got {
		seen[img.Namespace+"|"+img.ImageRef+"|"+img.Tag+"|"+img.Digest] = true
	}

	if seen["staging|hostingmaloonde/curlimages_curl|8.16.0|"] {
		t.Fatalf("did not expect digest-less entry when digest entries exist")
	}
	if !seen["staging|hostingmaloonde/curlimages_curl|8.16.0|sha256:a"] {
		t.Fatalf("missing digest entry sha256:a")
	}
	if !seen["staging|hostingmaloonde/curlimages_curl|8.16.0|sha256:b"] {
		t.Fatalf("missing digest entry sha256:b")
	}
}

func TestInventoryBufferKeepsDifferentTagsWithoutDigest(t *testing.T) {
	buffer := newInventoryBuffer()

	if !buffer.Add(clusterImageInput{Namespace: "ns", ImageRef: "nginx", Tag: "1.25", Digest: ""}) {
		t.Fatalf("expected first tag add to change buffer")
	}
	if !buffer.Add(clusterImageInput{Namespace: "ns", ImageRef: "nginx", Tag: "1.26", Digest: ""}) {
		t.Fatalf("expected second tag add to change buffer")
	}

	got := buffer.Snapshot()
	if len(got) != 2 {
		t.Fatalf("expected 2 entries for distinct tags, got %d", len(got))
	}
}

func TestInventoryBufferTouchAll(t *testing.T) {
	buffer := newInventoryBuffer()

	img1 := clusterImageInput{Namespace: "ns", ImageRef: "nginx", Tag: "1.25", Digest: "sha256:a"}
	img2 := clusterImageInput{Namespace: "ns", ImageRef: "redis", Tag: "7", Digest: "sha256:r"}

	// TouchAll with two new images should report changed.
	if !buffer.TouchAll([]clusterImageInput{img1, img2}) {
		t.Fatalf("expected TouchAll with new images to report changed")
	}
	if len(buffer.Snapshot()) != 2 {
		t.Fatalf("expected 2 images after TouchAll")
	}

	// TouchAll with the same images should not report changed.
	if buffer.TouchAll([]clusterImageInput{img1, img2}) {
		t.Fatalf("expected TouchAll with same images to not report changed")
	}

	// TouchAll with a subset updates timestamps but does not remove the missing entry.
	if buffer.TouchAll([]clusterImageInput{img1}) {
		t.Fatalf("expected TouchAll subset to not report changed (no new images)")
	}
	if len(buffer.Snapshot()) != 2 {
		t.Fatalf("expected both images still present after partial TouchAll")
	}

	// TouchAll with a tag-enriching entry should report changed.
	noTag := clusterImageInput{Namespace: "ns", ImageRef: "extra", Tag: "", Digest: "sha256:e"}
	buffer.Add(noTag)
	withTag := clusterImageInput{Namespace: "ns", ImageRef: "extra", Tag: "latest", Digest: "sha256:e"}
	if !buffer.TouchAll([]clusterImageInput{withTag}) {
		t.Fatalf("expected TouchAll with tag enrichment to report changed")
	}
}

func TestInventoryBufferEvict(t *testing.T) {
	buffer := newInventoryBuffer()

	img := clusterImageInput{Namespace: "ns", ImageRef: "nginx", Tag: "1.25", Digest: "sha256:a"}
	buffer.Add(img)

	// Evict with a long TTL should not remove anything.
	if buffer.Evict(24 * time.Hour) {
		t.Fatalf("expected Evict with long TTL to not remove anything")
	}
	if len(buffer.Snapshot()) != 1 {
		t.Fatalf("expected image still present after no-op eviction")
	}

	// Evict after the TTL has elapsed should remove the entry.
	time.Sleep(2 * time.Millisecond)
	if !buffer.Evict(1 * time.Millisecond) {
		t.Fatalf("expected Evict to remove stale entry")
	}
	if len(buffer.Snapshot()) != 0 {
		t.Fatalf("expected empty buffer after eviction")
	}
}

func TestInventoryBufferEvictReportsChangeOnlyWhenRemoved(t *testing.T) {
	buffer := newInventoryBuffer()

	img1 := clusterImageInput{Namespace: "ns", ImageRef: "nginx", Tag: "1.25", Digest: "sha256:a"}
	img2 := clusterImageInput{Namespace: "ns", ImageRef: "redis", Tag: "7", Digest: "sha256:r"}
	buffer.Add(img1)
	time.Sleep(2 * time.Millisecond)
	// Touch img2 more recently.
	buffer.Add(img2)

	// Evict with 1ms TTL: img1 is stale, img2 is fresh.
	if !buffer.Evict(1 * time.Millisecond) {
		t.Fatalf("expected Evict to remove img1")
	}
	got := buffer.Snapshot()
	if len(got) != 1 {
		t.Fatalf("expected 1 image remaining after partial eviction, got %d", len(got))
	}
	if got[0].ImageRef != "redis" {
		t.Fatalf("expected redis to remain, got %s", got[0].ImageRef)
	}
}

func TestCollectPodObservationIncludesAllContainerKinds(t *testing.T) {
	buffer := newInventoryBuffer()
	excluded := map[string]bool{}

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ci"},
		Spec: corev1.PodSpec{
			InitContainers: []corev1.Container{
				{Name: "init", Image: "busybox:1.36"},
			},
			Containers: []corev1.Container{
				{Name: "app", Image: "ghcr.io/acme/app:2.0"},
			},
			EphemeralContainers: []corev1.EphemeralContainer{
				{EphemeralContainerCommon: corev1.EphemeralContainerCommon{Name: "debug", Image: "alpine:3.20"}},
			},
		},
	}

	changed := collectPodObservation(pod, excluded, buffer)
	if !changed {
		t.Fatalf("expected pod observation to report change")
	}

	got := buffer.Snapshot()
	if len(got) != 3 {
		t.Fatalf("expected 3 observed images, got %d", len(got))
	}

	seen := make(map[string]bool)
	for _, img := range got {
		seen[img.Namespace+"|"+img.ImageRef+"|"+img.Tag] = true
	}

	if !seen["ci|busybox|1.36"] {
		t.Fatalf("missing init container observation")
	}
	if !seen["ci|ghcr.io/acme/app|2.0"] {
		t.Fatalf("missing app container observation")
	}
	if !seen["ci|alpine|3.20"] {
		t.Fatalf("missing ephemeral container observation")
	}

	// No status set → no digests expected.
	for _, img := range got {
		if img.Digest != "" {
			t.Fatalf("expected no digest without status, got %q for %s", img.Digest, img.ImageRef)
		}
	}
}

func TestCollectPodObservationExtractsRuntimeDigests(t *testing.T) {
	buffer := newInventoryBuffer()
	excluded := map[string]bool{}

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "prod"},
		Spec: corev1.PodSpec{
			InitContainers: []corev1.Container{
				{Name: "init", Image: "docker.io/hostingmaloonde/falcosecurity_falco-driver-loader:0.41.3"},
			},
			Containers: []corev1.Container{
				{Name: "app", Image: "docker.io/hostingmaloonde/falcosecurity_falco:0.41.3"},
			},
		},
		Status: corev1.PodStatus{
			InitContainerStatuses: []corev1.ContainerStatus{
				{
					Name:    "init",
					Image:   "docker.io/hostingmaloonde/falcosecurity_falco-driver-loader:0.41.3",
					ImageID: "docker.io/hostingmaloonde/falcosecurity_falco-driver-loader@sha256:b96987181cc42a2b",
				},
			},
			ContainerStatuses: []corev1.ContainerStatus{
				{
					Name:    "app",
					Image:   "docker.io/hostingmaloonde/falcosecurity_falco:0.41.3",
					ImageID: "docker.io/hostingmaloonde/falcosecurity_falco@sha256:a8aca039f2b19e9c",
				},
			},
		},
	}

	changed := collectPodObservation(pod, excluded, buffer)
	if !changed {
		t.Fatalf("expected pod observation to report change")
	}

	got := buffer.Snapshot()
	if len(got) != 2 {
		t.Fatalf("expected 2 observed images, got %d", len(got))
	}

	seen := make(map[string]string) // imageRef → digest
	for _, img := range got {
		seen[img.ImageRef] = img.Digest
	}

	if d := seen["docker.io/hostingmaloonde/falcosecurity_falco"]; d != "sha256:a8aca039f2b19e9c" {
		t.Fatalf("expected runtime digest for app container, got %q", d)
	}
	if d := seen["docker.io/hostingmaloonde/falcosecurity_falco-driver-loader"]; d != "sha256:b96987181cc42a2b" {
		t.Fatalf("expected runtime digest for init container, got %q", d)
	}
}

func TestCollectPodObservationDiscardsRedirectedDigests(t *testing.T) {
	buffer := newInventoryBuffer()
	excluded := map[string]bool{}

	// Simulate a pod where containerd redirected the mirror to the upstream registry.
	// The spec says hostingmaloonde/..., but the runtime resolved to falcosecurity/...
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "prod"},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{Name: "app", Image: "docker.io/hostingmaloonde/falcosecurity_falco:0.41.3"},
			},
		},
		Status: corev1.PodStatus{
			ContainerStatuses: []corev1.ContainerStatus{
				{
					Name:    "app",
					Image:   "docker.io/falcosecurity/falco:0.41.3",
					ImageID: "docker.io/falcosecurity/falco@sha256:5f6f325327c9704",
				},
			},
		},
	}

	changed := collectPodObservation(pod, excluded, buffer)
	if !changed {
		t.Fatalf("expected pod observation to report change")
	}

	got := buffer.Snapshot()
	if len(got) != 1 {
		t.Fatalf("expected 1 observed image, got %d", len(got))
	}

	// The digest should be empty because the imageID repo (falcosecurity/falco)
	// doesn't match the spec imageRef (hostingmaloonde/falcosecurity_falco).
	if got[0].Digest != "" {
		t.Fatalf("expected empty digest for redirected imageID, got %q", got[0].Digest)
	}
	if got[0].ImageRef != "docker.io/hostingmaloonde/falcosecurity_falco" {
		t.Fatalf("expected spec imageRef, got %q", got[0].ImageRef)
	}
	if got[0].Tag != "0.41.3" {
		t.Fatalf("expected tag 0.41.3, got %q", got[0].Tag)
	}
}

func TestCollectEventObservationPullingImage(t *testing.T) {
	buffer := newInventoryBuffer()
	excluded := map[string]bool{}

	event := &corev1.Event{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ci"},
		InvolvedObject: corev1.ObjectReference{
			Kind: "Pod",
			Name: "runner-abc",
		},
		Reason:  "Pulling",
		Message: "Pulling image \"ghcr.io/example/runner:1.2.3\"",
	}

	if changed := collectEventObservation(event, excluded, buffer, time.Time{}, testLogger()); !changed {
		t.Fatalf("expected event observation to report change")
	}

	got := buffer.Snapshot()
	if len(got) != 1 {
		t.Fatalf("expected 1 observed event image, got %d", len(got))
	}
	if got[0].Namespace != "ci" || got[0].ImageRef != "ghcr.io/example/runner" || got[0].Tag != "1.2.3" {
		t.Fatalf("unexpected event observation: %+v", got[0])
	}
}

func TestCollectEventObservationIgnoresNonPodAndUnknownReason(t *testing.T) {
	buffer := newInventoryBuffer()
	excluded := map[string]bool{}

	nonPod := &corev1.Event{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ci"},
		InvolvedObject: corev1.ObjectReference{
			Kind: "Node",
		},
		Reason:  "Pulling",
		Message: "Pulling image \"alpine:3.20\"",
	}
	if changed := collectEventObservation(nonPod, excluded, buffer, time.Time{}, testLogger()); changed {
		t.Fatalf("expected non-pod event to not change buffer")
	}

	unknownReason := &corev1.Event{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ci"},
		InvolvedObject: corev1.ObjectReference{
			Kind: "Pod",
		},
		Reason:  "Scheduled",
		Message: "Pulling image \"alpine:3.20\"",
	}
	if changed := collectEventObservation(unknownReason, excluded, buffer, time.Time{}, testLogger()); changed {
		t.Fatalf("expected unknown reason event to not change buffer")
	}

	// Created/Started events contain container names, not image refs.
	// "Created container: scan" would parse "container:" as an image ref.
	createdEvent := &corev1.Event{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ci"},
		InvolvedObject: corev1.ObjectReference{
			Kind: "Pod",
		},
		Reason:  "Created",
		Message: "Created container: scan",
	}
	if changed := collectEventObservation(createdEvent, excluded, buffer, time.Time{}, testLogger()); changed {
		t.Fatalf("expected Created event to not change buffer")
	}

	startedEvent := &corev1.Event{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ci"},
		InvolvedObject: corev1.ObjectReference{
			Kind: "Pod",
		},
		Reason:  "Started",
		Message: "Started container scan",
	}
	if changed := collectEventObservation(startedEvent, excluded, buffer, time.Time{}, testLogger()); changed {
		t.Fatalf("expected Started event to not change buffer")
	}

	if got := buffer.Snapshot(); len(got) != 0 {
		t.Fatalf("expected no observations, got %d", len(got))
	}
}

func TestCollectEventObservationIgnoresStaleEvents(t *testing.T) {
	buffer := newInventoryBuffer()
	excluded := map[string]bool{}
	startedAt := time.Date(2026, time.January, 2, 15, 0, 0, 0, time.UTC)

	stale := &corev1.Event{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ci"},
		InvolvedObject: corev1.ObjectReference{
			Kind: "Pod",
		},
		Reason:        "Pulling",
		Message:       "Pulling image \"alpine:3.20\"",
		LastTimestamp: metav1.NewTime(startedAt.Add(-1 * time.Minute)),
	}

	if changed := collectEventObservation(stale, excluded, buffer, startedAt, testLogger()); changed {
		t.Fatalf("expected stale event to not change buffer")
	}

	fresh := &corev1.Event{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ci"},
		InvolvedObject: corev1.ObjectReference{
			Kind: "Pod",
		},
		Reason:        "Pulling",
		Message:       "Pulling image \"alpine:3.20\"",
		LastTimestamp: metav1.NewTime(startedAt.Add(1 * time.Minute)),
	}

	if changed := collectEventObservation(fresh, excluded, buffer, startedAt, testLogger()); !changed {
		t.Fatalf("expected fresh event to change buffer")
	}

	if got := buffer.Snapshot(); len(got) != 1 {
		t.Fatalf("expected one observed image from fresh event, got %d", len(got))
	}
}
