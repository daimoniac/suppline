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

func TestInventoryBufferSnapshotAndReplace(t *testing.T) {
	buffer := newInventoryBuffer()

	if !buffer.Add(clusterImageInput{Namespace: "ns", ImageRef: "nginx", Tag: "1.25", Digest: "sha256:a"}) {
		t.Fatalf("expected first add to be a change")
	}
	if buffer.Add(clusterImageInput{Namespace: "ns", ImageRef: "nginx", Tag: "1.25", Digest: "sha256:a"}) {
		t.Fatalf("expected duplicate add to not be a change")
	}
	if !buffer.Add(clusterImageInput{Namespace: "ns", ImageRef: "busybox", Tag: "1.36", Digest: ""}) {
		t.Fatalf("expected second unique add to be a change")
	}

	first := buffer.Snapshot()
	if len(first) != 2 {
		t.Fatalf("expected 2 unique images, got %d", len(first))
	}

	if changed := buffer.Replace(first); changed {
		t.Fatalf("expected replace with same snapshot to report unchanged")
	}

	updated := append(first, clusterImageInput{Namespace: "ns", ImageRef: "redis", Tag: "7", Digest: "sha256:r"})
	if changed := buffer.Replace(updated); !changed {
		t.Fatalf("expected replace with new data to report changed")
	}

	third := buffer.Snapshot()
	if len(third) != 3 {
		t.Fatalf("expected 3 images after replace, got %d", len(third))
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
		Status: corev1.PodStatus{
			InitContainerStatuses: []corev1.ContainerStatus{{Name: "init", ImageID: "containerd://sha256:initdigest"}},
			ContainerStatuses:     []corev1.ContainerStatus{{Name: "app", ImageID: "docker-pullable://ghcr.io/acme/app@sha256:appdigest"}},
			EphemeralContainerStatuses: []corev1.ContainerStatus{{
				Name: "debug", ImageID: "cri-o://sha256:debugdigest",
			}},
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
		seen[img.Namespace+"|"+img.ImageRef+"|"+img.Digest] = true
	}

	if !seen["ci|busybox|sha256:initdigest"] {
		t.Fatalf("missing init container observation")
	}
	if !seen["ci|ghcr.io/acme/app|sha256:appdigest"] {
		t.Fatalf("missing app container observation")
	}
	if !seen["ci|alpine|sha256:debugdigest"] {
		t.Fatalf("missing ephemeral container observation")
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

	if changed := collectEventObservation(event, excluded, buffer); !changed {
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
	if changed := collectEventObservation(nonPod, excluded, buffer); changed {
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
	if changed := collectEventObservation(unknownReason, excluded, buffer); changed {
		t.Fatalf("expected unknown reason event to not change buffer")
	}

	if got := buffer.Snapshot(); len(got) != 0 {
		t.Fatalf("expected no observations, got %d", len(got))
	}
}
