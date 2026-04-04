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

func TestInventoryBufferFlushAndRequeue(t *testing.T) {
	buffer := newInventoryBuffer()

	buffer.Add(clusterImageInput{Namespace: "ns", ImageRef: "nginx", Tag: "1.25", Digest: "sha256:a"})
	buffer.Add(clusterImageInput{Namespace: "ns", ImageRef: "nginx", Tag: "1.25", Digest: "sha256:a"})
	buffer.Add(clusterImageInput{Namespace: "ns", ImageRef: "busybox", Tag: "1.36", Digest: ""})

	first := buffer.Flush()
	if len(first) != 2 {
		t.Fatalf("expected 2 unique images, got %d", len(first))
	}

	second := buffer.Flush()
	if len(second) != 0 {
		t.Fatalf("expected empty second flush, got %d", len(second))
	}

	buffer.Requeue(first)
	third := buffer.Flush()
	if len(third) != 2 {
		t.Fatalf("expected 2 images after requeue, got %d", len(third))
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

	collectPodObservation(pod, excluded, buffer)
	got := buffer.Flush()
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

	collectEventObservation(event, excluded, buffer)
	got := buffer.Flush()
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
	collectEventObservation(nonPod, excluded, buffer)

	unknownReason := &corev1.Event{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ci"},
		InvolvedObject: corev1.ObjectReference{
			Kind: "Pod",
		},
		Reason:  "Scheduled",
		Message: "Pulling image \"alpine:3.20\"",
	}
	collectEventObservation(unknownReason, excluded, buffer)

	if got := buffer.Flush(); len(got) != 0 {
		t.Fatalf("expected no observations, got %d", len(got))
	}
}
