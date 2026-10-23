package main

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
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

	changed := collectPodObservation(pod, excluded, buffer, time.Hour)
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

	changed := collectPodObservation(pod, excluded, buffer, time.Hour)
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

	changed := collectPodObservation(pod, excluded, buffer, time.Hour)
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

func TestExtractImageFromEventMessageVariants(t *testing.T) {
	tests := []struct {
		name    string
		message string
		want    string
	}{
		{
			name:    "pulling quoted",
			message: "Pulling image \"ghcr.io/example/runner:1.2.3\"",
			want:    "ghcr.io/example/runner:1.2.3",
		},
		{
			name:    "failed to pull and unpack image",
			message: "Failed to pull and unpack image \"docker.io/library/alpine:3.20\": failed to resolve reference",
			want:    "docker.io/library/alpine:3.20",
		},
		{
			name:    "failed to resolve reference",
			message: "rpc error: code = Unknown desc = failed to resolve reference ghcr.io/org/app:2.4.1: not found",
			want:    "ghcr.io/org/app:2.4.1",
		},
		{
			name:    "ignore non image text",
			message: "Created container: scan",
			want:    "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractImageFromEventMessage(tt.message)
			if got != tt.want {
				t.Fatalf("extractImageFromEventMessage(%q) = %q, want %q", tt.message, got, tt.want)
			}
		})
	}
}

func TestCollectWorkloadImagesIncludesReplicaSets(t *testing.T) {
	client := fake.NewSimpleClientset(
		&appsv1.ReplicaSet{
			ObjectMeta: metav1.ObjectMeta{Name: "rs-one", Namespace: "apps"},
			Spec: appsv1.ReplicaSetSpec{
				Template: corev1.PodTemplateSpec{
					Spec: corev1.PodSpec{
						Containers: []corev1.Container{{Name: "app", Image: "ghcr.io/example/kaniko-executor:v1.23.0"}},
					},
				},
			},
		},
		&appsv1.ReplicaSet{
			ObjectMeta: metav1.ObjectMeta{Name: "rs-excluded", Namespace: "kube-system"},
			Spec: appsv1.ReplicaSetSpec{
				Template: corev1.PodTemplateSpec{
					Spec: corev1.PodSpec{
						Containers: []corev1.Container{{Name: "skip", Image: "docker.io/library/busybox:1.36"}},
					},
				},
			},
		},
	)

	excluded := map[string]bool{"kube-system": true}
	images, expired, err := collectWorkloadImages(context.Background(), client, excluded, time.Hour, testLogger())
	if err != nil {
		t.Fatalf("collectWorkloadImages returned error: %v", err)
	}
	if len(expired) != 0 {
		t.Fatalf("expected no expired workload images, got %d", len(expired))
	}

	found := false
	for _, img := range images {
		if img.Namespace == "apps" && img.ImageRef == "ghcr.io/example/kaniko-executor" && img.Tag == "v1.23.0" {
			found = true
		}
		if img.Namespace == "kube-system" {
			t.Fatalf("did not expect images from excluded namespace, got %+v", img)
		}
	}

	if !found {
		t.Fatalf("expected ReplicaSet image to be collected")
	}
}

func TestCompletedWorkloadRetentionDefault(t *testing.T) {
	t.Setenv("COMPLETED_WORKLOAD_RETENTION", "")
	got := completedWorkloadRetention(testLogger())
	if got != 60*time.Minute {
		t.Fatalf("expected default retention 60m, got %v", got)
	}
}

func TestCollectWorkloadImagesAppliesCompletedRetention(t *testing.T) {
	const retention = 60 * time.Minute
	client := fake.NewSimpleClientset(
		testJob("active", "jobs", "ghcr.io/example/active-job:1", "", 0),
		testJob("recent-complete", "jobs", "ghcr.io/example/recent-complete:1", batchv1.JobComplete, 5*time.Minute),
		testJob("old-complete", "jobs", "ghcr.io/example/old-complete:1", batchv1.JobComplete, 3*time.Hour),
		testJob("recent-failed", "jobs", "ghcr.io/example/recent-failed:1", batchv1.JobFailed, 5*time.Minute),
		testJob("old-failed", "jobs", "ghcr.io/example/old-failed:1", batchv1.JobFailed, 3*time.Hour),
		testJob("excluded-old", "kube-system", "ghcr.io/example/excluded:1", batchv1.JobComplete, 3*time.Hour),
		&batchv1.CronJob{
			ObjectMeta: metav1.ObjectMeta{Name: "nightly", Namespace: "jobs"},
			Spec: batchv1.CronJobSpec{
				Schedule: "0 * * * *",
				JobTemplate: batchv1.JobTemplateSpec{
					Spec: batchv1.JobSpec{
						Template: corev1.PodTemplateSpec{
							Spec: corev1.PodSpec{
								Containers: []corev1.Container{{Name: "work", Image: "ghcr.io/example/cron-template:1"}},
							},
						},
					},
				},
			},
		},
	)

	excluded := map[string]bool{"kube-system": true}
	images, expired, err := collectWorkloadImages(context.Background(), client, excluded, retention, testLogger())
	if err != nil {
		t.Fatalf("collectWorkloadImages returned error: %v", err)
	}

	included := imageIdentitySet(images)
	expiredSet := imageIdentitySet(expired)
	for _, id := range []string{
		"jobs|ghcr.io/example/active-job|1",
		"jobs|ghcr.io/example/recent-complete|1",
		"jobs|ghcr.io/example/recent-failed|1",
		"jobs|ghcr.io/example/cron-template|1",
	} {
		if !included[id] {
			t.Fatalf("expected %s to be included", id)
		}
		if expiredSet[id] {
			t.Fatalf("did not expect %s to be expired", id)
		}
	}
	for _, id := range []string{
		"jobs|ghcr.io/example/old-complete|1",
		"jobs|ghcr.io/example/old-failed|1",
	} {
		if included[id] {
			t.Fatalf("did not expect %s to be included", id)
		}
		if !expiredSet[id] {
			t.Fatalf("expected %s to be expired", id)
		}
	}
	if included["kube-system|ghcr.io/example/excluded|1"] || expiredSet["kube-system|ghcr.io/example/excluded|1"] {
		t.Fatalf("excluded namespace job leaked into inventory: included=%v expired=%v", included, expiredSet)
	}
}

func TestCollectPodObservationAppliesJobPodRetention(t *testing.T) {
	const retention = 60 * time.Minute
	excluded := map[string]bool{}

	cases := []struct {
		name    string
		pod     *corev1.Pod
		wantAdd bool
	}{
		{
			name:    "running job pod",
			pod:     jobPod("running", "ghcr.io/example/active-job:1", corev1.PodRunning, time.Time{}),
			wantAdd: true,
		},
		{
			name:    "recently succeeded job pod",
			pod:     jobPod("recent-ok", "ghcr.io/example/recent-complete:1", corev1.PodSucceeded, time.Now().Add(-5*time.Minute)),
			wantAdd: true,
		},
		{
			name:    "recently failed job pod",
			pod:     jobPod("recent-fail", "ghcr.io/example/recent-failed:1", corev1.PodFailed, time.Now().Add(-5*time.Minute)),
			wantAdd: true,
		},
		{
			name:    "old succeeded job pod",
			pod:     jobPod("old-ok", "ghcr.io/example/old-complete:1", corev1.PodSucceeded, time.Now().Add(-3*time.Hour)),
			wantAdd: false,
		},
		{
			name:    "old failed job pod",
			pod:     jobPod("old-fail", "ghcr.io/example/old-failed:1", corev1.PodFailed, time.Now().Add(-3*time.Hour)),
			wantAdd: false,
		},
		{
			name: "old succeeded pod not owned by a job",
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{Name: "bare", Namespace: "jobs"},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{{Name: "work", Image: "ghcr.io/example/bare:1"}},
				},
				Status: corev1.PodStatus{Phase: corev1.PodSucceeded},
			},
			wantAdd: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			buffer := newInventoryBuffer()
			changed := collectPodObservation(tc.pod, excluded, buffer, retention)
			if changed != tc.wantAdd {
				t.Fatalf("collectPodObservation changed=%v, want %v", changed, tc.wantAdd)
			}
			got := imageIdentitySet(buffer.Snapshot())
			id := "jobs|" + mustImageIdentity(tc.pod.Spec.Containers[0].Image)
			if tc.wantAdd && !got[id] {
				t.Fatalf("expected buffer to contain %s, got %v", id, got)
			}
			if !tc.wantAdd && len(got) != 0 {
				t.Fatalf("expected expired job pod to leave the buffer empty, got %v", got)
			}
		})
	}
}

func TestRefreshRemovesExpiredJobImagesDespiteStaleTTL(t *testing.T) {
	const (
		retention = 60 * time.Minute
		staleTTL  = 24 * time.Hour
	)
	excluded := map[string]bool{}
	oldImage := clusterImageInput{
		Namespace: "jobs",
		ImageRef:  "ghcr.io/example/old-job",
		Tag:       "1",
		Digest:    "sha256:deadbeef",
	}
	apiImage := clusterImageInput{Namespace: "jobs", ImageRef: "ghcr.io/example/api", Tag: "2"}

	buffer := newInventoryBuffer()
	if !buffer.Add(oldImage) || !buffer.Add(apiImage) {
		t.Fatal("expected seed images to enter the buffer")
	}
	// The pod watcher updates lastSeen when it observes a completed Job pod, so
	// the 24h stale TTL alone keeps the image after the Job has aged out.
	if buffer.Evict(staleTTL) {
		t.Fatal("expected fresh buffer entries to survive the stale TTL")
	}

	oldPod := jobPod("old-pod", "ghcr.io/example/old-job:1", corev1.PodSucceeded, time.Now().Add(-3*time.Hour))
	oldPod.Status.ContainerStatuses[0].ImageID = "ghcr.io/example/old-job@sha256:deadbeef"
	client := fake.NewSimpleClientset(
		testJob("old-complete", "jobs", "ghcr.io/example/old-job:1", batchv1.JobComplete, 3*time.Hour),
		testJob("recent-complete", "jobs", "ghcr.io/example/recent-complete:1", batchv1.JobComplete, 5*time.Minute),
		testJob("active", "jobs", "ghcr.io/example/active-job:1", "", 0),
		oldPod,
		&appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{Name: "api", Namespace: "jobs"},
			Spec: appsv1.DeploymentSpec{
				Template: corev1.PodTemplateSpec{
					Spec: corev1.PodSpec{
						Containers: []corev1.Container{{Name: "api", Image: "ghcr.io/example/api:2"}},
					},
				},
			},
		},
	)

	changed, err := refreshInventoryBuffer(context.Background(), client, excluded, buffer, staleTTL, retention, testLogger())
	if err != nil {
		t.Fatalf("refreshInventoryBuffer returned error: %v", err)
	}
	if !changed {
		t.Fatal("expected refresh to report a change when expired job images are removed")
	}

	got := imageIdentitySet(buffer.Snapshot())
	if got["jobs|ghcr.io/example/old-job|1"] {
		t.Fatal("expected expired job image to be removed from the buffer")
	}
	for _, id := range []string{
		"jobs|ghcr.io/example/api|2",
		"jobs|ghcr.io/example/recent-complete|1",
		"jobs|ghcr.io/example/active-job|1",
	} {
		if !got[id] {
			t.Fatalf("expected live image %s to remain, got %v", id, got)
		}
	}

	if buffer.Add(oldImage) {
		t.Fatal("expected event observation to not resurrect an expired job image")
	}
	if collectPodObservation(oldPod, excluded, buffer, retention) {
		t.Fatal("expected pod watcher to ignore a terminal job pod past retention")
	}
	if imageIdentitySet(buffer.Snapshot())["jobs|ghcr.io/example/old-job|1"] {
		t.Fatal("expired job image returned to the buffer")
	}

	dropped, err := dropExpiredCompletedWorkloads(context.Background(), client, excluded, buffer, retention, testLogger())
	if err != nil {
		t.Fatalf("dropExpiredCompletedWorkloads returned error: %v", err)
	}
	if dropped {
		t.Fatal("expected a second expiry pass to find nothing left to remove")
	}

	rerun := jobPod("rerun", "ghcr.io/example/old-job:1", corev1.PodRunning, time.Time{})
	if !collectPodObservation(rerun, excluded, buffer, retention) {
		t.Fatal("expected a new running job pod to report a previously expired image")
	}
	if !imageIdentitySet(buffer.Snapshot())["jobs|ghcr.io/example/old-job|1"] {
		t.Fatal("expected the running job pod to restore the image")
	}
}

func TestExpiredJobImageKeptWhenStillLive(t *testing.T) {
	const retention = 60 * time.Minute
	excluded := map[string]bool{}
	shared := clusterImageInput{Namespace: "jobs", ImageRef: "ghcr.io/example/shared", Tag: "1", Digest: "sha256:abc"}

	t.Run("deployment", func(t *testing.T) {
		buffer := newInventoryBuffer()
		buffer.Add(shared)
		client := fake.NewSimpleClientset(
			testJob("old-complete", "jobs", "ghcr.io/example/shared:1", batchv1.JobComplete, 3*time.Hour),
			&appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{Name: "api", Namespace: "jobs"},
				Spec: appsv1.DeploymentSpec{
					Template: corev1.PodTemplateSpec{
						Spec: corev1.PodSpec{
							Containers: []corev1.Container{{Name: "api", Image: "ghcr.io/example/shared:1"}},
						},
					},
				},
			},
		)
		if _, err := refreshInventoryBuffer(context.Background(), client, excluded, buffer, 24*time.Hour, retention, testLogger()); err != nil {
			t.Fatalf("refreshInventoryBuffer returned error: %v", err)
		}
		if !imageIdentitySet(buffer.Snapshot())["jobs|ghcr.io/example/shared|1"] {
			t.Fatal("expected image to remain while a Deployment still uses it")
		}
	})

	t.Run("cronjob template", func(t *testing.T) {
		buffer := newInventoryBuffer()
		buffer.Add(shared)
		client := fake.NewSimpleClientset(
			testJob("old-complete", "jobs", "ghcr.io/example/shared:1", batchv1.JobComplete, 3*time.Hour),
			&batchv1.CronJob{
				ObjectMeta: metav1.ObjectMeta{Name: "nightly", Namespace: "jobs"},
				Spec: batchv1.CronJobSpec{
					Schedule: "0 * * * *",
					JobTemplate: batchv1.JobTemplateSpec{
						Spec: batchv1.JobSpec{
							Template: corev1.PodTemplateSpec{
								Spec: corev1.PodSpec{
									Containers: []corev1.Container{{Name: "work", Image: "ghcr.io/example/shared:1"}},
								},
							},
						},
					},
				},
			},
		)
		if _, err := refreshInventoryBuffer(context.Background(), client, excluded, buffer, 24*time.Hour, retention, testLogger()); err != nil {
			t.Fatalf("refreshInventoryBuffer returned error: %v", err)
		}
		if !imageIdentitySet(buffer.Snapshot())["jobs|ghcr.io/example/shared|1"] {
			t.Fatal("expected CronJob template image to remain after the spawned job expires")
		}
	})
}

func imageIdentitySet(images []clusterImageInput) map[string]bool {
	set := make(map[string]bool, len(images))
	for _, img := range images {
		set[imageIdentityKey(img)] = true
	}
	return set
}

func mustImageIdentity(image string) string {
	imageRef, tag, _ := parseImageRef(image, "")
	return imageRef + "|" + tag
}

func testJob(name, namespace, image string, condition batchv1.JobConditionType, completedAgo time.Duration) *batchv1.Job {
	job := &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Spec: batchv1.JobSpec{
			Template: corev1.PodTemplateSpec{
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{{Name: "work", Image: image}},
				},
			},
		},
	}
	if condition == "" {
		job.Status.Active = 1
		return job
	}
	finished := metav1.NewTime(time.Now().Add(-completedAgo))
	job.Status.Conditions = []batchv1.JobCondition{{
		Type:               condition,
		Status:             corev1.ConditionTrue,
		LastTransitionTime: finished,
	}}
	if condition == batchv1.JobComplete {
		job.Status.CompletionTime = &finished
	}
	return job
}

func jobPod(name, image string, phase corev1.PodPhase, finished time.Time) *corev1.Pod {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: "jobs",
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: "batch/v1",
				Kind:       "Job",
				Name:       name,
			}},
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{Name: "work", Image: image}},
		},
		Status: corev1.PodStatus{Phase: phase},
	}
	if !finished.IsZero() {
		pod.Status.ContainerStatuses = []corev1.ContainerStatus{{
			Name: "work",
			State: corev1.ContainerState{
				Terminated: &corev1.ContainerStateTerminated{FinishedAt: metav1.NewTime(finished)},
			},
		}}
	}
	return pod
}
