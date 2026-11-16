package main

import (
	"reflect"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func digests(images []clusterImageInput) []string {
	out := make([]string, 0, len(images))
	for _, img := range images {
		out = append(out, img.Digest)
	}
	return out
}

// hetzner-1, 2026-11-16: the cortex memcached StatefulSets rolled from
// sha256:old to sha256:new. Managed pods are read from the watch cache, so the
// old digest leaves the snapshot as soon as its last pod is gone.
func TestManagedPodImagesFollowLivePods(t *testing.T) {
	before := []*corev1.Pod{
		ptr(ownedPod("blocks-0", "StatefulSet", "cortex-memcached-blocks", nil, "sha256:old")),
		ptr(ownedPod("blocks-1", "StatefulSet", "cortex-memcached-blocks", nil, "sha256:old")),
	}
	if got := digests(managedPodImages(before, nil)); !reflect.DeepEqual(got, []string{"sha256:old"}) {
		t.Fatalf("before rollout = %v", got)
	}

	// Mid-rollout both digests run.
	during := []*corev1.Pod{
		ptr(ownedPod("blocks-0", "StatefulSet", "cortex-memcached-blocks", nil, "sha256:new")),
		before[1],
	}
	if got := digests(managedPodImages(during, nil)); !reflect.DeepEqual(got, []string{"sha256:new", "sha256:old"}) {
		t.Fatalf("during rollout = %v", got)
	}

	after := []*corev1.Pod{
		during[0],
		ptr(ownedPod("blocks-1", "StatefulSet", "cortex-memcached-blocks", nil, "sha256:new")),
	}
	if got := digests(managedPodImages(after, nil)); !reflect.DeepEqual(got, []string{"sha256:new"}) {
		t.Fatalf("after rollout = %v", got)
	}
}

func TestManagedPodImagesSkipsUnmanagedAndFinishedPods(t *testing.T) {
	evicted := ownedPod("api-1", "ReplicaSet", "api-7d4b9c", map[string]string{"pod-template-hash": "7d4b9c"}, "sha256:evicted")
	evicted.Status.Phase = corev1.PodFailed
	excluded := ownedPod("dns-0", "DaemonSet", "dns", nil, "sha256:excluded")
	excluded.Namespace = "kube-system"
	pods := []*corev1.Pod{
		ptr(ownedPod("api-2", "ReplicaSet", "api-7d4b9c", map[string]string{"pod-template-hash": "7d4b9c"}, "sha256:live")),
		&evicted,
		&excluded,
		ptr(ownedPod("debug", "", "", nil, "sha256:bare")),
		jobPod("backup", "alpine:3.20", corev1.PodRunning, time.Time{}),
	}

	got := managedPodImages(pods, map[string]bool{"kube-system": true})
	if len(got) != 1 || got[0].Digest != "sha256:live" || !reflect.DeepEqual(got[0].Workloads, []string{"Deployment/api"}) {
		t.Fatalf("managed images = %+v, want only the live Deployment pod", got)
	}
}

// Managed pods are not buffered; bare pods still are, so ad-hoc runs stay
// visible for IMAGE_STALE_AFTER after they end.
func TestCollectPodObservationBuffersOnlyUnmanagedPods(t *testing.T) {
	buffer := newInventoryBuffer()
	sts := ownedPod("cache-0", "StatefulSet", "cache", nil, "sha256:sts")
	if collectPodObservation(&sts, nil, buffer, time.Hour) {
		t.Fatal("managed pod was buffered")
	}
	bare := ownedPod("debug", "", "", nil, "sha256:bare")
	if !collectPodObservation(&bare, nil, buffer, time.Hour) {
		t.Fatal("bare pod was not buffered")
	}
	if got := digests(buffer.Snapshot()); !reflect.DeepEqual(got, []string{"sha256:bare"}) {
		t.Fatalf("buffer = %v", got)
	}
}

func TestPodImageSignatureChangesOnlyWithImages(t *testing.T) {
	pod := ownedPod("cache-0", "StatefulSet", "cache", nil, "sha256:a")
	statusOnly := pod
	statusOnly.Status.Conditions = []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}
	if podImageSignature(&pod) != podImageSignature(&statusOnly) {
		t.Fatal("status-only update changed the signature")
	}

	newDigest := ownedPod("cache-0", "StatefulSet", "cache", nil, "sha256:b")
	if podImageSignature(&pod) == podImageSignature(&newDigest) {
		t.Fatal("digest change kept the signature")
	}

	finished := pod
	finished.Status.Phase = corev1.PodFailed
	if podImageSignature(&finished) != "" {
		t.Fatal("finished pod still contributes images")
	}
	bare := ownedPod("debug", "", "", nil, "sha256:a")
	if podImageSignature(&bare) != "" {
		t.Fatal("bare pod has a managed signature")
	}
}

// After a restart the agent replays recent pull events. Each image ages from
// its event time, so an event older than IMAGE_STALE_AFTER is dropped at the
// next sweep instead of being reported for another full TTL.
func TestReplayedEventsAgeFromEventTime(t *testing.T) {
	const ttl = time.Hour
	now := time.Now().UTC()
	buffer := newInventoryBuffer()
	buffer.MarkRefreshed(now)

	pull := func(image string, at time.Time) *corev1.Event {
		return &corev1.Event{
			ObjectMeta:     metav1.ObjectMeta{Namespace: "ci"},
			InvolvedObject: corev1.ObjectReference{Kind: "Pod"},
			Reason:         "Pulling",
			Message:        "Pulling image \"" + image + "\"",
			LastTimestamp:  metav1.NewTime(at),
		}
	}
	minObservedAt := now.Add(-ttl)
	if !collectEventObservation(pull("alpine:3.20", now.Add(-50*time.Minute)), nil, buffer, minObservedAt, testLogger()) {
		t.Fatal("recent event before start was not replayed")
	}
	if collectEventObservation(pull("busybox:1.37", now.Add(-70*time.Minute)), nil, buffer, minObservedAt, testLogger()) {
		t.Fatal("event older than the TTL was replayed")
	}

	// Twenty minutes later the replayed image has passed its TTL.
	if !buffer.EvictStale(ttl, now.Add(20*time.Minute)) {
		t.Fatal("replayed image did not age from its event time")
	}
	if len(buffer.Snapshot()) != 0 {
		t.Fatalf("buffer = %+v, want empty", buffer.Snapshot())
	}
}

func ptr(pod corev1.Pod) *corev1.Pod { return &pod }
