package main

import (
	"reflect"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func ownedPod(name, kind, owner string, labels map[string]string, imageID string) corev1.Pod {
	controller := true
	pod := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "monitoring", Labels: labels},
		Spec: corev1.PodSpec{Containers: []corev1.Container{
			{Name: "memcached", Image: "docker.io/hostingmaloonde/memcached:1.6.45"},
		}},
		Status: corev1.PodStatus{
			Phase: corev1.PodRunning,
			ContainerStatuses: []corev1.ContainerStatus{
				{Name: "memcached", ImageID: "docker.io/hostingmaloonde/memcached@" + imageID},
			},
		},
	}
	if kind != "" {
		pod.OwnerReferences = []metav1.OwnerReference{{Kind: kind, Name: owner, Controller: &controller}}
	}
	return pod
}

func TestPodWorkload(t *testing.T) {
	cases := []struct {
		name string
		pod  corev1.Pod
		want string
	}{
		{"statefulset", ownedPod("cache-0", "StatefulSet", "cache", nil, "sha256:a"), "StatefulSet/cache"},
		{"deployment via replicaset", ownedPod("api-7d4b9c-xk2p", "ReplicaSet", "api-7d4b9c", map[string]string{"pod-template-hash": "7d4b9c"}, "sha256:a"), "Deployment/api"},
		{"bare replicaset", ownedPod("rs-abc", "ReplicaSet", "rs", nil, "sha256:a"), "ReplicaSet/rs"},
		{"no controller", ownedPod("debug", "", "", nil, "sha256:a"), "Pod/debug"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := podWorkload(&tc.pod); got != tc.want {
				t.Fatalf("podWorkload = %q, want %q", got, tc.want)
			}
		})
	}
}

// Pods of several StatefulSets running one digest report every owner once on
// that image; another digest of the same tag keeps its own owners.
func TestCollectImagesReportsWorkloadsPerDigest(t *testing.T) {
	pods := []corev1.Pod{
		ownedPod("blocks-0", "StatefulSet", "cortex-memcached-blocks", nil, "sha256:old"),
		ownedPod("blocks-1", "StatefulSet", "cortex-memcached-blocks", nil, "sha256:old"),
		ownedPod("frontend-0", "StatefulSet", "cortex-memcached-frontend", nil, "sha256:old"),
		ownedPod("frontend-1", "StatefulSet", "cortex-memcached-frontend", nil, "sha256:new"),
	}

	images, managed, _ := collectImages(pods, nil, 0, testLogger())
	if len(images) != 0 {
		t.Fatalf("managed pods must not be buffered, got %+v", images)
	}
	images = managed

	got := map[string][]string{}
	for _, img := range images {
		got[img.Digest] = img.Workloads
	}
	want := map[string][]string{
		"sha256:old": {"StatefulSet/cortex-memcached-blocks", "StatefulSet/cortex-memcached-frontend"},
		"sha256:new": {"StatefulSet/cortex-memcached-frontend"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("workloads by digest = %v, want %v", got, want)
	}
}

func TestInventoryBufferWorkloads(t *testing.T) {
	buffer := newInventoryBuffer()
	base := clusterImageInput{Namespace: "monitoring", ImageRef: "docker.io/hostingmaloonde/memcached", Tag: "1.6.45", Digest: "sha256:old"}

	first := base
	first.Workloads = []string{"StatefulSet/b"}
	buffer.Observe(first)
	second := base
	second.Workloads = []string{"StatefulSet/a"}
	if !buffer.Observe(second) {
		t.Fatal("adding a workload to a known image should report a change")
	}
	if got := buffer.Snapshot()[0].Workloads; !reflect.DeepEqual(got, []string{"StatefulSet/a", "StatefulSet/b"}) {
		t.Fatalf("workloads after watch = %v", got)
	}

	// A full listing replaces owners collected from watch events.
	listed := base
	listed.Workloads = []string{"StatefulSet/a"}
	buffer.TouchAll([]clusterImageInput{listed})
	if got := buffer.Snapshot()[0].Workloads; !reflect.DeepEqual(got, []string{"StatefulSet/a"}) {
		t.Fatalf("workloads after refresh = %v", got)
	}
}

// production-2 kept a scaled-down ReplicaSet whose image was ":sha-fd8089b5".
// Its empty image reference must not reach the snapshot, or suppline rejects
// the whole inventory with 400.
func TestSnapshotDropsEntriesWithoutImageRef(t *testing.T) {
	buffer := newInventoryBuffer()
	images := appendWorkloadPodSpecImages(nil, "ai", corev1.PodSpec{Containers: []corev1.Container{
		{Name: "broken", Image: ":sha-fd8089b5"},
		{Name: "api", Image: "registry.gitlab.com/cmd/model-api:sha-fd8089b5"},
	}})
	buffer.TouchAll(images)

	snapshot := buffer.Snapshot()
	if len(snapshot) != 1 || snapshot[0].ImageRef != "registry.gitlab.com/cmd/model-api" {
		t.Fatalf("snapshot = %+v, want only the image with a reference", snapshot)
	}
	if merged := mergeImages(images, nil); len(merged) != 1 {
		t.Fatalf("mergeImages = %+v, want the empty reference dropped", merged)
	}
}
