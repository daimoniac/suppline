package main

import (
	"context"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

const (
	grafanaPinned   = "sha256:e93c891f2f6b37e11621cb76554cd1d9dab330e192d98d410b22589df2bb4acf"
	sidecarPinned   = "sha256:ab26090b686bc358cb3dcb201d12b314e3d50eaa3e957979f5096aef264597bd"
	busyboxPinned   = "sha256:cbf608bac227b555568030a804f7666bb60524ea25c626db8b9b93789748784e"
	busyboxPlatform = "sha256:0000000000000000000000000000000000000000000000000000000000000001"
)

func hasImage(images []clusterImageInput, namespace, imageRef, tag, digest string) bool {
	for _, img := range images {
		if img.Namespace == namespace && img.ImageRef == imageRef && img.Tag == tag && img.Digest == digest {
			return true
		}
	}
	return false
}

func TestCollectPodObservationReportsPinnedDigestsFromStatus(t *testing.T) {
	buffer := newInventoryBuffer()
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "monitoring", Name: "grafana-0"},
		Spec: corev1.PodSpec{
			InitContainers: []corev1.Container{{Name: "init-chown-data", Image: "docker.io/hostingmaloonde/dhi_busybox:1.37.0-debian13@" + busyboxPinned}},
			Containers: []corev1.Container{
				{Name: "grafana", Image: "docker.io/hostingmaloonde/dhi_grafana:13.2.3-debian13@" + grafanaPinned},
				// Spec without the docker.io prefix; the runtime reports the canonical name.
				{Name: "grafana-sc-dashboard", Image: "hostingmaloonde/dhi_k8s-sidecar:2.14.1-debian13@" + sidecarPinned},
			},
		},
		Status: corev1.PodStatus{
			InitContainerStatuses: []corev1.ContainerStatus{{Name: "init-chown-data", ImageID: "docker.io/hostingmaloonde/dhi_busybox@" + busyboxPinned}},
			ContainerStatuses: []corev1.ContainerStatus{
				{Name: "grafana", ImageID: "docker.io/hostingmaloonde/dhi_grafana@" + grafanaPinned},
				{Name: "grafana-sc-dashboard", ImageID: "docker.io/hostingmaloonde/dhi_k8s-sidecar@" + sidecarPinned},
			},
		},
	}

	collectPodObservation(pod, map[string]bool{}, buffer, time.Hour)
	got := buffer.Snapshot()
	if len(got) != 3 {
		t.Fatalf("snapshot = %+v, want three images", got)
	}
	if !hasImage(got, "monitoring", "docker.io/hostingmaloonde/dhi_busybox", "1.37.0-debian13", busyboxPinned) {
		t.Errorf("init container digest missing: %+v", got)
	}
	if !hasImage(got, "monitoring", "docker.io/hostingmaloonde/dhi_grafana", "13.2.3-debian13", grafanaPinned) {
		t.Errorf("grafana digest missing: %+v", got)
	}
	if !hasImage(got, "monitoring", "hostingmaloonde/dhi_k8s-sidecar", "2.14.1-debian13", sidecarPinned) {
		t.Errorf("sidecar digest dropped for shorthand repository: %+v", got)
	}
}

func TestParseImageRefDigestsKeepsSpecDigest(t *testing.T) {
	cases := []struct {
		name, image, imageID string
		want                 []string
	}{
		{
			name:    "runtime matches spec",
			image:   "docker.io/hostingmaloonde/dhi_busybox:1.37.0-debian13@" + busyboxPinned,
			imageID: "docker.io/hostingmaloonde/dhi_busybox@" + busyboxPinned,
			want:    []string{busyboxPinned},
		},
		{
			name:    "runtime differs from spec",
			image:   "docker.io/hostingmaloonde/dhi_busybox:1.37.0-debian13@" + busyboxPinned,
			imageID: "containerd://docker.io/hostingmaloonde/dhi_busybox@" + busyboxPlatform,
			want:    []string{busyboxPlatform, busyboxPinned},
		},
		{
			name:    "redirected runtime keeps the spec digest",
			image:   "docker.io/hostingmaloonde/dhi_busybox:1.37.0-debian13@" + busyboxPinned,
			imageID: "dhi.io/busybox@" + busyboxPlatform,
			want:    []string{busyboxPinned},
		},
		{
			name:  "template without status",
			image: "docker.io/hostingmaloonde/dhi_busybox:1.37.0-debian13@" + busyboxPinned,
			want:  []string{busyboxPinned},
		},
		{
			name:    "library shorthand",
			image:   "busybox:1.37",
			imageID: "docker.io/library/busybox@" + busyboxPlatform,
			want:    []string{busyboxPlatform},
		},
		{
			name:  "bare tag",
			image: "docker.io/hostingmaloonde/dhi_busybox:1.37.0-debian13",
		},
	}
	for _, tc := range cases {
		_, _, got := parseImageRefDigests(tc.image, tc.imageID)
		if len(got) != len(tc.want) {
			t.Errorf("%s: digests = %v, want %v", tc.name, got, tc.want)
			continue
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Errorf("%s: digests = %v, want %v", tc.name, got, tc.want)
			}
		}
	}
}

func TestCollectWorkloadImagesKeepsTemplateDigests(t *testing.T) {
	zero := int32(0)
	one := int32(1)
	pinnedSpec := corev1.PodSpec{
		InitContainers: []corev1.Container{{Name: "init", Image: "docker.io/hostingmaloonde/dhi_busybox:1.37.0-debian13@" + busyboxPinned}},
		Containers:     []corev1.Container{{Name: "grafana", Image: "docker.io/hostingmaloonde/dhi_grafana:13.2.3-debian13@" + grafanaPinned}},
	}
	client := fake.NewSimpleClientset(
		&appsv1.StatefulSet{
			ObjectMeta: metav1.ObjectMeta{Name: "grafana", Namespace: "monitoring"},
			Spec:       appsv1.StatefulSetSpec{Template: corev1.PodTemplateSpec{Spec: pinnedSpec}},
		},
		&batchv1.CronJob{
			ObjectMeta: metav1.ObjectMeta{Name: "backup", Namespace: "backup"},
			Spec: batchv1.CronJobSpec{JobTemplate: batchv1.JobTemplateSpec{Spec: batchv1.JobSpec{Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{
				Containers: []corev1.Container{{Name: "job", Image: "docker.io/hostingmaloonde/dhi_k8s-sidecar:2.14.1-debian13@" + sidecarPinned}},
			}}}}},
		},
		&appsv1.ReplicaSet{
			ObjectMeta: metav1.ObjectMeta{Name: "old-revision", Namespace: "apps"},
			Spec: appsv1.ReplicaSetSpec{Replicas: &zero, Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{
				Containers: []corev1.Container{{Name: "app", Image: "docker.io/hostingmaloonde/old:1.0@" + busyboxPlatform}},
			}}},
		},
		&appsv1.ReplicaSet{
			ObjectMeta: metav1.ObjectMeta{Name: "live-revision", Namespace: "apps"},
			Spec: appsv1.ReplicaSetSpec{Replicas: &one, Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{
				Containers: []corev1.Container{{Name: "app", Image: "docker.io/hostingmaloonde/live:2.0"}},
			}}},
		},
		&appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{Name: "system", Namespace: "kube-system"},
			Spec:       appsv1.DeploymentSpec{Template: corev1.PodTemplateSpec{Spec: pinnedSpec}},
		},
	)

	images, _, err := collectWorkloadImages(context.Background(), client, map[string]bool{"kube-system": true}, time.Hour, testLogger())
	if err != nil {
		t.Fatalf("collectWorkloadImages: %v", err)
	}
	if !hasImage(images, "monitoring", "docker.io/hostingmaloonde/dhi_grafana", "13.2.3-debian13", grafanaPinned) {
		t.Errorf("StatefulSet container digest missing: %+v", images)
	}
	if !hasImage(images, "monitoring", "docker.io/hostingmaloonde/dhi_busybox", "1.37.0-debian13", busyboxPinned) {
		t.Errorf("StatefulSet init container digest missing: %+v", images)
	}
	if !hasImage(images, "backup", "docker.io/hostingmaloonde/dhi_k8s-sidecar", "2.14.1-debian13", sidecarPinned) {
		t.Errorf("CronJob jobTemplate digest missing: %+v", images)
	}
	if !hasImage(images, "apps", "docker.io/hostingmaloonde/live", "2.0", "") {
		t.Errorf("scaled-up ReplicaSet missing: %+v", images)
	}
	for _, img := range images {
		if img.ImageRef == "docker.io/hostingmaloonde/old" {
			t.Errorf("ReplicaSet scaled to zero was reported: %+v", img)
		}
		if img.Namespace == "kube-system" {
			t.Errorf("excluded namespace was reported: %+v", img)
		}
	}
}

// hetzner-1, 2026-11-16: 40 of 95 images from controller-managed pods were
// reported without a digest. The spec named "hostingmaloonde/kubereboot_kured",
// the runtime "docker.io/hostingmaloonde/kubereboot_kured@sha256:...", and the
// plain string comparison treated that as a redirect.
func TestManagedPodImagesKeepDigestOfShorthandImage(t *testing.T) {
	const digest = "sha256:5b2d1c4f0a9e8d7c6b5a49382716051e4d3c2b1a0f9e8d7c6b5a493827160514"
	controller := true
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:       "kured",
			Name:            "kured-x7k2p",
			OwnerReferences: []metav1.OwnerReference{{Kind: "DaemonSet", Name: "kured", Controller: &controller}},
		},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "kured", Image: "hostingmaloonde/kubereboot_kured:1.23.0"}}},
		Status: corev1.PodStatus{
			Phase:             corev1.PodRunning,
			ContainerStatuses: []corev1.ContainerStatus{{Name: "kured", ImageID: "docker.io/hostingmaloonde/kubereboot_kured@" + digest}},
		},
	}

	got := managedPodImages([]*corev1.Pod{pod}, nil)
	if len(got) != 1 || got[0].Digest != digest || got[0].ImageRef != "hostingmaloonde/kubereboot_kured" || got[0].Tag != "1.23.0" {
		t.Fatalf("managed images = %+v, want the runtime digest kept", got)
	}
}

func TestCanonicalRepository(t *testing.T) {
	same := [][]string{
		{"nginx", "docker.io/library/nginx", "library/nginx", "index.docker.io/library/nginx"},
		{"hostingmaloonde/kubereboot_kured", "docker.io/hostingmaloonde/kubereboot_kured", "registry-1.docker.io/hostingmaloonde/kubereboot_kured"},
		{"ghcr.io/daimoniac/suppline", "GHCR.io/daimoniac/suppline"},
	}
	for _, group := range same {
		for _, repo := range group[1:] {
			if canonicalRepository(repo) != canonicalRepository(group[0]) {
				t.Errorf("canonicalRepository(%q) = %q, want %q", repo, canonicalRepository(repo), canonicalRepository(group[0]))
			}
		}
	}
	// A real mirror redirect still differs, so its digest stays dropped.
	if canonicalRepository("index.docker.io/rancher/hardened-etcd") != canonicalRepository("docker.io/rancher/hardened-etcd") {
		t.Error("index.docker.io alias not folded")
	}
	if canonicalRepository("registry.example.com/mirror/nginx") == canonicalRepository("nginx") {
		t.Error("different registries compared equal")
	}
}
