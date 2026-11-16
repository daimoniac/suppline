package main

import (
	"context"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

// 2026-11-16: all 33 "out of bounds" semver tasks came from Deployment
// revision history, e.g. alpine 3.22.2 only in ReplicaSets with replicas 0.
func TestCollectWorkloadImagesSkipsReplicaSetsScaledToZero(t *testing.T) {
	rs := func(name, image string, replicas int32) *appsv1.ReplicaSet {
		return &appsv1.ReplicaSet{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "elk"},
			Spec: appsv1.ReplicaSetSpec{
				Replicas: &replicas,
				Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{
					Containers: []corev1.Container{{Name: "app", Image: image}},
				}},
			},
		}
	}
	client := fake.NewSimpleClientset(
		rs("elk-oauth2-proxy-558b78bddf", "hostingmaloonde/alpine:3.22.2", 0),
		// Mid-rollout the old revision still has replicas while it drains.
		rs("elk-oauth2-proxy-6c9f7d8b5", "hostingmaloonde/alpine:3.23.3", 1),
		rs("elk-oauth2-proxy-7f5b9c6d4", "hostingmaloonde/alpine:3.23.4", 2),
	)

	images, _, err := collectWorkloadImages(context.Background(), client, nil, time.Hour, testLogger())
	if err != nil {
		t.Fatalf("collectWorkloadImages: %v", err)
	}
	tags := map[string]bool{}
	for _, img := range images {
		tags[img.Tag] = true
	}
	if tags["3.22.2"] {
		t.Fatal("reported the image of a ReplicaSet scaled to zero")
	}
	if !tags["3.23.3"] || !tags["3.23.4"] {
		t.Fatalf("ReplicaSets with replicas missing, got tags %v", tags)
	}
}
