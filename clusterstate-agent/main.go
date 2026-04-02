package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// clusterImageInput mirrors the suppline webhook payload format.
type clusterImageInput struct {
	Namespace string `json:"namespace"`
	ImageRef  string `json:"image_ref"`
	Tag       string `json:"tag,omitempty"`
	Digest    string `json:"digest,omitempty"`
}

type clusterInventoryRequest struct {
	Cluster string              `json:"cluster"`
	Images  []clusterImageInput `json:"images"`
}

func main() {
	logger := buildLogger()

	// --- Required configuration ---
	supplineURL := os.Getenv("SUPPLINE_URL")
	if supplineURL == "" {
		logger.Error("SUPPLINE_URL environment variable is required")
		os.Exit(1)
	}
	clusterName := os.Getenv("CLUSTER_NAME")
	if clusterName == "" {
		logger.Error("CLUSTER_NAME environment variable is required")
		os.Exit(1)
	}

	apiKey := os.Getenv("SUPPLINE_API_KEY")
	debugDumpPayload := isTrueEnv("DEBUG_DUMP_PAYLOAD")
	excludedNS := parseExcludedNamespaces()

	logger.Info("starting cluster inventory collection",
		"cluster", clusterName,
		"suppline_url", supplineURL,
		"excluded_namespaces", os.Getenv("EXCLUDED_NAMESPACES"),
		"debug_dump_payload", debugDumpPayload,
	)

	// --- Build Kubernetes client ---
	kubeClient, err := buildKubeClient()
	if err != nil {
		logger.Error("failed to build Kubernetes client", "error", err)
		os.Exit(1)
	}

	ctx := context.Background()

	// --- List all pods across all namespaces ---
	podList, err := kubeClient.CoreV1().Pods("").List(ctx, metav1.ListOptions{})
	if err != nil {
		logger.Error("failed to list pods", "error", err)
		os.Exit(1)
	}
	logger.Info("listed pods", "total", len(podList.Items))

	// --- Collect and deduplicate image entries ---
	images := collectImages(podList.Items, excludedNS, logger)
	logger.Info("collected unique images", "count", len(images))

	// --- POST inventory to suppline ---
	if err := sendInventory(ctx, supplineURL, clusterName, apiKey, debugDumpPayload, images, logger); err != nil {
		logger.Error("failed to send inventory to suppline", "error", err)
		os.Exit(1)
	}

	logger.Info("inventory sent successfully", "cluster", clusterName, "images", len(images))
}

// buildLogger constructs a JSON slog logger at the configured log level.
func buildLogger() *slog.Logger {
	level := slog.LevelInfo
	switch strings.ToLower(os.Getenv("LOG_LEVEL")) {
	case "debug":
		level = slog.LevelDebug
	case "warn", "warning":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}
	return slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level}))
}

// parseExcludedNamespaces reads EXCLUDED_NAMESPACES and returns a lookup set.
// Defaults to kube-system, kube-public, kube-node-lease.
func parseExcludedNamespaces() map[string]bool {
	raw := os.Getenv("EXCLUDED_NAMESPACES")
	if raw == "" {
		raw = "kube-system,kube-public,kube-node-lease"
	}
	result := make(map[string]bool)
	for _, ns := range strings.Split(raw, ",") {
		ns = strings.TrimSpace(ns)
		if ns != "" {
			result[ns] = true
		}
	}
	return result
}

// isTrueEnv returns true for common truthy env values.
func isTrueEnv(key string) bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv(key)))
	return v == "1" || v == "true" || v == "yes" || v == "on"
}

// buildKubeClient tries in-cluster config first (running inside a cluster),
// then falls back to the default kubeconfig / KUBECONFIG env var (local dev).
func buildKubeClient() (*kubernetes.Clientset, error) {
	cfg, err := rest.InClusterConfig()
	if err != nil {
		loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
		cfg, err = clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
			loadingRules,
			&clientcmd.ConfigOverrides{},
		).ClientConfig()
		if err != nil {
			return nil, fmt.Errorf("build kubeconfig: %w", err)
		}
	}
	return kubernetes.NewForConfig(cfg)
}

// collectImages iterates pods, builds image entries and deduplicates them.
func collectImages(pods []corev1.Pod, excludedNS map[string]bool, logger *slog.Logger) []clusterImageInput {
	seen := make(map[string]struct{})
	var images []clusterImageInput

	for _, pod := range pods {
		if excludedNS[pod.Namespace] {
			logger.Debug("skipping excluded namespace", "namespace", pod.Namespace, "pod", pod.Name)
			continue
		}

		imageIDByContainer := buildImageIDLookup(pod.Status.ContainerStatuses)

		for _, c := range pod.Spec.Containers {
			imageRef, tag, digest := parseImageRef(c.Image, imageIDByContainer[c.Name])

			key := pod.Namespace + "|" + imageRef + "|" + digest
			if _, exists := seen[key]; exists {
				continue
			}
			seen[key] = struct{}{}

			images = append(images, clusterImageInput{
				Namespace: pod.Namespace,
				ImageRef:  imageRef,
				Tag:       tag,
				Digest:    digest,
			})
		}
	}

	return images
}

// buildImageIDLookup maps container name → imageID from pod status.
func buildImageIDLookup(statuses []corev1.ContainerStatus) map[string]string {
	m := make(map[string]string, len(statuses))
	for _, s := range statuses {
		m[s.Name] = s.ImageID
	}
	return m
}

// parseImageRef extracts the normalised imageRef, tag, and digest.
//
// Handles all common formats:
//   - nginx:1.25                             → imageRef=nginx, tag=1.25
//   - nginx:1.25@sha256:abc…                 → imageRef=nginx, tag=1.25, digest=sha256:abc…
//   - registry.example.com/repo/img:tag      → imageRef=registry.example.com/repo/img, tag=tag
//   - registry.example.com:5000/img:tag      → correctly ignores port colon
//
// The digest is resolved from the container's runtime imageID (most reliable
// source), stripping the "docker-pullable://" prefix that Docker adds.
func parseImageRef(image, imageID string) (imageRef, tag, digest string) {
	imageRef = image

	// Resolve digest from runtime imageID.
	if imageID != "" {
		id := strings.TrimPrefix(imageID, "docker-pullable://")
		if idx := strings.Index(id, "@sha256:"); idx != -1 {
			digest = id[idx+1:] // "sha256:..."
		} else if strings.HasPrefix(id, "sha256:") {
			digest = id
		}
	}

	// Strip inline digest from image reference (e.g. nginx:1.25@sha256:...)
	if idx := strings.Index(image, "@sha256:"); idx != -1 {
		imageRef = image[:idx]
		image = imageRef // parse tag from the part before the digest
	}

	// Parse tag: look for the last colon, but make sure it's not a registry port.
	// A tag colon must appear after the last '/' in the path.
	if lastColon := strings.LastIndex(image, ":"); lastColon != -1 {
		lastSlash := strings.LastIndex(image, "/")
		if lastColon > lastSlash {
			tag = image[lastColon+1:]
			imageRef = image[:lastColon]
		}
	}

	return
}

// sendInventory marshals the payload and POSTs it to the suppline webhook.
func sendInventory(
	ctx context.Context,
	supplineURL, clusterName, apiKey string,
	debugDumpPayload bool,
	images []clusterImageInput,
	logger *slog.Logger,
) error {
	payload := clusterInventoryRequest{
		Cluster: clusterName,
		Images:  images,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal payload: %w", err)
	}

	if debugDumpPayload {
		pretty, err := json.MarshalIndent(payload, "", "  ")
		if err != nil {
			logger.Warn("failed to pretty-print payload", "error", err)
		} else {
			logger.Info("cluster inventory payload", "json", string(pretty))
		}
	}

	endpoint := strings.TrimRight(supplineURL, "/") + "/api/v1/webhook/cluster-inventory"
	logger.Debug("posting cluster inventory", "url", endpoint, "payload_bytes", len(body))

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+apiKey)
	}

	httpClient := &http.Client{Timeout: 30 * time.Second}
	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("http post: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("suppline returned unexpected status %s", resp.Status)
	}
	return nil
}
