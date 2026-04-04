package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/joho/godotenv"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
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

var quotedStringRe = regexp.MustCompile(`"([^"]+)"|'([^']+)'`)

type inventoryBuffer struct {
	mu   sync.Mutex
	seen map[string]clusterImageInput
}

func newInventoryBuffer() *inventoryBuffer {
	return &inventoryBuffer{seen: make(map[string]clusterImageInput)}
}

func imageKey(img clusterImageInput) string {
	return img.Namespace + "|" + img.ImageRef + "|" + img.Digest
}

func (b *inventoryBuffer) Add(img clusterImageInput) bool {
	key := imageKey(img)
	b.mu.Lock()
	defer b.mu.Unlock()

	if existing, ok := b.seen[key]; ok {
		if existing.Tag == "" && img.Tag != "" {
			b.seen[key] = img
			return true
		}
		return false
	}

	b.seen[key] = img
	return true
}

func (b *inventoryBuffer) Snapshot() []clusterImageInput {
	b.mu.Lock()
	defer b.mu.Unlock()

	out := make([]clusterImageInput, 0, len(b.seen))
	for _, img := range b.seen {
		out = append(out, img)
	}
	return out
}

func (b *inventoryBuffer) Replace(images []clusterImageInput) bool {
	b.mu.Lock()
	defer b.mu.Unlock()

	next := make(map[string]clusterImageInput, len(images))
	for _, img := range images {
		next[imageKey(img)] = img
	}

	changed := len(next) != len(b.seen)
	if !changed {
		for key := range next {
			if _, ok := b.seen[key]; !ok {
				changed = true
				break
			}
		}
	}

	b.seen = next
	return changed
}

func main() {
	_ = godotenv.Load()

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
	mode := strings.ToLower(strings.TrimSpace(os.Getenv("AGENT_MODE")))
	if mode == "" {
		mode = "snapshot"
	}

	logger.Info("starting cluster inventory collection",
		"cluster", clusterName,
		"suppline_url", supplineURL,
		"mode", mode,
		"excluded_namespaces", os.Getenv("EXCLUDED_NAMESPACES"),
		"debug_dump_payload", debugDumpPayload,
	)

	// --- Build Kubernetes client ---
	kubeClient, err := buildKubeClient()
	if err != nil {
		logger.Error("failed to build Kubernetes client", "error", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	switch mode {
	case "snapshot":
		if err := runSnapshot(ctx, kubeClient, supplineURL, clusterName, apiKey, debugDumpPayload, excludedNS, logger); err != nil {
			logger.Error("snapshot mode failed", "error", err)
			os.Exit(1)
		}
	case "watch":
		if err := runWatch(ctx, kubeClient, supplineURL, clusterName, apiKey, debugDumpPayload, excludedNS, logger); err != nil {
			logger.Error("watch mode failed", "error", err)
			os.Exit(1)
		}
	default:
		logger.Error("invalid AGENT_MODE; expected snapshot or watch", "mode", mode)
		os.Exit(1)
	}
}

func runSnapshot(
	ctx context.Context,
	kubeClient *kubernetes.Clientset,
	supplineURL, clusterName, apiKey string,
	debugDumpPayload bool,
	excludedNS map[string]bool,
	logger *slog.Logger,
) error {
	images, err := collectClusterInventory(ctx, kubeClient, excludedNS, logger)
	if err != nil {
		return fmt.Errorf("collect inventory: %w", err)
	}

	if err := sendInventory(ctx, supplineURL, clusterName, apiKey, debugDumpPayload, images, logger); err != nil {
		return fmt.Errorf("send inventory: %w", err)
	}

	logger.Info("inventory sent successfully", "cluster", clusterName, "images", len(images))
	return nil
}

func runWatch(
	ctx context.Context,
	kubeClient *kubernetes.Clientset,
	supplineURL, clusterName, apiKey string,
	debugDumpPayload bool,
	excludedNS map[string]bool,
	logger *slog.Logger,
) error {
	retryInterval := parseWatchRetryInterval(logger)
	if retryInterval <= 0 {
		return fmt.Errorf("WATCH_RETRY_INTERVAL/WATCH_FLUSH_INTERVAL must be > 0")
	}

	refreshInterval := parseDurationEnv("WATCH_REFRESH_INTERVAL", 24*time.Hour, logger)
	if refreshInterval <= 0 {
		return fmt.Errorf("WATCH_REFRESH_INTERVAL must be > 0")
	}

	buffer := newInventoryBuffer()
	if _, err := refreshInventoryBuffer(ctx, kubeClient, excludedNS, buffer, logger); err != nil {
		return fmt.Errorf("initial inventory refresh: %w", err)
	}

	factory := informers.NewSharedInformerFactory(kubeClient, 0)
	podInformer := factory.Core().V1().Pods().Informer()
	eventInformer := factory.Core().V1().Events().Informer()

	changeCh := make(chan struct{}, 1)
	signalSend := func() {
		select {
		case changeCh <- struct{}{}:
		default:
		}
	}

	podInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			pod, ok := obj.(*corev1.Pod)
			if !ok {
				return
			}
			if collectPodObservation(pod, excludedNS, buffer) {
				signalSend()
			}
		},
		UpdateFunc: func(_, newObj interface{}) {
			pod, ok := newObj.(*corev1.Pod)
			if !ok {
				return
			}
			if collectPodObservation(pod, excludedNS, buffer) {
				signalSend()
			}
		},
	})

	eventInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			event, ok := obj.(*corev1.Event)
			if !ok {
				return
			}
			if collectEventObservation(event, excludedNS, buffer) {
				signalSend()
			}
		},
		UpdateFunc: func(_, newObj interface{}) {
			event, ok := newObj.(*corev1.Event)
			if !ok {
				return
			}
			if collectEventObservation(event, excludedNS, buffer) {
				signalSend()
			}
		},
	})

	stopCh := make(chan struct{})
	defer close(stopCh)
	factory.Start(stopCh)

	if !cache.WaitForCacheSync(stopCh, podInformer.HasSynced, eventInformer.HasSynced) {
		return fmt.Errorf("failed to sync informer caches")
	}

	attemptSend := func() error {
		images := buffer.Snapshot()
		if len(images) == 0 {
			logger.Info("skipping inventory send because snapshot is empty")
			return nil
		}

		if err := sendInventory(ctx, supplineURL, clusterName, apiKey, debugDumpPayload, images, logger); err != nil {
			return err
		}

		logger.Info("submitted watched inventory snapshot", "images", len(images))
		return nil
	}

	pendingSend := true
	if err := attemptSend(); err != nil {
		logger.Warn("failed to send initial watched inventory snapshot", "error", err)
	} else {
		pendingSend = false
	}

	refreshTicker := time.NewTicker(refreshInterval)
	defer refreshTicker.Stop()
	retryTicker := time.NewTicker(retryInterval)
	defer retryTicker.Stop()

	logger.Info("watch mode started", "refresh_interval", refreshInterval.String(), "retry_interval", retryInterval.String())

	for {
		select {
		case <-ctx.Done():
			if pendingSend {
				if err := attemptSend(); err != nil {
					logger.Warn("failed to send final watched inventory snapshot", "error", err)
				}
			}
			logger.Info("watch mode stopping", "reason", ctx.Err())
			return nil
		case <-changeCh:
			pendingSend = true
			if err := attemptSend(); err != nil {
				logger.Warn("failed to send changed inventory snapshot; will retry", "error", err)
				continue
			}
			pendingSend = false
		case <-retryTicker.C:
			if !pendingSend {
				continue
			}
			if err := attemptSend(); err != nil {
				logger.Warn("failed to retry watched inventory snapshot", "error", err)
				continue
			}
			pendingSend = false
		case <-refreshTicker.C:
			changed, err := refreshInventoryBuffer(ctx, kubeClient, excludedNS, buffer, logger)
			if err != nil {
				logger.Warn("failed to refresh watched inventory snapshot", "error", err)
				continue
			}

			if changed {
				logger.Info("refreshed inventory buffer with changes")
			} else {
				logger.Info("refreshed inventory buffer with no changes")
			}

			pendingSend = true
			if err := attemptSend(); err != nil {
				logger.Warn("failed to send refreshed inventory snapshot; will retry", "error", err)
				continue
			}
			pendingSend = false
		}
	}
}

func collectPodObservation(pod *corev1.Pod, excludedNS map[string]bool, buffer *inventoryBuffer) bool {
	if pod == nil || excludedNS[pod.Namespace] {
		return false
	}

	changed := false

	imageIDByContainer := buildImageIDLookup(*pod)
	if addObservedContainers(buffer, pod.Namespace, pod.Spec.InitContainers, imageIDByContainer) {
		changed = true
	}
	if addObservedContainers(buffer, pod.Namespace, pod.Spec.Containers, imageIDByContainer) {
		changed = true
	}

	for _, c := range pod.Spec.EphemeralContainers {
		imageRef, tag, digest := parseImageRef(c.Image, imageIDByContainer[c.Name])
		if buffer.Add(clusterImageInput{Namespace: pod.Namespace, ImageRef: imageRef, Tag: tag, Digest: digest}) {
			changed = true
		}
	}

	return changed
}

func collectEventObservation(event *corev1.Event, excludedNS map[string]bool, buffer *inventoryBuffer) bool {
	if event == nil || excludedNS[event.Namespace] {
		return false
	}
	if !shouldObserveEvent(event) {
		return false
	}

	image := extractImageFromEventMessage(event.Message)
	if image == "" {
		return false
	}

	imageRef, tag, digest := parseImageRef(image, "")
	return buffer.Add(clusterImageInput{Namespace: event.Namespace, ImageRef: imageRef, Tag: tag, Digest: digest})
}

func shouldObserveEvent(event *corev1.Event) bool {
	if event == nil {
		return false
	}
	if event.InvolvedObject.Kind != "Pod" {
		return false
	}

	// Watch common pod lifecycle events that may mention pull/runtime image refs.
	switch event.Reason {
	case "Pulling", "Pulled", "Created", "Started", "Failed":
		return true
	default:
		return false
	}
}

func extractImageFromEventMessage(message string) string {
	trimmed := strings.TrimSpace(message)
	if trimmed == "" {
		return ""
	}

	matches := quotedStringRe.FindAllStringSubmatch(trimmed, -1)
	for _, m := range matches {
		candidate := strings.TrimSpace(m[1])
		if candidate == "" {
			candidate = strings.TrimSpace(m[2])
		}
		if isLikelyImageRef(candidate) {
			return candidate
		}
	}

	for _, token := range strings.Fields(trimmed) {
		token = strings.Trim(token, ",.;()[]{}\"")
		if isLikelyImageRef(token) {
			return token
		}
	}

	return ""
}

func isLikelyImageRef(v string) bool {
	v = strings.TrimSpace(v)
	if v == "" {
		return false
	}
	if strings.Contains(v, " ") {
		return false
	}
	return strings.Contains(v, "/") || strings.Contains(v, ":") || strings.Contains(v, "@sha256:")
}

func addObservedContainers(buffer *inventoryBuffer, namespace string, containers []corev1.Container, imageIDByContainer map[string]string) bool {
	changed := false
	for _, c := range containers {
		imageRef, tag, digest := parseImageRef(c.Image, imageIDByContainer[c.Name])
		if buffer.Add(clusterImageInput{Namespace: namespace, ImageRef: imageRef, Tag: tag, Digest: digest}) {
			changed = true
		}
	}
	return changed
}

func collectClusterInventory(
	ctx context.Context,
	kubeClient *kubernetes.Clientset,
	excludedNS map[string]bool,
	logger *slog.Logger,
) ([]clusterImageInput, error) {
	// --- List all pods across all namespaces ---
	podList, err := kubeClient.CoreV1().Pods("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list pods: %w", err)
	}
	logger.Info("listed pods", "total", len(podList.Items))

	// --- Collect images from running pods and workload definitions ---
	images := collectImages(podList.Items, excludedNS, logger)
	logger.Info("collected images from pods", "count", len(images))

	// --- Collect images from Deployments, StatefulSets, DaemonSets, Jobs, CronJobs ---
	workloadImages, err := collectWorkloadImages(ctx, kubeClient, excludedNS, logger)
	if err != nil {
		logger.Warn("failed to collect workload images", "error", err)
	} else {
		logger.Info("collected images from workloads", "count", len(workloadImages))
	}

	// --- Merge and deduplicate ---
	images = mergeImages(images, workloadImages)
	logger.Info("collected unique images total", "count", len(images))
	return images, nil
}

func refreshInventoryBuffer(
	ctx context.Context,
	kubeClient *kubernetes.Clientset,
	excludedNS map[string]bool,
	buffer *inventoryBuffer,
	logger *slog.Logger,
) (bool, error) {
	images, err := collectClusterInventory(ctx, kubeClient, excludedNS, logger)
	if err != nil {
		return false, err
	}

	changed := buffer.Replace(images)
	logger.Info("inventory buffer refreshed", "images", len(images), "changed", changed)
	return changed, nil
}

func parseDurationEnv(key string, fallback time.Duration, logger *slog.Logger) time.Duration {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		logger.Warn("invalid duration env value; using fallback", "key", key, "value", raw, "fallback", fallback.String(), "error", err)
		return fallback
	}
	return d
}

func parseWatchRetryInterval(logger *slog.Logger) time.Duration {
	if strings.TrimSpace(os.Getenv("WATCH_RETRY_INTERVAL")) != "" {
		return parseDurationEnv("WATCH_RETRY_INTERVAL", 30*time.Second, logger)
	}

	// Backward compatibility with older configuration key.
	if strings.TrimSpace(os.Getenv("WATCH_FLUSH_INTERVAL")) != "" {
		return parseDurationEnv("WATCH_FLUSH_INTERVAL", 30*time.Second, logger)
	}

	return 30 * time.Second
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

		imageIDByContainer := buildImageIDLookup(pod)

		images = appendUniquePodContainerImages(images, seen, pod.Namespace, pod.Spec.InitContainers, imageIDByContainer)
		images = appendUniquePodContainerImages(images, seen, pod.Namespace, pod.Spec.Containers, imageIDByContainer)
		images = appendUniquePodEphemeralContainerImages(images, seen, pod.Namespace, pod.Spec.EphemeralContainers, imageIDByContainer)
	}

	return images
}

func appendUniquePodContainerImages(
	images []clusterImageInput,
	seen map[string]struct{},
	namespace string,
	containers []corev1.Container,
	imageIDByContainer map[string]string,
) []clusterImageInput {
	for _, c := range containers {
		imageRef, tag, digest := parseImageRef(c.Image, imageIDByContainer[c.Name])
		img := clusterImageInput{Namespace: namespace, ImageRef: imageRef, Tag: tag, Digest: digest}
		key := imageKey(img)
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		images = append(images, img)
	}
	return images
}

func appendUniquePodEphemeralContainerImages(
	images []clusterImageInput,
	seen map[string]struct{},
	namespace string,
	containers []corev1.EphemeralContainer,
	imageIDByContainer map[string]string,
) []clusterImageInput {
	for _, c := range containers {
		imageRef, tag, digest := parseImageRef(c.Image, imageIDByContainer[c.Name])
		img := clusterImageInput{Namespace: namespace, ImageRef: imageRef, Tag: tag, Digest: digest}
		key := imageKey(img)
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		images = append(images, img)
	}
	return images
}

// buildImageIDLookup maps container name → imageID from pod status.
func buildImageIDLookup(pod corev1.Pod) map[string]string {
	total := len(pod.Status.InitContainerStatuses) + len(pod.Status.ContainerStatuses) + len(pod.Status.EphemeralContainerStatuses)
	m := make(map[string]string, total)
	addContainerStatuses(m, pod.Status.InitContainerStatuses)
	addContainerStatuses(m, pod.Status.ContainerStatuses)
	addContainerStatuses(m, pod.Status.EphemeralContainerStatuses)
	return m
}

func addContainerStatuses(lookup map[string]string, statuses []corev1.ContainerStatus) {
	for _, s := range statuses {
		lookup[s.Name] = s.ImageID
	}
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
// source), normalizing common runtime prefixes (docker, containerd, cri-o).
func parseImageRef(image, imageID string) (imageRef, tag, digest string) {
	imageRef = image

	// Resolve digest from runtime imageID.
	if imageID != "" {
		digest = extractDigestFromImageID(imageID)
	}

	// Strip inline digest from image reference (e.g. nginx:1.25@sha256:...).
	if idx := strings.LastIndex(image, "@"); idx != -1 {
		if digest == "" {
			candidate := image[idx+1:]
			if strings.Contains(candidate, ":") {
				digest = candidate
			}
		}
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

func extractDigestFromImageID(imageID string) string {
	id := strings.TrimSpace(imageID)
	if id == "" {
		return ""
	}

	prefixes := []string{"docker-pullable://", "docker://", "containerd://", "cri-o://"}
	for _, p := range prefixes {
		id = strings.TrimPrefix(id, p)
	}

	if idx := strings.Index(id, "@sha256:"); idx != -1 {
		return id[idx+1:]
	}
	if strings.HasPrefix(id, "sha256:") {
		return id
	}
	if idx := strings.LastIndex(id, "sha256:"); idx != -1 {
		return id[idx:]
	}

	return ""
}

// collectWorkloadImages gathers images from Deployments, StatefulSets, DaemonSets, Jobs, and CronJobs.
func collectWorkloadImages(ctx context.Context, kubeClient *kubernetes.Clientset, excludedNS map[string]bool, logger *slog.Logger) ([]clusterImageInput, error) {
	var images []clusterImageInput

	// Collect from Deployments
	deployments, err := kubeClient.AppsV1().Deployments("").List(ctx, metav1.ListOptions{})
	if err != nil {
		logger.Warn("failed to list deployments", "error", err)
	} else {
		for _, dep := range deployments.Items {
			if excludedNS[dep.Namespace] {
				continue
			}
			images = appendWorkloadPodSpecImages(images, dep.Namespace, dep.Spec.Template.Spec)
		}
	}

	// Collect from StatefulSets
	statefulSets, err := kubeClient.AppsV1().StatefulSets("").List(ctx, metav1.ListOptions{})
	if err != nil {
		logger.Warn("failed to list statefulsets", "error", err)
	} else {
		for _, sts := range statefulSets.Items {
			if excludedNS[sts.Namespace] {
				continue
			}
			images = appendWorkloadPodSpecImages(images, sts.Namespace, sts.Spec.Template.Spec)
		}
	}

	// Collect from DaemonSets
	daemonSets, err := kubeClient.AppsV1().DaemonSets("").List(ctx, metav1.ListOptions{})
	if err != nil {
		logger.Warn("failed to list daemonsets", "error", err)
	} else {
		for _, ds := range daemonSets.Items {
			if excludedNS[ds.Namespace] {
				continue
			}
			images = appendWorkloadPodSpecImages(images, ds.Namespace, ds.Spec.Template.Spec)
		}
	}

	// Collect from Jobs
	jobs, err := kubeClient.BatchV1().Jobs("").List(ctx, metav1.ListOptions{})
	if err != nil {
		logger.Warn("failed to list jobs", "error", err)
	} else {
		for _, job := range jobs.Items {
			if excludedNS[job.Namespace] {
				continue
			}
			images = appendWorkloadPodSpecImages(images, job.Namespace, job.Spec.Template.Spec)
		}
	}

	// Collect from CronJobs
	cronJobs, err := kubeClient.BatchV1().CronJobs("").List(ctx, metav1.ListOptions{})
	if err != nil {
		logger.Warn("failed to list cronjobs", "error", err)
	} else {
		for _, cj := range cronJobs.Items {
			if excludedNS[cj.Namespace] {
				continue
			}
			images = appendWorkloadPodSpecImages(images, cj.Namespace, cj.Spec.JobTemplate.Spec.Template.Spec)
		}
	}

	return images, nil
}

func appendWorkloadPodSpecImages(images []clusterImageInput, namespace string, spec corev1.PodSpec) []clusterImageInput {
	for _, c := range spec.InitContainers {
		imageRef, tag, _ := parseImageRef(c.Image, "")
		images = append(images, clusterImageInput{Namespace: namespace, ImageRef: imageRef, Tag: tag})
	}
	for _, c := range spec.Containers {
		imageRef, tag, _ := parseImageRef(c.Image, "")
		images = append(images, clusterImageInput{Namespace: namespace, ImageRef: imageRef, Tag: tag})
	}
	return images
}

// mergeImages deduplicates and merges two image lists by (namespace, imageRef, digest).
func mergeImages(list1, list2 []clusterImageInput) []clusterImageInput {
	seen := make(map[string]struct{})
	var merged []clusterImageInput

	for _, img := range list1 {
		key := imageKey(img)
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		merged = append(merged, img)
	}

	for _, img := range list2 {
		key := imageKey(img)
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		merged = append(merged, img)
	}

	return merged
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
