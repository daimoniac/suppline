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

	batchv1 "k8s.io/api/batch/v1"
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

var (
	quotedStringRe   = regexp.MustCompile(`"([^"]+)"|'([^']+)'`)
	eventImageHintRe = regexp.MustCompile(`(?i)(?:pulling image|failed to pull image|failed to pull and unpack image|error pulling image|failed to resolve reference|failed to resolve image|failed to unpack image)\s*["']?([^"'\s]+)`)
)

type seenEntry struct {
	img      clusterImageInput
	lastSeen time.Time
}

type inventoryBuffer struct {
	mu   sync.Mutex
	seen map[string]seenEntry
	// blocked identities (namespace, imageRef, tag) were reported by a completed
	// workload that is past retention and are not part of the live inventory.
	// Pod and Event observers must not add them back; the 24h stale TTL would
	// otherwise keep the image in the next snapshots.
	blocked map[string]struct{}
}

func newInventoryBuffer() *inventoryBuffer {
	return &inventoryBuffer{
		seen:    make(map[string]seenEntry),
		blocked: make(map[string]struct{}),
	}
}

func imageKey(img clusterImageInput) string {
	return img.Namespace + "|" + img.ImageRef + "|" + img.Tag + "|" + img.Digest
}

func imageIdentityKey(img clusterImageInput) string {
	return img.Namespace + "|" + img.ImageRef + "|" + img.Tag
}

// normalizeImagesPreferDigests removes digest-less duplicates for an
// image identity (namespace, imageRef, tag) when digest-bearing entries exist.
// Distinct digests for the same identity are preserved.
func normalizeImagesPreferDigests(images []clusterImageInput) []clusterImageInput {
	if len(images) == 0 {
		return nil
	}

	order := make([]string, 0, len(images))
	groups := make(map[string][]clusterImageInput)
	hasDigest := make(map[string]bool)

	for _, img := range images {
		identity := imageIdentityKey(img)
		if _, ok := groups[identity]; !ok {
			order = append(order, identity)
		}

		digest := strings.TrimSpace(img.Digest)
		img.Digest = digest
		groups[identity] = append(groups[identity], img)
		if digest != "" {
			hasDigest[identity] = true
		}
	}

	result := make([]clusterImageInput, 0, len(images))
	seenFull := make(map[string]struct{})
	for _, identity := range order {
		for _, img := range groups[identity] {
			if hasDigest[identity] && strings.TrimSpace(img.Digest) == "" {
				continue
			}

			key := imageKey(img)
			if _, exists := seenFull[key]; exists {
				continue
			}
			seenFull[key] = struct{}{}
			result = append(result, img)
		}
	}

	return result
}

func (b *inventoryBuffer) Add(img clusterImageInput) bool {
	b.mu.Lock()
	defer b.mu.Unlock()

	if _, blocked := b.blocked[imageIdentityKey(img)]; blocked {
		return false
	}
	return b.addLocked(img)
}

// Observe records an image from a live pod. A current pod is authoritative, so
// this clears any completed-workload block for the same identity.
func (b *inventoryBuffer) Observe(img clusterImageInput) bool {
	b.mu.Lock()
	defer b.mu.Unlock()

	delete(b.blocked, imageIdentityKey(img))
	return b.addLocked(img)
}

func (b *inventoryBuffer) addLocked(img clusterImageInput) bool {
	key := imageKey(img)
	if existing, ok := b.seen[key]; ok {
		updated := existing.img
		tagEnriched := false
		if existing.img.Tag == "" && img.Tag != "" {
			updated.Tag = img.Tag
			tagEnriched = true
		}
		b.seen[key] = seenEntry{img: updated, lastSeen: time.Now().UTC()}
		return tagEnriched
	}

	b.seen[key] = seenEntry{img: img, lastSeen: time.Now().UTC()}
	return true
}

// ReconcileExpired removes buffered images whose identity is in expired and not
// in live, and remembers those identities so later pod or event observations
// cannot resurrect them. Live identities are unblocked. Returns true when at
// least one buffered image was removed.
func (b *inventoryBuffer) ReconcileExpired(expired, live []clusterImageInput) bool {
	liveIDs := make(map[string]struct{}, len(live))
	for _, img := range live {
		liveIDs[imageIdentityKey(img)] = struct{}{}
	}
	expiredIDs := make(map[string]struct{}, len(expired))
	for _, img := range expired {
		id := imageIdentityKey(img)
		if _, ok := liveIDs[id]; ok {
			continue
		}
		expiredIDs[id] = struct{}{}
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	for id := range liveIDs {
		delete(b.blocked, id)
	}
	for id := range expiredIDs {
		b.blocked[id] = struct{}{}
	}
	if len(expiredIDs) == 0 {
		return false
	}

	changed := false
	for key, entry := range b.seen {
		if _, drop := expiredIDs[imageIdentityKey(entry.img)]; !drop {
			continue
		}
		delete(b.seen, key)
		changed = true
	}
	return changed
}

func (b *inventoryBuffer) Snapshot() []clusterImageInput {
	b.mu.Lock()
	defer b.mu.Unlock()

	out := make([]clusterImageInput, 0, len(b.seen))
	for _, entry := range b.seen {
		out = append(out, entry.img)
	}
	return normalizeImagesPreferDigests(out)
}

// TouchAll updates the lastSeen timestamp for every provided image, adding any
// that are not already present. Returns true if any new image was added or an
// existing entry was enriched with a tag.
func (b *inventoryBuffer) TouchAll(images []clusterImageInput) bool {
	b.mu.Lock()
	defer b.mu.Unlock()

	now := time.Now().UTC()
	changed := false
	for _, img := range images {
		key := imageKey(img)
		if existing, ok := b.seen[key]; ok {
			updated := existing.img
			if existing.img.Tag == "" && img.Tag != "" {
				updated.Tag = img.Tag
				changed = true
			}
			b.seen[key] = seenEntry{img: updated, lastSeen: now}
		} else {
			b.seen[key] = seenEntry{img: img, lastSeen: now}
			changed = true
		}
	}
	return changed
}

// Evict removes entries whose lastSeen timestamp is older than ttl. Returns
// true if any entries were removed.
func (b *inventoryBuffer) Evict(ttl time.Duration) bool {
	b.mu.Lock()
	defer b.mu.Unlock()

	cutoff := time.Now().UTC().Add(-ttl)
	changed := false
	for key, entry := range b.seen {
		if entry.lastSeen.Before(cutoff) {
			delete(b.seen, key)
			changed = true
		}
	}
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

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := runWatch(ctx, kubeClient, supplineURL, clusterName, apiKey, debugDumpPayload, excludedNS, logger); err != nil {
		logger.Error("watcher mode failed", "error", err)
		os.Exit(1)
	}
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

	heartbeatInterval := parseDurationEnv("WATCH_HEARTBEAT_INTERVAL", 60*time.Minute, logger)
	if heartbeatInterval <= 0 {
		return fmt.Errorf("WATCH_HEARTBEAT_INTERVAL must be > 0")
	}

	refreshInterval := parseDurationEnv("WATCH_REFRESH_INTERVAL", 24*time.Hour, logger)
	if refreshInterval <= 0 {
		return fmt.Errorf("WATCH_REFRESH_INTERVAL must be > 0")
	}

	staleTTL := parseDurationEnv("IMAGE_STALE_AFTER", 24*time.Hour, logger)
	if staleTTL <= 0 {
		return fmt.Errorf("IMAGE_STALE_AFTER must be > 0")
	}

	completedRetention := completedWorkloadRetention(logger)
	if completedRetention <= 0 {
		return fmt.Errorf("COMPLETED_WORKLOAD_RETENTION must be > 0")
	}
	sweepEvery := completedRetention
	if sweepEvery > time.Minute {
		sweepEvery = time.Minute
	}

	buffer := newInventoryBuffer()
	if _, err := refreshInventoryBuffer(ctx, kubeClient, excludedNS, buffer, staleTTL, completedRetention, logger); err != nil {
		return fmt.Errorf("initial inventory refresh: %w", err)
	}
	watchStartedAt := time.Now().UTC()

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
			if collectPodObservation(pod, excludedNS, buffer, completedRetention) {
				signalSend()
			}
		},
		UpdateFunc: func(_, newObj interface{}) {
			pod, ok := newObj.(*corev1.Pod)
			if !ok {
				return
			}
			if collectPodObservation(pod, excludedNS, buffer, completedRetention) {
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
			if collectEventObservation(event, excludedNS, buffer, watchStartedAt, logger) {
				signalSend()
			}
		},
		UpdateFunc: func(_, newObj interface{}) {
			event, ok := newObj.(*corev1.Event)
			if !ok {
				return
			}
			if collectEventObservation(event, excludedNS, buffer, watchStartedAt, logger) {
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

	attemptSend := func(force bool) error {
		images := buffer.Snapshot()
		if images == nil {
			images = []clusterImageInput{}
		}
		if len(images) == 0 && !force {
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
	pendingForceSend := false
	if err := attemptSend(false); err != nil {
		logger.Warn("failed to send initial watched inventory snapshot", "error", err)
	} else {
		pendingSend = false
		pendingForceSend = false
	}

	refreshTicker := time.NewTicker(refreshInterval)
	defer refreshTicker.Stop()
	heartbeatTicker := time.NewTicker(heartbeatInterval)
	defer heartbeatTicker.Stop()
	retryTicker := time.NewTicker(retryInterval)
	defer retryTicker.Stop()
	sweepTicker := time.NewTicker(sweepEvery)
	defer sweepTicker.Stop()

	logger.Info("watch mode started",
		"refresh_interval", refreshInterval.String(),
		"retry_interval", retryInterval.String(),
		"heartbeat_interval", heartbeatInterval.String(),
		"stale_ttl", staleTTL.String(),
		"completed_workload_retention", completedRetention.String(),
	)

	for {
		select {
		case <-ctx.Done():
			if pendingSend {
				if err := attemptSend(pendingForceSend); err != nil {
					logger.Warn("failed to send final watched inventory snapshot", "error", err)
				}
			}
			logger.Info("watch mode stopping", "reason", ctx.Err())
			return nil
		case <-changeCh:
			pendingSend = true
			pendingForceSend = false
			if err := attemptSend(false); err != nil {
				logger.Warn("failed to send changed inventory snapshot; will retry", "error", err)
				continue
			}
			pendingSend = false
			pendingForceSend = false
		case <-heartbeatTicker.C:
			pendingSend = true
			pendingForceSend = true
			if err := attemptSend(true); err != nil {
				logger.Warn("failed to send heartbeat inventory snapshot; will retry", "error", err)
				continue
			}
			pendingSend = false
			pendingForceSend = false
		case <-retryTicker.C:
			if !pendingSend {
				continue
			}
			if err := attemptSend(pendingForceSend); err != nil {
				logger.Warn("failed to retry watched inventory snapshot", "error", err)
				continue
			}
			pendingSend = false
			pendingForceSend = false
		case <-sweepTicker.C:
			dropped, err := dropExpiredCompletedWorkloads(ctx, kubeClient, excludedNS, buffer, completedRetention, logger)
			if err != nil {
				logger.Warn("failed to drop expired completed workloads", "error", err)
				continue
			}
			if !dropped {
				continue
			}

			pendingSend = true
			pendingForceSend = len(buffer.Snapshot()) == 0
			if err := attemptSend(pendingForceSend); err != nil {
				logger.Warn("failed to send inventory snapshot after completed workload expiry; will retry", "error", err)
				continue
			}
			pendingSend = false
			pendingForceSend = false
		case <-refreshTicker.C:
			changed, err := refreshInventoryBuffer(ctx, kubeClient, excludedNS, buffer, staleTTL, completedRetention, logger)
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
			pendingForceSend = len(buffer.Snapshot()) == 0
			if err := attemptSend(pendingForceSend); err != nil {
				logger.Warn("failed to send refreshed inventory snapshot; will retry", "error", err)
				continue
			}
			pendingSend = false
			pendingForceSend = false
		}
	}
}

// buildImageIDMap builds a container-name → imageID lookup from pod status.
func buildImageIDMap(pod *corev1.Pod) map[string]string {
	if pod == nil {
		return nil
	}
	total := len(pod.Status.ContainerStatuses) + len(pod.Status.InitContainerStatuses) + len(pod.Status.EphemeralContainerStatuses)
	if total == 0 {
		return nil
	}
	m := make(map[string]string, total)
	for _, cs := range pod.Status.InitContainerStatuses {
		if cs.ImageID != "" {
			m[cs.Name] = cs.ImageID
		}
	}
	for _, cs := range pod.Status.ContainerStatuses {
		if cs.ImageID != "" {
			m[cs.Name] = cs.ImageID
		}
	}
	for _, cs := range pod.Status.EphemeralContainerStatuses {
		if cs.ImageID != "" {
			m[cs.Name] = cs.ImageID
		}
	}
	return m
}

func collectPodObservation(pod *corev1.Pod, excludedNS map[string]bool, buffer *inventoryBuffer, retention time.Duration) bool {
	if pod == nil || excludedNS[pod.Namespace] {
		return false
	}
	if !includePodReports(pod, time.Now().UTC(), retention) {
		return false
	}

	imageIDs := buildImageIDMap(pod)
	changed := false

	if addObservedContainers(buffer, pod.Namespace, pod.Spec.InitContainers, imageIDs) {
		changed = true
	}
	if addObservedContainers(buffer, pod.Namespace, pod.Spec.Containers, imageIDs) {
		changed = true
	}

	for _, c := range pod.Spec.EphemeralContainers {
		imageRef, tag, digest := parseImageRef(c.Image, imageIDs[c.Name])
		if buffer.Observe(clusterImageInput{Namespace: pod.Namespace, ImageRef: imageRef, Tag: tag, Digest: digest}) {
			changed = true
		}
	}

	return changed
}

func collectEventObservation(event *corev1.Event, excludedNS map[string]bool, buffer *inventoryBuffer, minObservedAt time.Time, logger *slog.Logger) bool {
	if event == nil || excludedNS[event.Namespace] {
		return false
	}
	if !eventObservedAtOrAfter(event, minObservedAt) {
		if logger != nil {
			observedAt := eventObservationTime(event)
			logger.Debug("ignoring stale event observation",
				"namespace", event.Namespace,
				"name", event.Name,
				"reason", event.Reason,
				"observed_at", observedAt,
				"watch_started_at", minObservedAt,
			)
		}
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

func eventObservedAtOrAfter(event *corev1.Event, minObservedAt time.Time) bool {
	if event == nil || minObservedAt.IsZero() {
		return true
	}

	observedAt := eventObservationTime(event)
	if observedAt.IsZero() {
		return false
	}

	return !observedAt.Before(minObservedAt)
}

func eventObservationTime(event *corev1.Event) time.Time {
	if event == nil {
		return time.Time{}
	}

	if !event.EventTime.IsZero() {
		return event.EventTime.Time.UTC()
	}
	if event.Series != nil && !event.Series.LastObservedTime.IsZero() {
		return event.Series.LastObservedTime.Time.UTC()
	}
	if !event.LastTimestamp.IsZero() {
		return event.LastTimestamp.Time.UTC()
	}
	if !event.FirstTimestamp.IsZero() {
		return event.FirstTimestamp.Time.UTC()
	}
	if !event.CreationTimestamp.IsZero() {
		return event.CreationTimestamp.Time.UTC()
	}

	return time.Time{}
}

func shouldObserveEvent(event *corev1.Event) bool {
	if event == nil {
		return false
	}
	if event.InvolvedObject.Kind != "Pod" {
		return false
	}

	// Watch common pod lifecycle events that mention image refs.
	// Only Pulling, Pulled, and Failed events include the image reference
	// in the message. Created/Started messages contain container names,
	// not image refs (e.g. "Created container: scan").
	switch event.Reason {
	case "Pulling", "Pulled", "Failed":
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

	if match := eventImageHintRe.FindStringSubmatch(trimmed); len(match) == 2 {
		candidate := strings.TrimSpace(match[1])
		candidate = strings.TrimRight(candidate, ",.;:")
		if isLikelyImageRef(candidate) {
			return candidate
		}
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
		token = strings.Trim(token, ",.;()[]{}\"'`")
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
	if strings.HasSuffix(v, ":") {
		return false
	}
	return strings.Contains(v, "/") || strings.Contains(v, ":") || strings.Contains(v, "@sha256:")
}

func addObservedContainers(buffer *inventoryBuffer, namespace string, containers []corev1.Container, imageIDByContainer map[string]string) bool {
	changed := false
	for _, c := range containers {
		imageRef, tag, digest := parseImageRef(c.Image, imageIDByContainer[c.Name])
		if buffer.Observe(clusterImageInput{Namespace: namespace, ImageRef: imageRef, Tag: tag, Digest: digest}) {
			changed = true
		}
	}
	return changed
}

func collectClusterInventory(
	ctx context.Context,
	kubeClient kubernetes.Interface,
	excludedNS map[string]bool,
	retention time.Duration,
	logger *slog.Logger,
) (images, expired []clusterImageInput, err error) {
	// --- List all pods across all namespaces ---
	podList, err := kubeClient.CoreV1().Pods("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, nil, fmt.Errorf("list pods: %w", err)
	}
	logger.Debug("listed pods", "total", len(podList.Items))

	// --- Collect images from pods and workload definitions ---
	podImages, expiredPods := collectImages(podList.Items, excludedNS, retention, logger)
	logger.Debug("collected images from pods", "count", len(podImages), "expired", len(expiredPods))

	// --- Collect images from Deployments, StatefulSets, DaemonSets, Jobs, CronJobs ---
	workloadImages, expiredWorkloads, err := collectWorkloadImages(ctx, kubeClient, excludedNS, retention, logger)
	if err != nil {
		logger.Warn("failed to collect workload images", "error", err)
	} else {
		logger.Debug("collected images from workloads", "count", len(workloadImages), "expired", len(expiredWorkloads))
	}

	// --- Merge and deduplicate ---
	images = mergeImages(podImages, workloadImages)
	expired = mergeImages(expiredPods, expiredWorkloads)
	logger.Debug("collected unique images total", "count", len(images), "expired", len(expired))
	return images, expired, nil
}

func refreshInventoryBuffer(
	ctx context.Context,
	kubeClient kubernetes.Interface,
	excludedNS map[string]bool,
	buffer *inventoryBuffer,
	staleTTL time.Duration,
	retention time.Duration,
	logger *slog.Logger,
) (bool, error) {
	images, expired, err := collectClusterInventory(ctx, kubeClient, excludedNS, retention, logger)
	if err != nil {
		return false, err
	}

	changed := buffer.TouchAll(images)
	if buffer.ReconcileExpired(expired, images) {
		changed = true
	}
	if buffer.Evict(staleTTL) {
		changed = true
	}
	logger.Info("inventory buffer refreshed", "images", len(images), "expired", len(expired), "changed", changed)
	return changed, nil
}

// dropExpiredCompletedWorkloads removes buffered images that belong only to
// completed or failed Jobs (and their terminal Pods) past retention. The pod
// watcher and IMAGE_STALE_AFTER window must not keep those images alive.
func dropExpiredCompletedWorkloads(
	ctx context.Context,
	kubeClient kubernetes.Interface,
	excludedNS map[string]bool,
	buffer *inventoryBuffer,
	retention time.Duration,
	logger *slog.Logger,
) (bool, error) {
	images, expired, err := collectClusterInventory(ctx, kubeClient, excludedNS, retention, logger)
	if err != nil {
		return false, err
	}
	dropped := buffer.ReconcileExpired(expired, images)
	if dropped {
		logger.Info("removed expired completed workload images", "remaining", len(buffer.Snapshot()))
	}
	return dropped, nil
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

func completedWorkloadRetention(logger *slog.Logger) time.Duration {
	return parseDurationEnv("COMPLETED_WORKLOAD_RETENTION", 60*time.Minute, logger)
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
// Terminal Job-owned Pods are included only until completion plus retention;
// older ones are returned in expired so the inventory buffer can drop them.
func collectImages(pods []corev1.Pod, excludedNS map[string]bool, retention time.Duration, logger *slog.Logger) (images, expired []clusterImageInput) {
	now := time.Now().UTC()
	seen := make(map[string]struct{})
	expiredSeen := make(map[string]struct{})

	for i := range pods {
		pod := &pods[i]
		if excludedNS[pod.Namespace] {
			logger.Debug("skipping excluded namespace", "namespace", pod.Namespace, "pod", pod.Name)
			continue
		}

		if expiredTerminalJobPod(pod, now, retention) {
			completedAt, _ := podCompletionTime(pod)
			logger.Debug("skipping terminal job pod past retention",
				"namespace", pod.Namespace,
				"pod", pod.Name,
				"completed_at", completedAt,
				"retention", retention.String(),
			)
			expired = appendPodImages(expired, expiredSeen, pod)
			continue
		}

		images = appendPodImages(images, seen, pod)
	}

	return images, expired
}

func appendPodImages(images []clusterImageInput, seen map[string]struct{}, pod *corev1.Pod) []clusterImageInput {
	imageIDs := buildImageIDMap(pod)
	images = appendUniquePodContainerImages(images, seen, pod.Namespace, pod.Spec.InitContainers, imageIDs)
	images = appendUniquePodContainerImages(images, seen, pod.Namespace, pod.Spec.Containers, imageIDs)
	images = appendUniquePodEphemeralContainerImages(images, seen, pod.Namespace, pod.Spec.EphemeralContainers, imageIDs)
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
// If the imageID references a different repository than the spec image
// (e.g. containerd mirror redirect), the digest is discarded because it
// belongs to the redirected image, not the spec image.
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

	// If the imageID references a different repository than the spec image,
	// the digest belongs to a redirected/mirrored image and should not be
	// associated with the spec imageRef (avoids duplicate entries when
	// containerd transparently resolves a mirror to the upstream registry).
	if digest != "" && imageID != "" {
		if repo := imageIDRepo(imageID); repo != "" && repo != imageRef {
			digest = ""
		}
	}

	return
}

// imageIDRepo extracts the repository portion from a runtime imageID,
// stripping runtime prefixes and the @sha256: digest suffix.
func imageIDRepo(imageID string) string {
	id := strings.TrimSpace(imageID)
	if id == "" {
		return ""
	}
	for _, p := range []string{"docker-pullable://", "docker://", "containerd://", "cri-o://"} {
		id = strings.TrimPrefix(id, p)
	}
	if idx := strings.Index(id, "@"); idx != -1 {
		return id[:idx]
	}
	return ""
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

// collectWorkloadImages gathers images from common workload controllers.
// Active Jobs are included. Completed and failed Jobs are included only until
// completion time plus retention. CronJob templates are always included.
func collectWorkloadImages(ctx context.Context, kubeClient kubernetes.Interface, excludedNS map[string]bool, retention time.Duration, logger *slog.Logger) (images, expired []clusterImageInput, err error) {
	now := time.Now().UTC()

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

	// Collect from ReplicaSets (captures standalone or transient rollout states).
	replicaSets, err := kubeClient.AppsV1().ReplicaSets("").List(ctx, metav1.ListOptions{})
	if err != nil {
		logger.Warn("failed to list replicasets", "error", err)
	} else {
		for _, rs := range replicaSets.Items {
			if excludedNS[rs.Namespace] {
				continue
			}
			images = appendWorkloadPodSpecImages(images, rs.Namespace, rs.Spec.Template.Spec)
		}
	}

	// Collect from Jobs. Finished Jobs stay only until completion plus retention.
	jobs, err := kubeClient.BatchV1().Jobs("").List(ctx, metav1.ListOptions{})
	if err != nil {
		logger.Warn("failed to list jobs", "error", err)
	} else {
		for i := range jobs.Items {
			job := &jobs.Items[i]
			if excludedNS[job.Namespace] {
				continue
			}
			finished, completedAt := jobCompletion(job)
			if !finished || withinCompletedRetention(completedAt, now, retention) {
				images = appendWorkloadPodSpecImages(images, job.Namespace, job.Spec.Template.Spec)
				continue
			}
			logger.Debug("skipping completed job past retention",
				"namespace", job.Namespace,
				"job", job.Name,
				"completed_at", completedAt,
				"retention", retention.String(),
			)
			expired = appendWorkloadPodSpecImages(expired, job.Namespace, job.Spec.Template.Spec)
		}
	}

	// CronJob templates are the desired workload, not a completed run.
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

	return images, expired, nil
}

// jobCompletion reports whether a Job has succeeded or failed and the time it
// reached that state. Successful Jobs prefer status.completionTime. Failed
// Jobs use the Failed condition lastTransitionTime. A finished Job with no
// timestamp returns a zero time so callers treat the retention window as elapsed.
func jobCompletion(job *batchv1.Job) (finished bool, completedAt time.Time) {
	if job == nil {
		return false, time.Time{}
	}

	var failedAt time.Time
	failed := false
	for _, cond := range job.Status.Conditions {
		if cond.Status != corev1.ConditionTrue {
			continue
		}
		switch cond.Type {
		case batchv1.JobComplete:
			if job.Status.CompletionTime != nil && !job.Status.CompletionTime.IsZero() {
				return true, job.Status.CompletionTime.Time.UTC()
			}
			if !cond.LastTransitionTime.IsZero() {
				return true, cond.LastTransitionTime.Time.UTC()
			}
			return true, time.Time{}
		case batchv1.JobFailed:
			failed = true
			if !cond.LastTransitionTime.IsZero() {
				failedAt = cond.LastTransitionTime.Time.UTC()
			}
		}
	}
	if failed {
		return true, failedAt
	}
	return false, time.Time{}
}

func withinCompletedRetention(completedAt, now time.Time, retention time.Duration) bool {
	if completedAt.IsZero() || retention <= 0 {
		return false
	}
	return now.Before(completedAt.Add(retention))
}

func isJobOwnedPod(pod *corev1.Pod) bool {
	if pod == nil {
		return false
	}
	for _, ref := range pod.OwnerReferences {
		if ref.Kind != "Job" {
			continue
		}
		if ref.APIVersion == "" || strings.HasPrefix(ref.APIVersion, "batch/") {
			return true
		}
	}
	return false
}

func isTerminalPodPhase(phase corev1.PodPhase) bool {
	return phase == corev1.PodSucceeded || phase == corev1.PodFailed
}

func podCompletionTime(pod *corev1.Pod) (time.Time, bool) {
	if pod == nil {
		return time.Time{}, false
	}

	var latest time.Time
	note := func(state corev1.ContainerState) {
		if state.Terminated == nil || state.Terminated.FinishedAt.IsZero() {
			return
		}
		finished := state.Terminated.FinishedAt.Time.UTC()
		if finished.After(latest) {
			latest = finished
		}
	}
	for _, cs := range pod.Status.InitContainerStatuses {
		note(cs.State)
	}
	for _, cs := range pod.Status.ContainerStatuses {
		note(cs.State)
	}
	for _, cs := range pod.Status.EphemeralContainerStatuses {
		note(cs.State)
	}
	if latest.IsZero() {
		return time.Time{}, false
	}
	return latest, true
}

// includePodReports reports whether a pod's images belong in the live inventory.
// Non-Job pods are always included. Terminal Pods owned by a Job are kept only
// until their completion time plus retention.
func includePodReports(pod *corev1.Pod, now time.Time, retention time.Duration) bool {
	if pod == nil {
		return false
	}
	if !isJobOwnedPod(pod) || !isTerminalPodPhase(pod.Status.Phase) {
		return true
	}
	completedAt, ok := podCompletionTime(pod)
	if !ok {
		return false
	}
	return withinCompletedRetention(completedAt, now, retention)
}

func expiredTerminalJobPod(pod *corev1.Pod, now time.Time, retention time.Duration) bool {
	if pod == nil || !isJobOwnedPod(pod) || !isTerminalPodPhase(pod.Status.Phase) {
		return false
	}
	return !includePodReports(pod, now, retention)
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

// mergeImages deduplicates and merges two image lists by
// (namespace, imageRef, tag, digest), then normalizes digest preference.
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

	return normalizeImagesPreferDigests(merged)
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
