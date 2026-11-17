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
	"slices"
	"sort"
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
	// Workloads names the pod owners running this image as "Kind/name", e.g.
	// "StatefulSet/cortex-memcached-blocks" or "Deployment/api". Sorted, unique.
	Workloads []string `json:"workloads,omitempty"`
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
	// lastRefresh is when a full cluster listing last touched every live image.
	lastRefresh time.Time
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

// mergeWorkloads returns the sorted union of two workload lists.
func mergeWorkloads(a, b []string) []string {
	if len(a) == 0 && len(b) == 0 {
		return nil
	}
	set := make(map[string]struct{}, len(a)+len(b))
	for _, w := range a {
		if w = strings.TrimSpace(w); w != "" {
			set[w] = struct{}{}
		}
	}
	for _, w := range b {
		if w = strings.TrimSpace(w); w != "" {
			set[w] = struct{}{}
		}
	}
	if len(set) == 0 {
		return nil
	}
	out := make([]string, 0, len(set))
	for w := range set {
		out = append(out, w)
	}
	sort.Strings(out)
	return out
}

// podWorkload names the controller that owns a pod as "Kind/name". A pod from a
// Deployment's ReplicaSet is reported as the Deployment, using the
// pod-template-hash suffix of the ReplicaSet name. A pod without a controller
// is reported as "Pod/name".
func podWorkload(pod *corev1.Pod) string {
	if pod == nil {
		return ""
	}
	for _, ref := range pod.OwnerReferences {
		if ref.Controller == nil || !*ref.Controller {
			continue
		}
		if ref.Kind == "ReplicaSet" {
			if hash := pod.Labels["pod-template-hash"]; hash != "" && strings.HasSuffix(ref.Name, "-"+hash) {
				return "Deployment/" + strings.TrimSuffix(ref.Name, "-"+hash)
			}
		}
		return ref.Kind + "/" + ref.Name
	}
	return "Pod/" + pod.Name
}

// isManagedPod reports whether a long-running controller (Deployment via
// ReplicaSet, StatefulSet, DaemonSet, an operator, ...) owns the pod. Such pods
// are replaced, not finished, so their images are reported straight from the
// pod watch cache and disappear with the pod. Bare pods and Job pods are
// buffered instead, so short-lived runs stay visible for their retention.
func isManagedPod(pod *corev1.Pod) bool {
	if pod == nil || isJobOwnedPod(pod) {
		return false
	}
	for _, ref := range pod.OwnerReferences {
		if ref.Controller != nil && *ref.Controller {
			return true
		}
	}
	return false
}

// managedPodImages returns the images of managed pods that are not finished,
// one entry per image key with every workload running it. Evicted or failed
// pods are left out: they no longer run their image.
func managedPodImages(pods []*corev1.Pod, excludedNS map[string]bool) []clusterImageInput {
	images := make([]clusterImageInput, 0)
	seen := make(map[string]int)
	for _, pod := range pods {
		if pod == nil || excludedNS[pod.Namespace] || !isManagedPod(pod) || isTerminalPodPhase(pod.Status.Phase) {
			continue
		}
		images = appendPodImages(images, seen, pod)
	}
	return images
}

// podImageSignature identifies what a managed pod contributes to the snapshot,
// so watch updates that change nothing (most status updates) send nothing.
func podImageSignature(pod *corev1.Pod) string {
	if pod == nil || !isManagedPod(pod) || isTerminalPodPhase(pod.Status.Phase) {
		return ""
	}
	keys := make([]string, 0)
	for _, img := range appendPodImages(nil, map[string]int{}, pod) {
		keys = append(keys, imageKey(img))
	}
	sort.Strings(keys)
	return strings.Join(keys, "\n")
}

func imageIdentityKey(img clusterImageInput) string {
	return img.Namespace + "|" + img.ImageRef + "|" + img.Tag
}

// normalizeImagesPreferDigests removes digest-less duplicates for an
// image identity (namespace, imageRef, tag) when digest-bearing entries exist,
// and drops entries without a namespace or image reference.
// Distinct digests for the same identity are preserved.
func normalizeImagesPreferDigests(images []clusterImageInput) []clusterImageInput {
	if len(images) == 0 {
		return nil
	}

	order := make([]string, 0, len(images))
	groups := make(map[string][]clusterImageInput)
	hasDigest := make(map[string]bool)

	for _, img := range images {
		// suppline rejects a snapshot with an entry that lacks either field, so
		// one malformed spec (e.g. image ":tag" in an old ReplicaSet) would
		// block the whole cluster's inventory.
		if strings.TrimSpace(img.Namespace) == "" || strings.TrimSpace(img.ImageRef) == "" {
			continue
		}
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
	indexByKey := make(map[string]int)
	for _, identity := range order {
		for _, img := range groups[identity] {
			if hasDigest[identity] && strings.TrimSpace(img.Digest) == "" {
				continue
			}

			key := imageKey(img)
			if i, exists := indexByKey[key]; exists {
				result[i].Workloads = mergeWorkloads(result[i].Workloads, img.Workloads)
				continue
			}
			indexByKey[key] = len(result)
			img.Workloads = mergeWorkloads(nil, img.Workloads)
			result = append(result, img)
		}
	}

	return result
}

func (b *inventoryBuffer) Add(img clusterImageInput) bool {
	return b.AddAt(img, time.Now().UTC())
}

// AddAt records an image observed at a past time, e.g. from a Kubernetes
// event. The entry ages from that time, so replaying old events on startup
// does not extend how long their images are reported.
func (b *inventoryBuffer) AddAt(img clusterImageInput, at time.Time) bool {
	b.mu.Lock()
	defer b.mu.Unlock()

	if _, blocked := b.blocked[imageIdentityKey(img)]; blocked {
		return false
	}
	return b.addLocked(img, at)
}

// Observe records an image from a live pod. A current pod is authoritative, so
// this clears any completed-workload block for the same identity.
func (b *inventoryBuffer) Observe(img clusterImageInput) bool {
	b.mu.Lock()
	defer b.mu.Unlock()

	delete(b.blocked, imageIdentityKey(img))
	return b.addLocked(img, time.Now().UTC())
}

func (b *inventoryBuffer) addLocked(img clusterImageInput, at time.Time) bool {
	key := imageKey(img)
	if existing, ok := b.seen[key]; ok {
		updated := existing.img
		enriched := false
		if existing.img.Tag == "" && img.Tag != "" {
			updated.Tag = img.Tag
			enriched = true
		}
		if workloads := mergeWorkloads(existing.img.Workloads, img.Workloads); len(workloads) != len(existing.img.Workloads) {
			updated.Workloads = workloads
			enriched = true
		}
		lastSeen := existing.lastSeen
		if at.After(lastSeen) {
			lastSeen = at
		}
		b.seen[key] = seenEntry{img: updated, lastSeen: lastSeen}
		return enriched
	}

	b.seen[key] = seenEntry{img: img, lastSeen: at}
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
			// A full listing names every current owner, so it replaces the
			// owners pod watch events accumulated, dropping deleted workloads.
			if len(img.Workloads) > 0 && !slices.Equal(updated.Workloads, img.Workloads) {
				updated.Workloads = img.Workloads
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

// MarkRefreshed records that a full cluster listing touched every live image
// at now.
func (b *inventoryBuffer) MarkRefreshed(now time.Time) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.lastRefresh = now
}

// EvictStale removes entries not seen for ttl, but only while the last full
// listing is younger than ttl. Every live image was touched by that listing,
// so an entry older than ttl is no longer in the cluster. Without a recent
// listing a long-running pod and a deleted one look alike, so nothing is
// removed. Returns true if any entries were removed.
func (b *inventoryBuffer) EvictStale(ttl time.Duration, now time.Time) bool {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.lastRefresh.IsZero() || now.Sub(b.lastRefresh) >= ttl {
		return false
	}
	cutoff := now.Add(-ttl)
	changed := false
	for key, entry := range b.seen {
		if entry.lastSeen.Before(cutoff) {
			delete(b.seen, key)
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
	refreshInterval = effectiveRefreshInterval(refreshInterval, staleTTL, logger)

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

	if _, err := podInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			pod, ok := obj.(*corev1.Pod)
			if !ok {
				return
			}
			if collectPodObservation(pod, excludedNS, buffer, completedRetention) {
				signalSend()
			}
			if !excludedNS[pod.Namespace] && podImageSignature(pod) != "" {
				signalSend()
			}
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			pod, ok := newObj.(*corev1.Pod)
			if !ok {
				return
			}
			if collectPodObservation(pod, excludedNS, buffer, completedRetention) {
				signalSend()
			}
			// A managed pod that started on a new digest, or finished or was
			// evicted, changes the snapshot read from the watch cache.
			oldPod, _ := oldObj.(*corev1.Pod)
			if !excludedNS[pod.Namespace] && podImageSignature(oldPod) != podImageSignature(pod) {
				signalSend()
			}
		},
		DeleteFunc: func(obj interface{}) {
			// The pod is already gone from the watch cache, so the next
			// snapshot drops its images unless another pod still runs them.
			pod, ok := obj.(*corev1.Pod)
			if !ok {
				tombstone, isTombstone := obj.(cache.DeletedFinalStateUnknown)
				if !isTombstone {
					return
				}
				if pod, ok = tombstone.Obj.(*corev1.Pod); !ok {
					return
				}
			}
			if !excludedNS[pod.Namespace] && isManagedPod(pod) {
				signalSend()
			}
		},
	}); err != nil {
		return fmt.Errorf("register pod informer handler: %w", err)
	}

	if _, err := eventInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			event, ok := obj.(*corev1.Event)
			if !ok {
				return
			}
			if collectEventObservation(event, excludedNS, buffer, time.Now().UTC().Add(-staleTTL), logger) {
				signalSend()
			}
		},
		UpdateFunc: func(_, newObj interface{}) {
			event, ok := newObj.(*corev1.Event)
			if !ok {
				return
			}
			if collectEventObservation(event, excludedNS, buffer, time.Now().UTC().Add(-staleTTL), logger) {
				signalSend()
			}
		},
	}); err != nil {
		return fmt.Errorf("register event informer handler: %w", err)
	}

	stopCh := make(chan struct{})
	defer close(stopCh)
	factory.Start(stopCh)

	if !cache.WaitForCacheSync(stopCh, podInformer.HasSynced, eventInformer.HasSynced) {
		return fmt.Errorf("failed to sync informer caches")
	}

	// snapshot joins the images of live managed pods, read from the watch cache,
	// with the buffered images of bare pods, Job pods, events and workload specs.
	snapshot := func() []clusterImageInput {
		pods := make([]*corev1.Pod, 0)
		for _, obj := range podInformer.GetStore().List() {
			if pod, ok := obj.(*corev1.Pod); ok {
				pods = append(pods, pod)
			}
		}
		return normalizeImagesPreferDigests(append(managedPodImages(pods, excludedNS), buffer.Snapshot()...))
	}

	attemptSend := func(force bool) error {
		images := snapshot()
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
			// Images from pods that are gone stop being reported once
			// IMAGE_STALE_AFTER has passed, not only at the next full refresh.
			evicted := buffer.EvictStale(staleTTL, time.Now().UTC())
			if evicted {
				logger.Info("evicted images not seen within stale TTL", "stale_ttl", staleTTL.String())
			}
			dropped, err := dropExpiredCompletedWorkloads(ctx, kubeClient, excludedNS, buffer, completedRetention, logger)
			if err != nil {
				logger.Warn("failed to drop expired completed workloads", "error", err)
				if !evicted {
					continue
				}
			}
			if !dropped && !evicted {
				continue
			}

			pendingSend = true
			pendingForceSend = len(snapshot()) == 0
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
			pendingForceSend = len(snapshot()) == 0
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

// collectPodObservation buffers the images of bare and Job pods. Managed pods
// are not buffered; snapshots read them from the pod watch cache.
func collectPodObservation(pod *corev1.Pod, excludedNS map[string]bool, buffer *inventoryBuffer, retention time.Duration) bool {
	if pod == nil || excludedNS[pod.Namespace] || isManagedPod(pod) {
		return false
	}
	if !includePodReports(pod, time.Now().UTC(), retention) {
		return false
	}

	imageIDs := buildImageIDMap(pod)
	workloads := []string{podWorkload(pod)}
	changed := addObservedContainers(buffer, pod.Namespace, workloads, pod.Spec.InitContainers, imageIDs)
	if addObservedContainers(buffer, pod.Namespace, workloads, pod.Spec.Containers, imageIDs) {
		changed = true
	}

	for _, c := range pod.Spec.EphemeralContainers {
		for _, img := range containerImages(pod.Namespace, c.Image, imageIDs[c.Name], workloads) {
			if buffer.Observe(img) {
				changed = true
			}
		}
	}

	return changed
}

// collectEventObservation buffers the image named by a pull event observed at
// or after minObservedAt. The entry ages from the event's own time.
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
	observedAt := eventObservationTime(event)
	if observedAt.IsZero() || observedAt.After(time.Now().UTC()) {
		observedAt = time.Now().UTC()
	}
	return buffer.AddAt(clusterImageInput{Namespace: event.Namespace, ImageRef: imageRef, Tag: tag, Digest: digest}, observedAt)
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
		return event.EventTime.UTC()
	}
	if event.Series != nil && !event.Series.LastObservedTime.IsZero() {
		return event.Series.LastObservedTime.UTC()
	}
	if !event.LastTimestamp.IsZero() {
		return event.LastTimestamp.UTC()
	}
	if !event.FirstTimestamp.IsZero() {
		return event.FirstTimestamp.UTC()
	}
	if !event.CreationTimestamp.IsZero() {
		return event.CreationTimestamp.UTC()
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

func addObservedContainers(buffer *inventoryBuffer, namespace string, workloads []string, containers []corev1.Container, imageIDByContainer map[string]string) bool {
	changed := false
	for _, c := range containers {
		for _, img := range containerImages(namespace, c.Image, imageIDByContainer[c.Name], workloads) {
			if buffer.Observe(img) {
				changed = true
			}
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
) (images, managed, expired []clusterImageInput, err error) {
	// --- List all pods across all namespaces ---
	podList, err := kubeClient.CoreV1().Pods("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, nil, nil, fmt.Errorf("list pods: %w", err)
	}
	logger.Debug("listed pods", "total", len(podList.Items))

	// --- Collect images from pods and workload definitions ---
	podImages, managed, expiredPods := collectImages(podList.Items, excludedNS, retention, logger)
	logger.Debug("collected images from pods", "count", len(podImages), "managed", len(managed), "expired", len(expiredPods))

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
	return images, managed, expired, nil
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
	images, managed, expired, err := collectClusterInventory(ctx, kubeClient, excludedNS, retention, logger)
	if err != nil {
		return false, err
	}

	// Taken before TouchAll, so every touched entry is at least this recent.
	refreshedAt := time.Now().UTC()
	changed := buffer.TouchAll(images)
	buffer.MarkRefreshed(refreshedAt)
	if buffer.ReconcileExpired(expired, append(images, managed...)) {
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
	images, managed, expired, err := collectClusterInventory(ctx, kubeClient, excludedNS, retention, logger)
	if err != nil {
		return false, err
	}
	dropped := buffer.ReconcileExpired(expired, append(images, managed...))
	if dropped {
		logger.Info("removed expired completed workload images", "remaining", len(buffer.Snapshot()))
	}
	return dropped, nil
}

// effectiveRefreshInterval keeps full refreshes at least twice per stale TTL.
// Stale entries can only be evicted while the last refresh is younger than the
// TTL (see EvictStale), so a longer interval would keep gone images alive.
func effectiveRefreshInterval(refresh, staleTTL time.Duration, logger *slog.Logger) time.Duration {
	limit := staleTTL / 2
	if limit < time.Minute {
		limit = time.Minute
	}
	if refresh <= limit {
		return refresh
	}
	if logger != nil {
		logger.Info("shortening refresh interval to half the stale TTL",
			"configured", refresh.String(),
			"effective", limit.String(),
			"stale_ttl", staleTTL.String(),
		)
	}
	return limit
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
func collectImages(pods []corev1.Pod, excludedNS map[string]bool, retention time.Duration, logger *slog.Logger) (images, managed, expired []clusterImageInput) {
	now := time.Now().UTC()
	seen := make(map[string]int)
	expiredSeen := make(map[string]int)
	managedPods := make([]*corev1.Pod, 0)

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
		if isManagedPod(pod) {
			managedPods = append(managedPods, pod)
			continue
		}

		images = appendPodImages(images, seen, pod)
	}

	return images, managedPodImages(managedPods, excludedNS), expired
}

// appendPodImages adds each container image of pod once per image key; seen maps
// a key to its index in images so later pods add their workload to it.
func appendPodImages(images []clusterImageInput, seen map[string]int, pod *corev1.Pod) []clusterImageInput {
	imageIDs := buildImageIDMap(pod)
	workload := podWorkload(pod)
	for _, c := range pod.Spec.InitContainers {
		images = appendPodImage(images, seen, pod.Namespace, workload, c.Image, imageIDs[c.Name])
	}
	for _, c := range pod.Spec.Containers {
		images = appendPodImage(images, seen, pod.Namespace, workload, c.Image, imageIDs[c.Name])
	}
	for _, c := range pod.Spec.EphemeralContainers {
		images = appendPodImage(images, seen, pod.Namespace, workload, c.Image, imageIDs[c.Name])
	}
	return images
}

func appendPodImage(images []clusterImageInput, seen map[string]int, namespace, workload, image, imageID string) []clusterImageInput {
	for _, img := range containerImages(namespace, image, imageID, []string{workload}) {
		key := imageKey(img)
		if i, exists := seen[key]; exists {
			images[i].Workloads = mergeWorkloads(images[i].Workloads, img.Workloads)
			continue
		}
		seen[key] = len(images)
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
	imageRef, tag, digests := parseImageRefDigests(image, imageID)
	if len(digests) > 0 {
		digest = digests[0]
	}
	return imageRef, tag, digest
}

// parseImageRefDigests is parseImageRef keeping every digest the container is known by:
// the runtime imageID digest first, then the spec's inline digest when it differs.
// Admission verifies the digest the spec names, so it is never discarded. A runtime
// digest from a redirected repository is.
func parseImageRefDigests(image, imageID string) (imageRef, tag string, digests []string) {
	imageRef, tag, specDigest := splitImageRef(image)

	runtimeDigest := ""
	if imageID != "" {
		runtimeDigest = extractDigestFromImageID(imageID)
		// If the imageID references a different repository than the spec image,
		// the digest belongs to a redirected/mirrored image and should not be
		// associated with the spec imageRef (avoids duplicate entries when
		// containerd transparently resolves a mirror to the upstream registry).
		// Docker Hub shorthand is expanded first: a spec "org/app" and an
		// imageID "docker.io/org/app@sha256:..." name the same repository.
		if repo := imageIDRepo(imageID); repo != "" && canonicalRepository(repo) != canonicalRepository(imageRef) {
			runtimeDigest = ""
		}
	}

	if runtimeDigest != "" {
		digests = append(digests, runtimeDigest)
	}
	if specDigest != "" && specDigest != runtimeDigest {
		digests = append(digests, specDigest)
	}
	return imageRef, tag, digests
}

// splitImageRef separates the repository, tag, and inline digest of an image string.
func splitImageRef(image string) (imageRef, tag, digest string) {
	imageRef = image

	// Strip inline digest from image reference (e.g. nginx:1.25@sha256:...).
	if idx := strings.LastIndex(image, "@"); idx != -1 {
		candidate := image[idx+1:]
		if strings.Contains(candidate, ":") {
			digest = candidate
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

// canonicalRepository expands Docker Hub shorthand so nginx, library/nginx, and
// docker.io/library/nginx compare equal.
func canonicalRepository(repo string) string {
	repo = strings.ToLower(strings.TrimSpace(repo))
	parts := strings.SplitN(repo, "/", 2)
	if len(parts) == 1 || (!strings.ContainsAny(parts[0], ".:") && parts[0] != "localhost") {
		repo = "docker.io/" + repo
	}
	for _, alias := range []string{"index.docker.io/", "registry-1.docker.io/"} {
		if strings.HasPrefix(repo, alias) {
			repo = "docker.io/" + strings.TrimPrefix(repo, alias)
		}
	}
	if path := strings.TrimPrefix(repo, "docker.io/"); path != repo && !strings.Contains(path, "/") {
		repo = "docker.io/library/" + path
	}
	return repo
}

// containerImages returns one inventory entry per digest a container is known by,
// or a single digest-less entry. workloads, when set, names the pod's owner.
func containerImages(namespace, image, imageID string, workloads []string) []clusterImageInput {
	imageRef, tag, digests := parseImageRefDigests(image, imageID)
	if len(digests) == 0 {
		return []clusterImageInput{{Namespace: namespace, ImageRef: imageRef, Tag: tag, Workloads: workloads}}
	}
	out := make([]clusterImageInput, 0, len(digests))
	for _, digest := range digests {
		out = append(out, clusterImageInput{Namespace: namespace, ImageRef: imageRef, Tag: tag, Digest: digest, Workloads: workloads})
	}
	return out
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
			// Old rollout revisions are scaled to zero. Their images are not
			// running; reporting them made old versions look in use.
			if rs.Spec.Replicas != nil && *rs.Spec.Replicas == 0 {
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
				return true, job.Status.CompletionTime.UTC()
			}
			if !cond.LastTransitionTime.IsZero() {
				return true, cond.LastTransitionTime.UTC()
			}
			return true, time.Time{}
		case batchv1.JobFailed:
			failed = true
			if !cond.LastTransitionTime.IsZero() {
				failedAt = cond.LastTransitionTime.UTC()
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
		finished := state.Terminated.FinishedAt.UTC()
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

// appendWorkloadPodSpecImages adds a template's images. An inline @sha256: digest is
// kept: it is what admission verifies when the controller creates the next pod, even
// while no pod of the template is running (e.g. a pinned CronJob between runs).
func appendWorkloadPodSpecImages(images []clusterImageInput, namespace string, spec corev1.PodSpec) []clusterImageInput {
	for _, c := range spec.InitContainers {
		images = append(images, containerImages(namespace, c.Image, "", nil)...)
	}
	for _, c := range spec.Containers {
		images = append(images, containerImages(namespace, c.Image, "", nil)...)
	}
	for _, c := range spec.EphemeralContainers {
		images = append(images, containerImages(namespace, c.Image, "", nil)...)
	}
	return images
}

// mergeImages deduplicates and merges two image lists by
// (namespace, imageRef, tag, digest), then normalizes digest preference.
func mergeImages(list1, list2 []clusterImageInput) []clusterImageInput {
	merged := make([]clusterImageInput, 0, len(list1)+len(list2))
	merged = append(merged, list1...)
	merged = append(merged, list2...)
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
