package mirror

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/daimoniac/suppline/internal/config"
	"github.com/daimoniac/suppline/internal/statestore"
)

type syncKeyCtx struct{}

func withSyncKey(ctx context.Context, key string) context.Context {
	return context.WithValue(ctx, syncKeyCtx{}, key)
}

func syncKeyFrom(ctx context.Context) string {
	key, _ := ctx.Value(syncKeyCtx{}).(string)
	return key
}

// Activity is the in-memory set of syncs whose run has not finished.
// A restart drops it, so a crashed run does not stay running.
type Activity struct {
	mu      sync.Mutex
	running map[string]struct{}
}

// NewActivity returns an empty running set.
func NewActivity() *Activity {
	return &Activity{running: map[string]struct{}{}}
}

// Mark records that a sync run is in progress.
func (a *Activity) Mark(key string) {
	if a == nil || key == "" {
		return
	}
	a.mu.Lock()
	a.running[key] = struct{}{}
	a.mu.Unlock()
}

// Clear removes a sync from the running set.
func (a *Activity) Clear(key string) {
	if a == nil || key == "" {
		return
	}
	a.mu.Lock()
	delete(a.running, key)
	a.mu.Unlock()
}

// Running reports whether a sync run is in progress.
func (a *Activity) Running(key string) bool {
	if a == nil || key == "" {
		return false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	_, ok := a.running[key]
	return ok
}

type journal struct {
	store    statestore.MirrorStore
	activity *Activity
	log      *slog.Logger
	entries  []keyedSync

	mu         sync.Mutex
	observed   map[string]map[string]struct{}
	listingOK  map[string]bool
	cleanupErr map[string]error
}

func newJournal(store statestore.MirrorStore, activity *Activity, cfg *config.RegsyncConfig, logger *slog.Logger) *journal {
	if logger == nil {
		logger = slog.Default()
	}
	entries := []keyedSync{}
	if cfg != nil {
		entries = assignSyncKeys(cfg.Sync)
	}
	return &journal{
		store:      store,
		activity:   activity,
		log:        logger,
		entries:    entries,
		observed:   map[string]map[string]struct{}{},
		listingOK:  map[string]bool{},
		cleanupErr: map[string]error{},
	}
}

func (j *journal) Bind(ctx context.Context) error {
	if j == nil || j.store == nil {
		return nil
	}
	syncs := make([]statestore.MirrorSync, len(j.entries))
	for i, entry := range j.entries {
		syncs[i] = statestore.MirrorSync{
			Key:      entry.key,
			Source:   entry.entry.Source,
			Target:   entry.entry.Target,
			Type:     entry.entry.Type,
			Schedule: entry.schedule,
			Position: entry.position,
		}
	}
	if err := j.store.ReplaceMirrorSyncs(ctx, syncs); err != nil {
		return err
	}
	return nil
}

func (j *journal) Begin(key string) {
	if j == nil || key == "" {
		return
	}
	j.mu.Lock()
	j.observed[key] = map[string]struct{}{}
	j.listingOK[key] = true
	j.mu.Unlock()
	j.activity.Mark(key)
}

func (j *journal) FailListing(key string) {
	if j == nil || key == "" {
		return
	}
	j.mu.Lock()
	j.listingOK[key] = false
	j.mu.Unlock()
}

func (j *journal) Observe(ctx context.Context, runningKey, repository, tag string, at time.Time) {
	if j == nil || j.store == nil || repository == "" || tag == "" {
		return
	}
	j.mu.Lock()
	if runningKey != "" {
		if j.observed[runningKey] == nil {
			j.observed[runningKey] = map[string]struct{}{}
		}
		j.observed[runningKey][repository+"\x1f"+tag] = struct{}{}
	}
	entries := append([]keyedSync(nil), j.entries...)
	j.mu.Unlock()

	keys := map[string]struct{}{}
	if runningKey != "" {
		keys[runningKey] = struct{}{}
	}
	for _, entry := range entries {
		if entryWantsImage(entry.entry, repository, tag) {
			keys[entry.key] = struct{}{}
		}
	}
	for key := range keys {
		if err := j.store.ObserveMirrorImage(ctx, key, repository, tag, at); err != nil {
			j.log.Error("failed to record mirrored image", "sync", key, "repository", repository, "tag", tag, "error", err.Error())
		}
	}
}

func (j *journal) RecordTagDeletion(ctx context.Context, repository, tag string, at time.Time) {
	if j == nil || j.store == nil || repository == "" || tag == "" {
		return
	}
	for _, entry := range j.syncsTargeting(repository) {
		if err := j.store.RecordMirrorTagDeletion(ctx, entry.key, repository, tag, at); err != nil {
			j.log.Error("failed to record tag deletion", "sync", entry.key, "repository", repository, "tag", tag, "error", err.Error())
		}
	}
}

func (j *journal) RecordHubDeletion(ctx context.Context, repository string, at time.Time) {
	if j == nil || j.store == nil || repository == "" {
		return
	}
	if err := j.store.RecordMirrorHubDeletion(ctx, repository, at); err != nil {
		j.log.Error("failed to record hub deletion", "repository", repository, "error", err.Error())
	}
}

func (j *journal) SetHubError(ctx context.Context, message string) {
	if j == nil || j.store == nil {
		return
	}
	if err := j.store.SetMirrorHubError(ctx, message); err != nil {
		j.log.Error("failed to record hub cleanup error", "error", err.Error())
	}
}

func (j *journal) NoteCleanupError(target string, err error) {
	if j == nil || target == "" || err == nil {
		return
	}
	j.mu.Lock()
	j.cleanupErr[target] = err
	j.mu.Unlock()
}

func (j *journal) cleanupError(target string) error {
	if j == nil {
		return nil
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.cleanupErr[target]
}

func (j *journal) Finish(ctx context.Context, key string, runErr error) {
	if j == nil || key == "" {
		return
	}
	defer j.activity.Clear(key)
	if errors.Is(runErr, context.Canceled) || (ctx != nil && ctx.Err() != nil) {
		return
	}
	if j.store == nil {
		return
	}
	j.mu.Lock()
	listingOK := j.listingOK[key]
	observed := j.observed[key]
	j.mu.Unlock()
	if listingOK {
		keep := make([]statestore.MirrorImage, 0, len(observed))
		for image := range observed {
			repo, tag, ok := splitImageKey(image)
			if !ok {
				continue
			}
			keep = append(keep, statestore.MirrorImage{Repository: repo, Tag: tag})
		}
		if err := j.store.PruneMirrorImages(ctx, key, keep); err != nil {
			j.log.Error("failed to prune mirrored images", "sync", key, "error", err.Error())
		}
	}
	status := "ok"
	message := ""
	if runErr != nil {
		status = "failed"
		message = runErr.Error()
	}
	if err := j.store.FinishMirrorSync(ctx, key, status, message, time.Now()); err != nil {
		j.log.Error("failed to record mirror sync status", "sync", key, "error", err.Error())
	}
}

func (j *journal) Abandon(key string) {
	if j == nil {
		return
	}
	j.activity.Clear(key)
}

func (j *journal) syncsTargeting(repository string) []keyedSync {
	if j == nil {
		return nil
	}
	var out []keyedSync
	for _, entry := range j.entries {
		if entryTargetsRepository(entry.entry, repository) {
			out = append(out, entry)
		}
	}
	return out
}

func splitImageKey(image string) (string, string, bool) {
	for i := 0; i < len(image); i++ {
		if image[i] == '\x1f' {
			return image[:i], image[i+1:], true
		}
	}
	return "", "", false
}
