package mirror

import (
	"context"
	"errors"
	"log/slog"
	"sync"

	"github.com/robfig/cron/v3"

	"github.com/daimoniac/suppline/internal/config"
	"github.com/daimoniac/suppline/internal/runway"
	"github.com/daimoniac/suppline/internal/statestore"
	"github.com/regclient/regclient"
	"github.com/regclient/regclient/types/manifest"
)

// Option configures Run.
type Option func(*runner)

// WithReady is called after the registry client is built and before the first copy.
func WithReady(fn func()) Option {
	return func(m *runner) {
		m.ready = fn
	}
}

// Runway decides when a tag may name a digest the mirror copied by digest,
// and moves the tag. Offer reports whether the tag now names the digest.
type Runway interface {
	Offer(ctx context.Context, c runway.Candidate) (bool, error)
	// Settle drops the candidates of a tag whose upstream digest the target
	// tag already names.
	Settle(ctx context.Context, repository, tag string)
	// Retain drops the candidates of tags upstream no longer has.
	Retain(ctx context.Context, repository string, upstreamTags []string)
	// Holding lists the digests whose hold tags cleanup must keep.
	Holding(ctx context.Context, repository string) (map[string]struct{}, error)
}

// WithRunway copies a changed digest by digest and leaves the tag to the
// runway. Without one, the copy moves the tag immediately.
func WithRunway(r Runway) Option {
	return func(m *runner) {
		m.runway = r
	}
}

// WithStore records sync health, current images, and cleanup deletions.
func WithStore(store statestore.MirrorStore) Option {
	return func(m *runner) {
		m.store = store
	}
}

// WithActivity publishes which syncs are currently running.
func WithActivity(activity *Activity) Option {
	return func(m *runner) {
		m.activity = activity
	}
}

type runner struct {
	cfg        *config.RegsyncConfig
	current    config.Source
	changed    func() <-chan struct{}
	log        *slog.Logger
	rc         *regclient.RegClient
	throttle   *gate
	hub        hubRepoAPI
	ready      func()
	runway     Runway
	store      statestore.MirrorStore
	activity   *Activity
	journal    *journal
	manifestMu sync.Mutex
	manifests  map[string]manifest.Manifest
	created    *createdCache
	inventory  ClusterInventory
}

// WithReload follows the running configuration. When a newly published
// snapshot changes what the mirror copies (sync entries, credentials or
// mirror defaults), the current schedule stops and a new one starts from the
// snapshot, beginning with a pass over missing tags. Snapshots that only
// change scan settings such as VEX or policy leave the schedule running.
func WithReload(current config.Source, changed func() <-chan struct{}) Option {
	return func(m *runner) {
		m.current = current
		m.changed = changed
	}
}

// Run copies configured images until ctx is cancelled.
// A failure to build the registry client for the first schedule is returned;
// later failures are logged and the mirror waits for the next configuration.
// Sync failures are logged.
func Run(ctx context.Context, cfg *config.RegsyncConfig, logger *slog.Logger, opts ...Option) error {
	if cfg == nil {
		return errors.New("mirror config is nil")
	}
	if logger == nil {
		logger = slog.Default()
	}
	logger = logger.With("module", "regsync")
	m := &runner{
		log:       logger,
		manifests: map[string]manifest.Manifest{},
		created:   newCreatedCache(),
	}
	for _, opt := range opts {
		opt(m)
	}

	for generation := 0; ; generation++ {
		var changed <-chan struct{}
		if m.changed != nil {
			changed = m.changed()
			if next := m.current(); next != nil {
				cfg = next
			}
		}
		genCtx, cancel := context.WithCancel(ctx)
		done := make(chan error, 1)
		go func(cfg *config.RegsyncConfig) { done <- m.runSchedule(genCtx, cfg) }(cfg)

		restarted, err := m.waitForChange(ctx, cfg, changed, done)
		cancel()
		if restarted {
			err = <-done
		}
		if err != nil {
			if generation == 0 {
				return err
			}
			logger.Error("mirror schedule failed; waiting for the next configuration", "error", err.Error())
			if !waitForNext(ctx, m.changed) {
				return nil
			}
			continue
		}
		if ctx.Err() != nil {
			return nil
		}
		logger.Info("mirror settings changed, restarting schedule")
	}
}

// waitForChange blocks until the schedule ends or a published snapshot changes
// mirror settings. restarted reports the latter; the schedule is still running.
func (m *runner) waitForChange(ctx context.Context, cfg *config.RegsyncConfig, changed <-chan struct{}, done <-chan error) (bool, error) {
	for {
		select {
		case err := <-done:
			return false, err
		case <-changed:
			changed = m.changed()
			if next := m.current(); next != nil && mirrorSettingsChanged(cfg, next) {
				return true, nil
			}
		case <-ctx.Done():
			return false, <-done
		}
	}
}

func waitForNext(ctx context.Context, changed func() <-chan struct{}) bool {
	if changed == nil {
		<-ctx.Done()
		return false
	}
	select {
	case <-changed():
		return true
	case <-ctx.Done():
		return false
	}
}

// runSchedule runs one mirror schedule over cfg until ctx is cancelled.
func (m *runner) runSchedule(ctx context.Context, cfg *config.RegsyncConfig) error {
	logger := m.log
	parallel := cfg.Defaults.Parallel
	if parallel < 1 {
		parallel = 1
	}
	m.cfg = cfg
	m.throttle = newGate(parallel)
	rc, err := newClient(cfg, logger)
	if err != nil {
		return err
	}
	m.rc = rc
	if m.ready != nil {
		m.ready()
		m.ready = nil
	}
	if m.store != nil {
		m.journal = newJournal(m.store, m.activity, cfg, logger)
		if err := m.journal.Bind(ctx); err != nil {
			logger.Error("failed to record mirror config", "error", err.Error())
		}
	}

	var wg sync.WaitGroup
	var startupMu sync.Mutex
	startupErr := map[string]error{}
	type startedSync struct {
		key    string
		target string
	}
	var started []startedSync
	c := cron.New(cron.WithChain(cron.SkipIfStillRunning(cron.DefaultLogger)))
	for i, s := range cfg.Sync {
		key := ""
		if m.journal != nil && i < len(m.journal.entries) {
			key = m.journal.entries[i].key
		}
		sched := s.Schedule
		if sched == "" && s.Interval != 0 {
			sched = "@every " + s.Interval.String()
		}
		if sched == "" {
			logger.Error("no schedule or interval found, ignoring",
				"source", s.Source, "target", s.Target, "type", s.Type)
			continue
		}
		runCtx := ctx
		if key != "" {
			runCtx = withSyncKey(ctx, key)
			started = append(started, startedSync{key: key, target: s.Target})
		}
		logger.Debug("scheduled task", "source", s.Source, "target", s.Target, "type", s.Type, "sched", sched)
		_, err := c.AddFunc(sched, func() {
			logger.Debug("running task", "source", s.Source, "target", s.Target, "type", s.Type)
			wg.Add(1)
			defer wg.Done()
			if m.journal != nil {
				m.journal.Begin(key)
			}
			err := m.process(runCtx, s, actionCopy)
			if m.journal != nil {
				m.journal.Finish(runCtx, key, err)
			}
			if err != nil && !errors.Is(err, context.Canceled) {
				logger.Error("sync failed", "source", s.Source, "target", s.Target, "error", err.Error())
			}
		})
		if err != nil {
			logger.Error("failed to schedule cron", "source", s.Source, "target", s.Target, "sched", sched, "error", err.Error())
		}
		recordMissing := func() {
			if m.journal != nil {
				m.journal.Begin(key)
			}
			err := m.process(runCtx, s, actionMissing)
			if err != nil && !errors.Is(err, context.Canceled) {
				startupMu.Lock()
				startupErr[key] = err
				startupMu.Unlock()
				logger.Error("missing sync failed", "source", s.Source, "target", s.Target, "error", err.Error())
			}
		}
		if cfg.Defaults.Parallel > 0 {
			wg.Go(recordMissing)
		} else {
			recordMissing()
		}
	}

	wg.Wait()
	if ctx.Err() != nil {
		if m.journal != nil {
			for _, item := range started {
				m.journal.Abandon(item.key)
			}
		}
		return nil
	}
	if err := m.runCleanupForAllTargets(ctx); err != nil {
		logger.Error("startup cleanup encountered errors", "error", err.Error())
	}
	if m.journal != nil {
		for _, item := range started {
			startupMu.Lock()
			err := startupErr[item.key]
			startupMu.Unlock()
			if cleanupErr := m.journal.cleanupError(item.target); cleanupErr != nil {
				err = errors.Join(err, cleanupErr)
			}
			m.journal.Finish(ctx, item.key, err)
		}
	}
	if cfg.Defaults.CleanupRepos != nil && *cfg.Defaults.CleanupRepos {
		sched := cfg.Defaults.CleanupReposSchedule
		if sched == "" {
			sched = "0 4 * * *"
		}
		logger.Info("scheduling cleanupRepos", "sched", sched)
		if _, err := c.AddFunc(sched, func() {
			wg.Add(1)
			defer wg.Done()
			err := m.runCleanupRepos(ctx)
			if m.journal != nil && !errors.Is(err, context.Canceled) {
				message := ""
				if err != nil {
					message = err.Error()
				}
				m.journal.SetHubError(ctx, message)
			}
			if err != nil && !errors.Is(err, context.Canceled) {
				logger.Error("cleanupRepos failed", "error", err.Error())
			}
		}); err != nil {
			logger.Error("failed to schedule cleanupRepos", "sched", sched, "error", err.Error())
		}
	}

	c.Start()
	<-ctx.Done()
	logger.Info("stopping mirror")
	c.Stop()
	wg.Wait()
	return nil
}
