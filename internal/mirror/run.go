package mirror

import (
	"context"
	"errors"
	"log/slog"
	"sync"

	"github.com/robfig/cron/v3"

	"github.com/daimoniac/suppline/internal/config"
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
	log        *slog.Logger
	rc         *regclient.RegClient
	throttle   *gate
	hub        hubRepoAPI
	ready      func()
	store      statestore.MirrorStore
	activity   *Activity
	journal    *journal
	manifestMu sync.Mutex
	manifests  map[string]manifest.Manifest
}

// Run copies configured images until ctx is cancelled.
// A failure to build the registry client is returned. Sync failures are logged.
func Run(ctx context.Context, cfg *config.RegsyncConfig, logger *slog.Logger, opts ...Option) error {
	if cfg == nil {
		return errors.New("mirror config is nil")
	}
	if logger == nil {
		logger = slog.Default()
	}
	logger = logger.With("module", "regsync")
	parallel := cfg.Defaults.Parallel
	if parallel < 1 {
		parallel = 1
	}
	m := &runner{
		cfg:       cfg,
		log:       logger,
		throttle:  newGate(parallel),
		manifests: map[string]manifest.Manifest{},
	}
	for _, opt := range opts {
		opt(m)
	}
	rc, err := newClient(cfg, logger)
	if err != nil {
		return err
	}
	m.rc = rc
	if m.ready != nil {
		m.ready()
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
