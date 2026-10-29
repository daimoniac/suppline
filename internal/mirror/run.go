package mirror

import (
	"context"
	"errors"
	"log/slog"
	"sync"

	"github.com/robfig/cron/v3"

	"github.com/daimoniac/suppline/internal/config"
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

type runner struct {
	cfg        *config.RegsyncConfig
	log        *slog.Logger
	rc         *regclient.RegClient
	throttle   *gate
	hub        hubRepoAPI
	ready      func()
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

	var wg sync.WaitGroup
	c := cron.New(cron.WithChain(cron.SkipIfStillRunning(cron.DefaultLogger)))
	for _, s := range cfg.Sync {
		sched := s.Schedule
		if sched == "" && s.Interval != 0 {
			sched = "@every " + s.Interval.String()
		}
		if sched == "" {
			logger.Error("no schedule or interval found, ignoring",
				"source", s.Source, "target", s.Target, "type", s.Type)
			continue
		}
		logger.Debug("scheduled task", "source", s.Source, "target", s.Target, "type", s.Type, "sched", sched)
		_, err := c.AddFunc(sched, func() {
			logger.Debug("running task", "source", s.Source, "target", s.Target, "type", s.Type)
			wg.Add(1)
			defer wg.Done()
			if err := m.process(ctx, s, actionCopy); err != nil && !errors.Is(err, context.Canceled) {
				logger.Error("sync failed", "source", s.Source, "target", s.Target, "error", err.Error())
			}
		})
		if err != nil {
			logger.Error("failed to schedule cron", "source", s.Source, "target", s.Target, "sched", sched, "error", err.Error())
		}
		if cfg.Defaults.Parallel > 0 {
			wg.Go(func() {
				if err := m.process(ctx, s, actionMissing); err != nil && !errors.Is(err, context.Canceled) {
					logger.Error("missing sync failed", "source", s.Source, "target", s.Target, "error", err.Error())
				}
			})
		} else {
			if err := m.process(ctx, s, actionMissing); err != nil && !errors.Is(err, context.Canceled) {
				logger.Error("missing sync failed", "source", s.Source, "target", s.Target, "error", err.Error())
			}
		}
	}

	wg.Wait()
	if ctx.Err() != nil {
		return nil
	}
	if err := m.runCleanupForAllTargets(ctx); err != nil {
		logger.Error("startup cleanup encountered errors", "error", err.Error())
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
			if err := m.runCleanupRepos(ctx); err != nil && !errors.Is(err, context.Canceled) {
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
