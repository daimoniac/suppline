package mirror

import (
	"context"
	"errors"
	"log/slog"
	"sync"

	"github.com/robfig/cron/v3"

	"github.com/daimoniac/suppline/internal/config"
	"github.com/daimoniac/suppline/internal/runway"
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
}

// WithRunway copies a changed digest by digest and leaves the tag to the
// runway. Without one, the copy moves the tag immediately.
func WithRunway(r Runway) Option {
	return func(m *runner) {
		m.runway = r
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
	manifestMu sync.Mutex
	manifests  map[string]manifest.Manifest
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
