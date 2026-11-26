package main

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/daimoniac/suppline/internal/api"
	"github.com/daimoniac/suppline/internal/attestation"
	"github.com/daimoniac/suppline/internal/config"
	"github.com/daimoniac/suppline/internal/configedit"
	"github.com/daimoniac/suppline/internal/configreload"
	"github.com/daimoniac/suppline/internal/leader"
	"github.com/daimoniac/suppline/internal/malicious"
	"github.com/daimoniac/suppline/internal/mirror"
	"github.com/daimoniac/suppline/internal/observability"
	"github.com/daimoniac/suppline/internal/policy"
	policycatalog "github.com/daimoniac/suppline/internal/policy/catalog"
	"github.com/daimoniac/suppline/internal/queue"
	"github.com/daimoniac/suppline/internal/registry"
	"github.com/daimoniac/suppline/internal/runway"
	"github.com/daimoniac/suppline/internal/scanenqueue"
	"github.com/daimoniac/suppline/internal/scanner"
	"github.com/daimoniac/suppline/internal/statestore"
	"github.com/daimoniac/suppline/internal/triage"
	"github.com/daimoniac/suppline/internal/version"
	"github.com/daimoniac/suppline/internal/vexaudit"
	"github.com/daimoniac/suppline/internal/watcher"
	"github.com/daimoniac/suppline/internal/worker"
	"github.com/joho/godotenv"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

// Shutdown budget (ADR 0004): the pod's termination grace period must exceed
// shutdownTimeout.
const (
	shutdownTimeout = 60 * time.Second
	drainDelay      = 3 * time.Second
	apiDrainTimeout = 45 * time.Second

	databaseCheckInterval = 15 * time.Second
	databaseCheckTimeout  = 3 * time.Second
)

func run() error {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	// runCtx outlives the signal: on SIGTERM the API drains first, while the
	// worker still finishes the scans that in-flight requests wait for.
	runCtx, stopRun := context.WithCancel(context.Background())
	defer stopRun()

	_ = godotenv.Load()

	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("failed to load configuration: %w", err)
	}

	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}

	logger := observability.NewLogger(cfg.Observability.LogLevel)
	logger.Info("starting suppline",
		"regsync_path", cfg.RegsyncPath,
		"log_level", cfg.Observability.LogLevel)

	_ = observability.GetMetrics()
	logger.Debug("metrics initialized",
		"observability_port", cfg.Observability.Port)

	healthChecker := observability.NewHealthChecker(logger)

	healthChecker.RegisterComponent("config")
	healthChecker.RegisterComponent("queue")
	healthChecker.RegisterComponent("worker")
	healthChecker.RegisterComponent("trivy")
	healthChecker.RegisterComponent("database")
	healthChecker.RegisterComponent("watcher")
	if cfg.MirrorEnabled {
		healthChecker.RegisterComponent("mirror")
	}

	healthChecker.UpdateComponentHealth("config", observability.StatusHealthy, "")

	logger.Debug("health checker initialized")

	obsServer := observability.NewServer(cfg.Observability.Port, logger, healthChecker)

	go func() {
		if err := obsServer.Start(runCtx); err != nil {
			logger.Error("observability server error",
				"error", err.Error())
		}
	}()

	logger.Debug("observability server started",
		"observability_port", cfg.Observability.Port)

	logger.Debug("parsing regsync configuration",
		"path", cfg.RegsyncPath)
	regsyncCfg, err := config.ParseRegsync(cfg.RegsyncPath)
	if err != nil {
		return fmt.Errorf("failed to parse regsync config: %w", err)
	}
	logger.Debug("regsync configuration parsed",
		"sync_entries", len(regsyncCfg.Sync),
		"credentials", len(regsyncCfg.Creds))
	repositoryPolicies := policycatalog.NewConfigCatalog(regsyncCfg)

	logger.Debug("initializing state store")
	var store statestore.StateStoreQuery
	// A PostgreSQL switchover refuses connections for a few seconds; wait for
	// the new primary instead of exiting and being restarted.
	store, err = retryOpen(ctx, startupDBRetry, func() (*statestore.Store, error) {
		return statestore.NewPostgresStore(cfg.StateStore.PostgresURL)
	}, func(err error, next time.Duration) {
		logger.Warn("cannot reach PostgreSQL yet; retrying", "retry_in", next, "error", err.Error())
		healthChecker.UpdateComponentHealth("database", observability.StatusUnhealthy, "waiting for PostgreSQL: "+err.Error())
	})
	if err != nil {
		healthChecker.UpdateComponentHealth("database", observability.StatusUnhealthy, err.Error())
		return fmt.Errorf("failed to initialize postgres store: %w", err)
	}
	healthChecker.UpdateComponentHealth("database", observability.StatusHealthy, "")
	logger.Debug("state store initialized")

	logger.Debug("initializing task queue",
		"buffer_size", cfg.Queue.BufferSize)
	taskQueue := queue.NewInMemoryQueue(cfg.Queue.BufferSize)
	scanEnqueuer := scanenqueue.New(taskQueue, store)
	logger.Debug("task queue initialized")

	logger.Debug("initializing trivy scanner",
		"server_addr", cfg.Scanner.ServerAddr)
	cfg.Scanner.Logger = logger
	trivyScanner, err := scanner.NewTrivyScanner(cfg.Scanner)
	if err != nil {
		healthChecker.UpdateComponentHealth("trivy", observability.StatusUnhealthy, err.Error())
		return fmt.Errorf("failed to initialize trivy scanner: %w", err)
	}

	if err := trivyScanner.HealthCheck(ctx); err != nil {
		healthChecker.UpdateComponentHealth("trivy", observability.StatusUnhealthy, err.Error())
		return fmt.Errorf("trivy server not reachable at %s: %w", cfg.Scanner.ServerAddr, err)
	}
	healthChecker.UpdateComponentHealth("trivy", observability.StatusHealthy, "")
	logger.Debug("trivy scanner initialized and connected",
		"server_addr", cfg.Scanner.ServerAddr)

	if repositoryPolicies.UsesVEXRepo() {
		downloadVEXRepo(ctx, logger)
	}

	logger.Debug("initializing attestor",
		"key_configured", cfg.Attestation.Key != "")
	attestorConfig := attestation.AttestationConfig{
		KeyBased: attestation.KeyBasedConfig{
			Key: cfg.Attestation.Key,
		},
		CommandTimeout:    cfg.Attestation.CommandTimeout,
		AllowHTTPRegistry: cfg.Attestation.AllowHTTPRegistry,
		NewBundleFormat:   cfg.Attestation.NewBundleFormat,
	}

	attestor, err := attestation.NewSigstoreAttestor(attestorConfig, logger)
	if err != nil {
		return fmt.Errorf("failed to initialize attestor: %w", err)
	}
	attestor.SetSharedRepositories(func(repository string) bool {
		running := repositoryPolicies.Current()
		return running != nil && running.IsInPlace(repository)
	})
	logger.Debug("attestor initialized")

	logger.Debug("authenticating cosign with registries")
	if err := authenticateCosignRegistries(ctx, regsyncCfg, logger); err != nil {
		return fmt.Errorf("failed to authenticate cosign with registries: %w", err)
	}
	logger.Debug("cosign authenticated with all registries")

	logger.Debug("initializing policy engine")
	maliciousGate := regsyncCfg.MaliciousPackages.BlockEnabled()
	policyEngine, err := policy.NewEngine(logger, policy.PolicyConfig{
		Expression: "criticalCount == 0",
	}, policy.WithMaliciousGate(maliciousGate))
	if err != nil {
		return fmt.Errorf("failed to initialize policy engine: %w", err)
	}
	logger.Debug("policy engine initialized")

	logger.Debug("initializing registry client")
	registryClient, err := registry.NewClient(regsyncCfg, registry.WithConfigSource(repositoryPolicies.Current))
	if err != nil {
		return fmt.Errorf("failed to initialize registry client: %w", err)
	}
	logger.Debug("registry client initialized")

	logger.Debug("initializing registry watcher",
		"poll_interval", cfg.Worker.PollInterval,
		"rescan_interval", cfg.StateStore.RescanInterval)
	var tagRunway *runway.Runway
	if cfg.MirrorEnabled {
		holds, ok := registryClient.(runway.Holds)
		if !ok {
			return fmt.Errorf("registry client cannot write hold tags")
		}
		tagRunway = runway.New(runway.Config{
			Store:     store,
			Tagger:    registryClient,
			Scheduler: scanEnqueuer,
			Holds:     holds,
			RescanInterval: func(repository string) time.Duration {
				interval, err := repositoryPolicies.Current().GetRescanInterval(repository)
				if err != nil {
					return 0
				}
				return interval
			},
			Cooldown: func(repository string) time.Duration {
				// Configuration load already rejected an invalid cooldown.
				cooldown, _ := repositoryPolicies.Current().GetCooldown(repository)
				return cooldown
			},
			Released: func(repository, digest string) bool {
				return repositoryPolicies.Current().CooldownReleased(repository, digest)
			},
			Log: logger.With("module", "runway"),
		})
	}

	watcherConfig := watcher.Config{
		PollInterval:   cfg.Worker.PollInterval,
		RescanInterval: cfg.StateStore.RescanInterval,
		ConfigChanged:  repositoryPolicies.Changed,
	}
	if tagRunway != nil {
		watcherConfig.HeldDigests = tagRunway.HeldDigests
	}
	registryWatcher := watcher.NewWatcherWithCatalogAndEnqueuer(
		registryClient,
		repositoryPolicies.Current,
		store,
		taskQueue,
		scanEnqueuer,
		repositoryPolicies,
		watcherConfig,
		logger,
	)
	logger.Debug("registry watcher initialized")

	logger.Debug("initializing worker",
		"retry_attempts", cfg.Worker.RetryAttempts,
		"retry_backoff", cfg.Worker.RetryBackoff,
		"concurrency", cfg.Worker.Concurrency)
	workerConfig := worker.Config{
		RetryAttempts: cfg.Worker.RetryAttempts,
		RetryBackoff:  cfg.Worker.RetryBackoff,
		Concurrency:   cfg.Worker.Concurrency,
		// Reserved for CI scan requests and single-digest rescans.
		UrgentConcurrency: cfg.Worker.UrgentConcurrency,
	}
	workerInstance := worker.NewImageWorkerWithCatalog(
		taskQueue,
		trivyScanner,
		policyEngine,
		attestor,
		registryClient,
		store,
		workerConfig,
		logger,
		repositoryPolicies.Current,
		repositoryPolicies,
	)
	editTarget, err := triage.ConfigTarget(regsyncCfg.Triage, cfg.RegsyncPath)
	if err != nil {
		return fmt.Errorf("failed to resolve config edit target: %w", err)
	}
	configEditor := configedit.New(editTarget, repositoryPolicies, scanEnqueuer, logger.With("module", "configedit"))
	triageService, err := triage.New(regsyncCfg.Triage, cfg.RegsyncPath, repositoryPolicies, store, configEditor, logger)
	if err != nil {
		return fmt.Errorf("failed to initialize triage: %w", err)
	}
	triageService.SetImageLabels(registryClient)
	if err := triageService.ValidateStartup(); err != nil {
		return err
	}
	kevService := newKEVService(config.ResolveKEV(regsyncCfg.KEV, regsyncCfg.Triage), healthChecker, logger)
	if kevService != nil {
		triageService.SetKEV(kevService)
		go kevService.Run(runCtx)
	} else if triageService.NeedsKEV() {
		return fmt.Errorf("kev.enabled is false but triage.block_kev is on: enable the kev feed or set triage.block_kev: false")
	}
	workerInstance.SetPolicyFailureNotifier(triageService)
	if tagRunway != nil {
		workerInstance.SetScanObserver(tagRunway)
		workerInstance.SetCooldownClock(tagRunway)
		workerInstance.SetHeldDigests(tagRunway.HeldDigests)
	}
	logger.Debug("worker initialized")

	scanReads, ok := store.(*statestore.Store)
	if !ok {
		return fmt.Errorf("state store cannot serve the VEX audit")
	}
	// /health shows a PostgreSQL outage after startup too. Liveness uses
	// /live, so an outage does not restart the pods.
	go healthChecker.StartPeriodicChecks(runCtx, databaseCheckInterval, map[string]observability.HealthCheckFunc{
		"database": func(ctx context.Context) error {
			ctx, cancel := context.WithTimeout(ctx, databaseCheckTimeout)
			defer cancel()
			return scanReads.Ping(ctx)
		},
	})
	// The audit evaluates every current scan, so it keeps its own quiet logger.
	// The shared engine would record each of those checks as a real scan.
	quiet := slog.New(slog.DiscardHandler)
	vexAudit := vexaudit.New(logger, repositoryPolicies, scanReads, func(cfg policy.PolicyConfig) (policy.PolicyEngine, error) {
		if cfg.Expression == "" {
			return policy.NewEngine(quiet, policy.PolicyConfig{Expression: "criticalCount == 0"}, policy.WithMaliciousGate(maliciousGate))
		}
		return policy.NewEngine(quiet, cfg, policy.WithMaliciousGate(maliciousGate))
	})

	maliciousService, err := newMaliciousService(regsyncCfg.MaliciousPackages, healthChecker, logger)
	if err != nil {
		return fmt.Errorf("failed to initialize malicious-package detection: %w", err)
	}
	if maliciousService != nil {
		workerInstance.SetMaliciousChecker(maliciousService, maliciousGate)
	}

	logger.Debug("initializing API server",
		"port", cfg.API.Port,
		"read_only", cfg.API.ReadOnly)
	apiServer := api.NewAPIServerWithCatalogAndEnqueuer(
		&cfg.API,
		&cfg.Attestation,
		store,
		taskQueue,
		scanEnqueuer,
		repositoryPolicies.Current,
		repositoryPolicies,
		logger,
	)
	apiServer.SetTriage(triageService)
	apiServer.SetConfigEditor(configEditor)
	apiServer.SetVEXAudit(vexAudit)
	if maliciousService != nil {
		apiServer.SetMalicious(maliciousService, api.MaliciousSettings{
			Block:   maliciousGate,
			RepoURL: regsyncCfg.MaliciousPackages.RepoURL(),
			Ref:     regsyncCfg.MaliciousPackages.RepoRef(),
		})
	}
	logger.Debug("API server initialized")
	mirrorActivity := mirror.NewActivity()
	apiServer.SetMirror(cfg.MirrorEnabled, mirrorActivity)
	// CI scan requests wait on finished tasks of the digest they queued.
	scanRequests := api.NewScanRequestWaiter()
	workerInstance.SetTaskObserver(scanRequests)
	apiServer.SetScanRequests(registryClient, scanRequests)
	if tagRunway != nil {
		apiServer.SetHeldDigests(tagRunway)
	}

	var wg sync.WaitGroup
	errChan := make(chan error, 8)

	// Leader-only components stand by until this instance is elected.
	leaderOnly := []string{"queue", "worker", "watcher"}
	if cfg.MirrorEnabled {
		leaderOnly = append(leaderOnly, "mirror")
	}
	if maliciousService != nil {
		// Only the leader syncs the feed; its health stays unknown until then.
		leaderOnly = append(leaderOnly, malicious.HealthComponent)
	}
	for _, name := range leaderOnly {
		healthChecker.UpdateComponentHealth(name, observability.StatusStandby, "waiting for leadership")
	}
	healthChecker.SetRole(observability.RoleStandby)

	// Until elected, this instance forwards every API and UI request to the
	// leader. Set before the API server starts serving.
	holder := leader.NewHolderID()
	apiServer.SetLeaderProxy(observability.IsLeader, holder, scanReads)

	if apiServer != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			logger.Info("API server listening",
				"port", cfg.API.Port)
			if err := apiServer.Start(runCtx); err != nil && err != context.Canceled {
				logger.Error("API server error",
					"error", err.Error())
				errChan <- fmt.Errorf("API server error: %w", err)
			}
			logger.Debug("API server stopped")
		}()
	}

	// startLeader starts everything that must run on one instance only. ctx
	// ends with the process: a leader never steps down, it exits.
	startLeader := func(ctx context.Context) {
		observability.MarkLeader()
		healthChecker.SetRole(observability.RoleLeader)
		for _, name := range []string{"queue", "worker", "watcher"} {
			healthChecker.UpdateComponentHealth(name, observability.StatusHealthy, "")
		}
		if cfg.MirrorEnabled {
			// The mirror reports healthy once its registry client is ready.
			healthChecker.UpdateComponentHealth("mirror", observability.StatusUnknown, "starting")
		}

		// Seed the queue: failed in-use artifacts first (urgent), then work already
		// known to be due, so a new leader does not wait for a full discovery walk.
		// This runs in the background because it blocks once the queue buffer is
		// full, draining as the workers catch up; OnElected must not block.
		go func() {
			logger.Info("checking for failed artifacts to rescan")
			if err := enqueueFailedArtifacts(ctx, store, scanEnqueuer, cfg.Worker.PollInterval, logger); err != nil {
				logger.Error("failed to enqueue failed artifacts", "error", err)
			}
			if err := enqueueDueArtifacts(ctx, store, scanEnqueuer, cfg.StateStore.RescanInterval, logger); err != nil {
				logger.Error("failed to seed artifacts due for rescan", "error", err)
			}
		}()

		wg.Add(1)
		go func() {
			defer wg.Done()
			logger.Debug("starting registry watcher")
			if err := registryWatcher.Start(ctx); err != nil && err != context.Canceled {
				logger.Error("registry watcher error",
					"error", err.Error())
				errChan <- fmt.Errorf("registry watcher error: %w", err)
			}
			logger.Debug("registry watcher stopped")
		}()

		wg.Add(1)
		go func() {
			defer wg.Done()
			logger.Debug("starting triage")
			if err := triageService.Start(ctx); err != nil && err != context.Canceled {
				logger.Error("triage error", "error", err.Error())
				errChan <- fmt.Errorf("triage error: %w", err)
			}
			logger.Debug("triage stopped")
		}()

		wg.Add(1)
		go func() {
			defer wg.Done()
			vexAudit.Run(ctx)
		}()

		if maliciousService != nil {
			rematcher := malicious.NewRematcher(maliciousService, scanReads, maliciousRescanQueue{enqueuer: scanEnqueuer},
				observability.GetMetrics().MaliciousRescans, logger.With("module", "malicious"))
			maliciousService.OnUpdate(rematcher.Notify)
			wg.Add(2)
			go func() {
				defer wg.Done()
				rematcher.Run(ctx)
			}()
			go func() {
				defer wg.Done()
				maliciousService.Run(ctx)
			}()
		}

		wg.Add(1)
		go func() {
			defer wg.Done()
			configreload.Run(ctx, logger, cfg.RegsyncPath, configreload.Interval, func(parsed *config.RegsyncConfig) {
				changed := repositoryPolicies.Replace(parsed)
				logger.Info("reloaded suppline config", "path", cfg.RegsyncPath, "repositories_changed", len(changed))
				queued, err := scanEnqueuer.RequeueRepositories(ctx, changed)
				if err != nil {
					logger.Error("config reload requeue failed", "repositories", len(changed), "queued", queued, "error", err)
				}
				if queued > 0 {
					logger.Info("queued scans after config reload", "images", queued, "repositories", len(changed))
				}
			})
		}()

		wg.Add(1)
		go func() {
			defer wg.Done()
			logger.Debug("starting worker")
			if err := workerInstance.Start(ctx); err != nil && err != context.Canceled {
				logger.Error("worker error",
					"error", err.Error())
				errChan <- fmt.Errorf("worker error: %w", err)
			}
			logger.Debug("worker stopped")
		}()

		if cfg.MirrorEnabled {
			wg.Add(1)
			go func() {
				defer wg.Done()
				mirrorLog := logger.With("module", "regsync")
				mirrorLog.Info("starting in-process mirror")
				mirrorStore, _ := store.(statestore.MirrorStore)
				opts := []mirror.Option{mirror.WithStore(mirrorStore), mirror.WithActivity(mirrorActivity)}
				if inventory, ok := store.(mirror.ClusterInventory); ok {
					opts = append(opts, mirror.WithInventory(inventory))
				}
				if err := mirror.Run(ctx, regsyncCfg, logger, append(opts, mirror.WithReady(func() {
					healthChecker.UpdateComponentHealth("mirror", observability.StatusHealthy, "")
				}), mirror.WithRunway(tagRunway),
					mirror.WithReload(repositoryPolicies.Current, repositoryPolicies.Changed))...); err != nil && err != context.Canceled {
					mirrorLog.Error("mirror error", "error", err.Error())
					healthChecker.UpdateComponentHealth("mirror", observability.StatusUnhealthy, err.Error())
				}
				mirrorLog.Debug("mirror stopped")
			}()
		}

	}

	elector, err := leader.New(leader.Config{
		Lock:      scanReads.LeaderLock(),
		Holder:    holder,
		Address:   cfg.API.AdvertiseAddress,
		OnElected: startLeader,
		Logger:    logger.With("module", "leader"),
	})
	if err != nil {
		return fmt.Errorf("failed to initialize leader election: %w", err)
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		_ = elector.Run(runCtx)
	}()

	// Every instance, leader or standby, shows on the dashboard's cluster card.
	hostname, _ := os.Hostname()
	wg.Add(1)
	go func() {
		defer wg.Done()
		runHeartbeat(runCtx, scanReads, statestore.Instance{
			Holder:    holder,
			Hostname:  hostname,
			Address:   cfg.API.AdvertiseAddress,
			Version:   version.Version,
			StartedAt: time.Now(),
		}, func() string { return string(healthChecker.GetHealth().Status) }, heartbeatInterval, logger.With("module", "heartbeat"))
	}()

	logger.Info("started; leader-only components start once elected", "holder", elector.Holder())

	select {
	case <-ctx.Done():
		logger.Info("received shutdown signal")
	case err := <-errChan:
		logger.Error("component error, initiating shutdown",
			"error", err.Error())
	}

	logger.Info("shutting down gracefully", "timeout", shutdownTimeout)
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer shutdownCancel()

	// 1. Fail readiness so the Service stops sending new requests, and give
	//    endpoint updates a moment to reach the load balancers.
	healthChecker.SetDraining()
	select {
	case <-time.After(drainDelay):
	case <-shutdownCtx.Done():
	}
	// 2. Open scan-request long-polls answer 202 with their poll path; the
	//    client polls again and reaches the next leader.
	scanRequests.Close()
	// 3. Let in-flight requests finish while the worker keeps running.
	apiDrainCtx, apiDrainCancel := context.WithTimeout(shutdownCtx, apiDrainTimeout)
	if err := apiServer.Shutdown(apiDrainCtx); err != nil {
		logger.Warn("API requests still running after the drain timeout", "error", err.Error())
	}
	apiDrainCancel()

	// 4. Stop the components.
	stopRun()
	logger.Debug("waiting for components to stop")
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		logger.Info("all components stopped gracefully")
	case <-shutdownCtx.Done():
		logger.Warn("shutdown timeout exceeded, forcing exit")
	}

	// Components have stopped, so a standby may take over now.
	releaseCtx, releaseCancel := context.WithTimeout(context.Background(), 5*time.Second)
	if err := elector.Release(releaseCtx); err != nil {
		logger.Warn("failed to release leader lock; it ends with the session", "error", err.Error())
	}
	releaseCancel()

	queueDepth, _ := taskQueue.GetQueueDepth(shutdownCtx)
	if queueDepth > 0 {
		logger.Warn("queue not empty at shutdown",
			"remaining_tasks", queueDepth)
	} else {
		logger.Debug("queue drained successfully")
	}

	if err := obsServer.Shutdown(shutdownCtx); err != nil {
		logger.Error("error shutting down observability server",
			"error", err.Error())
	}

	if closer, ok := store.(interface{ Close() error }); ok {
		if err := closer.Close(); err != nil {
			logger.Error("error closing state store",
				"error", err.Error())
		}
	}

	logger.Info("shutdown complete")
	return nil
}

func downloadVEXRepo(ctx context.Context, logger *slog.Logger) {
	logger.Info("downloading Trivy VEX repository (Aqua VEX Hub)")
	cmd := exec.CommandContext(ctx, "trivy", "vex", "repo", "download")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		// Non-fatal: VEX repo download failure should not prevent scanning.
		// Trivy will fall back to non-VEX scanning for affected tasks.
		logger.Warn("failed to download VEX repository; VEX filtering will be unavailable",
			"error", err,
			"stderr", stderr.String())
	} else {
		logger.Info("VEX repository downloaded successfully")
	}
}

func authenticateCosignRegistries(ctx context.Context, regsyncCfg *config.RegsyncConfig, logger *slog.Logger) error {
	for _, cred := range regsyncCfg.Creds {
		if cred.Registry == "" || cred.User == "" || cred.Pass == "" {
			logger.Warn("skipping incomplete registry credential", "registry", cred.Registry)
			continue
		}

		// Extract just the registry host (in case registry contains a repository path)
		registryHost := strings.Split(cred.Registry, "/")[0]

		logger.Debug("authenticating cosign with registry", "registry", registryHost)

		cmd := exec.CommandContext(ctx, "cosign", "login", registryHost,
			"--username", cred.User,
			"--password", cred.Pass)

		var stderr bytes.Buffer
		cmd.Stderr = &stderr

		if err := cmd.Run(); err != nil {
			logger.Error("cosign login failed",
				"registry", cred.Registry,
				"error", err,
				"stderr", stderr.String())
			return fmt.Errorf("cosign login to %s failed: %w", cred.Registry, err)
		}
	}

	return nil
}
