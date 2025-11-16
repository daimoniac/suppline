package main

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/joho/godotenv"
	"github.com/daimoniac/suppline/daimoniac/suppline/internal/api"
	"github.com/daimoniac/suppline/daimoniac/suppline/internal/attestation"
	"github.com/daimoniac/suppline/daimoniac/suppline/internal/config"
	"github.com/daimoniac/suppline/daimoniac/suppline/internal/observability"
	"github.com/daimoniac/suppline/daimoniac/suppline/internal/policy"
	"github.com/daimoniac/suppline/daimoniac/suppline/internal/queue"
	"github.com/daimoniac/suppline/daimoniac/suppline/internal/registry"
	"github.com/daimoniac/suppline/daimoniac/suppline/internal/scanner"
	"github.com/daimoniac/suppline/daimoniac/suppline/internal/statestore"
	"github.com/daimoniac/suppline/daimoniac/suppline/internal/watcher"
	"github.com/daimoniac/suppline/daimoniac/suppline/internal/worker"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	_ = godotenv.Load()

	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("failed to load configuration: %w", err)
	}

	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}

	logger := observability.NewLogger(cfg.Observability.LogLevel)
	logger.Info("starting daimoniac/suppline",
		"regsync_path", cfg.RegsyncPath,
		"log_level", cfg.Observability.LogLevel)

	_ = observability.GetMetrics()
	logger.Debug("metrics initialized",
		"metrics_port", cfg.Observability.MetricsPort)

	healthChecker := observability.NewHealthChecker(logger)

	healthChecker.RegisterComponent("config")
	healthChecker.RegisterComponent("queue")
	healthChecker.RegisterComponent("worker")
	healthChecker.RegisterComponent("trivy")
	healthChecker.RegisterComponent("database")
	healthChecker.RegisterComponent("watcher")

	healthChecker.UpdateComponentHealth("config", observability.StatusHealthy, "")

	logger.Debug("health checker initialized",
		"health_port", cfg.Observability.HealthCheckPort)

	obsServer := observability.NewServer(
		cfg.Observability.MetricsPort,
		cfg.Observability.HealthCheckPort,
		logger,
		healthChecker,
	)

	go func() {
		if err := obsServer.Start(ctx); err != nil {
			logger.Error("observability server error",
				"error", err.Error())
		}
	}()

	logger.Debug("observability server started",
		"metrics_port", cfg.Observability.MetricsPort,
		"health_port", cfg.Observability.HealthCheckPort)

	logger.Debug("parsing regsync configuration",
		"path", cfg.RegsyncPath)
	regsyncCfg, err := config.ParseRegsync(cfg.RegsyncPath)
	if err != nil {
		return fmt.Errorf("failed to parse regsync config: %w", err)
	}
	logger.Debug("regsync configuration parsed",
		"sync_entries", len(regsyncCfg.Sync),
		"credentials", len(regsyncCfg.Creds))

	logger.Debug("initializing state store",
		"type", cfg.StateStore.Type)
	var store statestore.StateStoreQuery
	switch cfg.StateStore.Type {
	case "sqlite":
		store, err = statestore.NewSQLiteStore(cfg.StateStore.SQLitePath)
		if err != nil {
			healthChecker.UpdateComponentHealth("database", observability.StatusUnhealthy, err.Error())
			return fmt.Errorf("failed to initialize sqlite store: %w", err)
		}
	case "postgres":
		return fmt.Errorf("postgres state store not yet implemented")
	case "memory":
		return fmt.Errorf("memory state store not yet implemented")
	default:
		return fmt.Errorf("unsupported state store type: %s", cfg.StateStore.Type)
	}
	healthChecker.UpdateComponentHealth("database", observability.StatusHealthy, "")
	logger.Debug("state store initialized")

	logger.Debug("initializing task queue",
		"buffer_size", cfg.Queue.BufferSize)
	taskQueue := queue.NewInMemoryQueue(cfg.Queue.BufferSize)
	healthChecker.UpdateComponentHealth("queue", observability.StatusHealthy, "")
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
		logger.Warn("trivy server not reachable",
			"error", err.Error())
	} else {
		healthChecker.UpdateComponentHealth("trivy", observability.StatusHealthy, "")
		logger.Debug("trivy scanner initialized and connected")
	}

	logger.Debug("initializing attestor",
		"key_path", cfg.Attestation.KeyBased.KeyPath)
	attestorConfig := attestation.AttestationConfig{
		KeyBased: attestation.KeyBasedConfig{
			KeyPath:     cfg.Attestation.KeyBased.KeyPath,
			KeyPassword: cfg.Attestation.KeyBased.KeyPassword,
		},
	}
	
	attestor, err := attestation.NewSigstoreAttestor(attestorConfig, logger)
	if err != nil {
		return fmt.Errorf("failed to initialize attestor: %w", err)
	}
	logger.Debug("attestor initialized")

	logger.Debug("authenticating cosign with registries")
	if err := authenticateCosignRegistries(ctx, regsyncCfg, logger); err != nil {
		return fmt.Errorf("failed to authenticate cosign with registries: %w", err)
	}
	logger.Debug("cosign authenticated with all registries")

	logger.Debug("initializing policy engine")
	policyEngine, err := policy.NewEngine(logger, policy.PolicyConfig{
		Expression: "criticalCount == 0",
	})
	if err != nil {
		return fmt.Errorf("failed to initialize policy engine: %w", err)
	}
	logger.Debug("policy engine initialized")

	logger.Debug("initializing registry client")
	registryClient, err := registry.NewClient(regsyncCfg)
	if err != nil {
		return fmt.Errorf("failed to initialize registry client: %w", err)
	}
	logger.Debug("registry client initialized")

	logger.Debug("initializing registry watcher",
		"poll_interval", cfg.Worker.PollInterval,
		"rescan_interval", cfg.StateStore.RescanInterval)
	watcherConfig := watcher.Config{
		PollInterval:   cfg.Worker.PollInterval,
		RescanInterval: cfg.StateStore.RescanInterval,
	}
	registryWatcher := watcher.NewWatcher(
		registryClient,
		regsyncCfg,
		store,
		taskQueue,
		watcherConfig,
		logger,
	)
	healthChecker.UpdateComponentHealth("watcher", observability.StatusHealthy, "")
	logger.Debug("registry watcher initialized")

	logger.Debug("initializing worker",
		"retry_attempts", cfg.Worker.RetryAttempts,
		"retry_backoff", cfg.Worker.RetryBackoff)
	workerConfig := worker.Config{
		RetryAttempts: cfg.Worker.RetryAttempts,
		RetryBackoff:  cfg.Worker.RetryBackoff,
	}
	workerInstance := worker.NewImageWorker(
		taskQueue,
		trivyScanner,
		policyEngine,
		attestor,
		registryClient,
		store,
		workerConfig,
		logger,
		regsyncCfg,
	)
	healthChecker.UpdateComponentHealth("worker", observability.StatusHealthy, "")
	logger.Debug("worker initialized")

	var apiServer *api.APIServer
	if cfg.API.Enabled {
		logger.Debug("initializing API server",
			"port", cfg.API.Port,
			"read_only", cfg.API.ReadOnly)
		apiServer = api.NewAPIServer(
			&cfg.API,
			store,
			taskQueue,
			cfg.RegsyncPath,
			logger,
		)
		logger.Debug("API server initialized")
	}

	var wg sync.WaitGroup
	errChan := make(chan error, 3)

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
		logger.Debug("starting worker")
		if err := workerInstance.Start(ctx); err != nil && err != context.Canceled {
			logger.Error("worker error",
				"error", err.Error())
			errChan <- fmt.Errorf("worker error: %w", err)
		}
		logger.Debug("worker stopped")
	}()

	if apiServer != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			logger.Info("API server listening",
				"port", cfg.API.Port)
			if err := apiServer.Start(ctx); err != nil && err != context.Canceled {
				logger.Error("API server error",
					"error", err.Error())
				errChan <- fmt.Errorf("API server error: %w", err)
			}
			logger.Debug("API server stopped")
		}()
	}

	logger.Info("all components started successfully")

	select {
	case <-ctx.Done():
		logger.Info("received shutdown signal")
	case err := <-errChan:
		logger.Error("component error, initiating shutdown",
			"error", err.Error())
		cancel()
	}

	logger.Info("shutting down gracefully")

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()

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

	queueDepth, _ := taskQueue.GetQueueDepth(shutdownCtx)
	if queueDepth > 0 {
		logger.Warn("queue not empty at shutdown",
			"remaining_tasks", queueDepth)
	} else {
		logger.Debug("queue drained successfully")
	}

	if apiServer != nil {
		if err := apiServer.Shutdown(shutdownCtx); err != nil {
			logger.Error("error shutting down API server",
				"error", err.Error())
		}
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

func authenticateCosignRegistries(ctx context.Context, regsyncCfg *config.RegsyncConfig, logger *slog.Logger) error {
	for _, cred := range regsyncCfg.Creds {
		if cred.Registry == "" || cred.User == "" || cred.Pass == "" {
			logger.Warn("skipping incomplete registry credential", "registry", cred.Registry)
			continue
		}

		logger.Debug("authenticating cosign with registry", "registry", cred.Registry)

		cmd := exec.CommandContext(ctx, "cosign", "login", cred.Registry,
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
