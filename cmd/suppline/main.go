package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/joho/godotenv"
	"github.com/suppline/suppline/internal/api"
	"github.com/suppline/suppline/internal/attestation"
	"github.com/suppline/suppline/internal/config"
	"github.com/suppline/suppline/internal/observability"
	"github.com/suppline/suppline/internal/policy"
	"github.com/suppline/suppline/internal/queue"
	"github.com/suppline/suppline/internal/registry"
	"github.com/suppline/suppline/internal/regsync"
	"github.com/suppline/suppline/internal/scanner"
	"github.com/suppline/suppline/internal/statestore"
	"github.com/suppline/suppline/internal/watcher"
	"github.com/suppline/suppline/internal/worker"
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

	// Load .env file if it exists (ignore error if file doesn't exist)
	_ = godotenv.Load()

	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("failed to load configuration: %w", err)
	}

	// Validate configuration
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}

	// Initialize logger with UTC timestamps
	logger := observability.NewLogger(cfg.Observability.LogLevel)
	logger.Info("starting suppline",
		"regsync_path", cfg.RegsyncPath,
		"log_level", cfg.Observability.LogLevel)

	// Initialize metrics
	_ = observability.GetMetrics()
	logger.Debug("metrics initialized",
		"metrics_port", cfg.Observability.MetricsPort)

	// Initialize health checker
	healthChecker := observability.NewHealthChecker(logger)

	// Register components for health checking
	healthChecker.RegisterComponent("config")
	healthChecker.RegisterComponent("queue")
	healthChecker.RegisterComponent("worker")
	healthChecker.RegisterComponent("trivy")
	healthChecker.RegisterComponent("database")
	healthChecker.RegisterComponent("watcher")

	// Mark config as healthy since we loaded it successfully
	healthChecker.UpdateComponentHealth("config", observability.StatusHealthy, "")

	logger.Info("health checker initialized",
		"health_port", cfg.Observability.HealthCheckPort)

	// Start observability server (metrics and health endpoints)
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

	logger.Info("observability server started",
		"metrics_port", cfg.Observability.MetricsPort,
		"health_port", cfg.Observability.HealthCheckPort)

	// Parse regsync configuration
	logger.Info("parsing regsync configuration",
		"path", cfg.RegsyncPath)
	regsyncCfg, err := regsync.Parse(cfg.RegsyncPath)
	if err != nil {
		return fmt.Errorf("failed to parse regsync config: %w", err)
	}
	logger.Info("regsync configuration parsed",
		"sync_entries", len(regsyncCfg.Sync),
		"credentials", len(regsyncCfg.Creds))

	// Initialize state store
	logger.Info("initializing state store",
		"type", cfg.StateStore.Type)
	var store statestore.StateStore
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
	logger.Info("state store initialized")

	// Initialize task queue
	logger.Info("initializing task queue",
		"buffer_size", cfg.Queue.BufferSize)
	taskQueue := queue.NewInMemoryQueue(cfg.Queue.BufferSize)
	healthChecker.UpdateComponentHealth("queue", observability.StatusHealthy, "")
	logger.Info("task queue initialized")

	// Initialize scanner
	logger.Info("initializing trivy scanner",
		"server_addr", cfg.Scanner.ServerAddr)
	trivyScanner, err := scanner.NewTrivyScanner(cfg.Scanner)
	if err != nil {
		healthChecker.UpdateComponentHealth("trivy", observability.StatusUnhealthy, err.Error())
		return fmt.Errorf("failed to initialize trivy scanner: %w", err)
	}

	// Check Trivy connectivity
	if err := trivyScanner.HealthCheck(ctx); err != nil {
		healthChecker.UpdateComponentHealth("trivy", observability.StatusUnhealthy, err.Error())
		logger.Warn("trivy server not reachable",
			"error", err.Error())
	} else {
		healthChecker.UpdateComponentHealth("trivy", observability.StatusHealthy, "")
		logger.Info("trivy scanner initialized and connected")
	}

	// Initialize attestor
	logger.Info("initializing attestor",
		"key_path", cfg.Attestation.KeyBased.KeyPath)
	attestorConfig := attestation.AttestationConfig{
		KeyBased: attestation.KeyBasedConfig{
			KeyPath:     cfg.Attestation.KeyBased.KeyPath,
			KeyPassword: cfg.Attestation.KeyBased.KeyPassword,
		},
	}
	
	// Build auth config from regsync credentials for attestor
	authConfig := make(map[string]authn.Authenticator)
	for _, cred := range regsyncCfg.Creds {
		if cred.User != "" && cred.Pass != "" {
			authConfig[cred.Registry] = &authn.Basic{
				Username: cred.User,
				Password: cred.Pass,
			}
		}
	}
	
	attestor, err := attestation.NewSigstoreAttestor(attestorConfig, authConfig)
	if err != nil {
		return fmt.Errorf("failed to initialize attestor: %w", err)
	}
	logger.Info("attestor initialized")

	// Initialize policy engine
	logger.Info("initializing policy engine")
	policyEngine := policy.NewEngine(logger)
	logger.Info("policy engine initialized")

	// Initialize registry client
	logger.Info("initializing registry client")
	registryClient, err := registry.NewClient(regsyncCfg)
	if err != nil {
		return fmt.Errorf("failed to initialize registry client: %w", err)
	}
	logger.Info("registry client initialized")

	// Initialize registry watcher
	logger.Info("initializing registry watcher",
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
	logger.Info("registry watcher initialized")

	// Initialize worker
	logger.Info("initializing worker",
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
	logger.Info("worker initialized")

	// Initialize API server if enabled
	var apiServer *api.APIServer
	if cfg.API.Enabled {
		logger.Info("initializing API server",
			"port", cfg.API.Port,
			"read_only", cfg.API.ReadOnly)
		apiServer = api.NewAPIServer(
			&cfg.API,
			store,
			taskQueue,
			cfg.RegsyncPath,
			logger,
		)
		logger.Info("API server initialized")
	}

	// Start all components
	var wg sync.WaitGroup
	errChan := make(chan error, 3)

	// Start registry watcher
	wg.Add(1)
	go func() {
		defer wg.Done()
		logger.Info("starting registry watcher")
		if err := registryWatcher.Start(ctx); err != nil && err != context.Canceled {
			logger.Error("registry watcher error",
				"error", err.Error())
			errChan <- fmt.Errorf("registry watcher error: %w", err)
		}
		logger.Info("registry watcher stopped")
	}()

	// Start worker
	wg.Add(1)
	go func() {
		defer wg.Done()
		logger.Info("starting worker")
		if err := workerInstance.Start(ctx); err != nil && err != context.Canceled {
			logger.Error("worker error",
				"error", err.Error())
			errChan <- fmt.Errorf("worker error: %w", err)
		}
		logger.Info("worker stopped")
	}()

	// Start API server if enabled
	if apiServer != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			logger.Info("starting API server",
				"port", cfg.API.Port)
			if err := apiServer.Start(ctx); err != nil && err != context.Canceled {
				logger.Error("API server error",
					"error", err.Error())
				errChan <- fmt.Errorf("API server error: %w", err)
			}
			logger.Info("API server stopped")
		}()
	}

	logger.Info("all components started successfully")

	// Wait for shutdown signal or error
	select {
	case <-ctx.Done():
		logger.Info("received shutdown signal")
	case err := <-errChan:
		logger.Error("component error, initiating shutdown",
			"error", err.Error())
		cancel()
	}

	// Graceful shutdown
	logger.Info("shutting down gracefully")

	// Create shutdown context with timeout
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()

	// Stop accepting new work (context already cancelled)
	logger.Info("waiting for components to stop")

	// Wait for all goroutines to finish with timeout
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

	// Drain remaining tasks from queue
	queueDepth, _ := taskQueue.GetQueueDepth(shutdownCtx)
	if queueDepth > 0 {
		logger.Warn("queue not empty at shutdown",
			"remaining_tasks", queueDepth)
	} else {
		logger.Info("queue drained successfully")
	}

	// Shutdown API server if enabled
	if apiServer != nil {
		if err := apiServer.Shutdown(shutdownCtx); err != nil {
			logger.Error("error shutting down API server",
				"error", err.Error())
		}
	}

	// Shutdown observability server
	if err := obsServer.Shutdown(shutdownCtx); err != nil {
		logger.Error("error shutting down observability server",
			"error", err.Error())
	}

	// Close state store
	if closer, ok := store.(interface{ Close() error }); ok {
		if err := closer.Close(); err != nil {
			logger.Error("error closing state store",
				"error", err.Error())
		}
	}

	logger.Info("shutdown complete")
	return nil
}
