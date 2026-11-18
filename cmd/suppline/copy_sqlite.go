package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"github.com/daimoniac/suppline/internal/config"
	"github.com/daimoniac/suppline/internal/statestore"
	"github.com/joho/godotenv"
)

// runCopySQLite copies the SQLite catalog at store.sqlitePath (suppline.yml)
// into the PostgreSQL database at POSTGRES_URL.
func runCopySQLite(ctx context.Context) error {
	_ = godotenv.Load()

	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("load configuration: %w", err)
	}
	sqlitePath := cfg.StateStore.SQLitePath
	postgresURL := cfg.StateStore.PostgresURL
	if postgresURL == "" {
		return fmt.Errorf("POSTGRES_URL is required for copy-sqlite")
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	logger.Info("copying sqlite catalog into postgres", "sqlite_path", sqlitePath)
	return statestore.CopySQLiteToPostgres(ctx, sqlitePath, postgresURL, logger)
}
