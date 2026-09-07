package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"github.com/daimoniac/suppline/internal/statestore"
	"github.com/joho/godotenv"
)

func runCopySQLite(ctx context.Context) error {
	_ = godotenv.Load()

	sqlitePath := os.Getenv("SQLITE_PATH")
	postgresURL := os.Getenv("POSTGRES_URL")
	if sqlitePath == "" || postgresURL == "" {
		return fmt.Errorf("SQLITE_PATH and POSTGRES_URL are required for copy-sqlite")
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	logger.Info("copying sqlite catalog into postgres", "sqlite_path", sqlitePath)
	return statestore.CopySQLiteToPostgres(ctx, sqlitePath, postgresURL, logger)
}
