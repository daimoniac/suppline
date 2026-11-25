// Package testpg gives tests a fresh PostgreSQL database each.
//
// Tests need SUPPLINE_TEST_POSTGRES_URL, a URL with rights to create
// databases. `make test` starts a throwaway server and sets it. Each test
// binary migrates one template database once, and every Database call clones
// it with CREATE DATABASE … TEMPLATE, which is much faster than migrating.
package testpg

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
)

// EnvURL names the variable holding the server URL.
const EnvURL = "SUPPLINE_TEST_POSTGRES_URL"

// Migrate creates the schema in the database at url.
type Migrate func(url string) error

var (
	templateOnce sync.Once
	templateName string
	templateErr  error
)

// Database creates an empty database migrated by migrate, drops it when the
// test ends, and returns its URL. migrate must be the same function for every
// call in one test binary: it runs once, on the template.
func Database(t testing.TB, migrate Migrate) string {
	t.Helper()
	base := os.Getenv(EnvURL)
	if base == "" {
		t.Fatalf("%s is not set: run `make test`, or point it at a PostgreSQL server that allows CREATE DATABASE", EnvURL)
	}

	templateOnce.Do(func() {
		templateName, templateErr = createTemplate(base, migrate)
	})
	if templateErr != nil {
		t.Fatalf("prepare template database: %v", templateErr)
	}

	name := "suppline_t_" + randomSuffix()
	if err := admin(base, func(ctx context.Context, db *sql.DB) error {
		_, err := db.ExecContext(ctx, fmt.Sprintf(`CREATE DATABASE %s TEMPLATE %s`, name, templateName))
		return err
	}); err != nil {
		t.Fatalf("create test database: %v", err)
	}
	t.Cleanup(func() {
		_ = admin(base, func(ctx context.Context, db *sql.DB) error {
			_, err := db.ExecContext(ctx, fmt.Sprintf(`DROP DATABASE IF EXISTS %s WITH (FORCE)`, name))
			return err
		})
	})
	return withDatabase(base, name)
}

func createTemplate(base string, migrate Migrate) (string, error) {
	name := "suppline_tmpl_" + randomSuffix()
	if err := admin(base, func(ctx context.Context, db *sql.DB) error {
		_, err := db.ExecContext(ctx, `CREATE DATABASE `+name)
		return err
	}); err != nil {
		return "", fmt.Errorf("create %s: %w", name, err)
	}
	if err := migrate(withDatabase(base, name)); err != nil {
		return "", fmt.Errorf("migrate %s: %w", name, err)
	}
	// Cloning needs a template nobody is connected to. migrate closed its own
	// connections; force out anything a pool left behind.
	if err := admin(base, func(ctx context.Context, db *sql.DB) error {
		_, err := db.ExecContext(ctx, `SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = $1 AND pid <> pg_backend_pid()`, name)
		return err
	}); err != nil {
		return "", fmt.Errorf("disconnect %s: %w", name, err)
	}
	return name, nil
}

func admin(base string, fn func(context.Context, *sql.DB) error) error {
	db, err := sql.Open("pgx", base)
	if err != nil {
		return err
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return fn(ctx, db)
}

func withDatabase(base, name string) string {
	u, err := url.Parse(base)
	if err != nil || u.Scheme == "" {
		// Key/value DSN.
		return strings.TrimSpace(base) + " dbname=" + name
	}
	u.Path = "/" + name
	return u.String()
}

func randomSuffix() string {
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}
