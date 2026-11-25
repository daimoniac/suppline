// Package storetest opens a state store on a fresh PostgreSQL database for
// tests outside package statestore.
package storetest

import (
	"testing"

	"github.com/daimoniac/suppline/internal/statestore"
	"github.com/daimoniac/suppline/internal/testpg"
)

// URL returns the URL of a fresh, migrated database that is dropped when the
// test ends. Open it more than once to test reopening.
func URL(t testing.TB) string {
	t.Helper()
	return testpg.Database(t, migrate)
}

// New opens a store on a fresh, migrated database and closes it when the
// test ends.
func New(t testing.TB) *statestore.SQLiteStore {
	t.Helper()
	store, err := statestore.NewPostgresStore(URL(t))
	if err != nil {
		t.Fatalf("open test store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func migrate(url string) error {
	store, err := statestore.NewPostgresStore(url)
	if err != nil {
		return err
	}
	return store.Close()
}
