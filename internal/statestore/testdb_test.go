package statestore

import (
	"testing"

	"github.com/daimoniac/suppline/internal/testpg"
)

// testDatabaseURL returns the URL of a fresh, migrated database that is
// dropped when the test ends.
func testDatabaseURL(t testing.TB) string {
	t.Helper()
	return testpg.Database(t, func(url string) error {
		store, err := NewPostgresStore(url)
		if err != nil {
			return err
		}
		return store.Close()
	})
}

// newTestStore opens a store on a fresh database and closes it when the
// test ends.
func newTestStore(t testing.TB) *Store {
	t.Helper()
	store, err := NewPostgresStore(testDatabaseURL(t))
	if err != nil {
		t.Fatalf("open test store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}
