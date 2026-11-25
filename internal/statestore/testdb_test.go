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
func newTestStore(t testing.TB) *SQLiteStore {
	t.Helper()
	store, err := NewPostgresStore(testDatabaseURL(t))
	if err != nil {
		t.Fatalf("open test store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

// Every test gets its own migrated database, so no test sees another's rows.
func TestNewTestStoreGivesEachTestAnEmptyDatabase(t *testing.T) {
	for range 2 {
		store := newTestStore(t)
		if _, err := store.db.ExecContext(t.Context(), `INSERT INTO repositories (name) VALUES ('isolated/repo')`); err != nil {
			t.Fatalf("insert into a fresh database: %v", err)
		}
	}
}
