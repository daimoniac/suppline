package statestore

import (
	"testing"
	"time"

	"github.com/daimoniac/suppline/internal/types"
)

func TestPostgresStoreRoundTrip(t *testing.T) {
	store, err := NewPostgresStore(testDatabaseURL(t))
	if err != nil {
		t.Fatalf("NewPostgresStore: %v", err)
	}
	defer store.Close()

	ctx := t.Context()
	if err := store.RecordScan(ctx, &ScanRecord{
		Repository:        "library/alpine",
		Digest:            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Tag:               "3.20",
		PolicyPassed:      true,
		PolicyStatus:      "passed",
		CriticalVulnCount: 0,
		HighVulnCount:     0,
		MediumVulnCount:   0,
		LowVulnCount:      0,
		Vulnerabilities: []types.VulnerabilityRecord{
			{CVEID: "CVE-2024-0001", Severity: "LOW", PackageName: "musl", Title: "test"},
		},
	}); err != nil {
		t.Fatalf("RecordScan: %v", err)
	}

	// A rescan commonly has no image-created timestamp. PostgreSQL must still be
	// able to type the NULL parameter when updating the existing artifact.
	if err := store.RecordScan(ctx, &ScanRecord{
		Repository:        "library/alpine",
		Digest:            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Tag:               "3.20",
		PolicyPassed:      true,
		PolicyStatus:      "passed",
		CriticalVulnCount: 0,
		HighVulnCount:     0,
		MediumVulnCount:   0,
		LowVulnCount:      0,
	}); err != nil {
		t.Fatalf("RecordScan existing artifact with unknown image timestamp: %v", err)
	}

	got, err := store.GetLastScan(ctx, "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	if err != nil {
		t.Fatalf("GetLastScan: %v", err)
	}
	// The rescan found nothing, so the latest scan carries no findings.
	if got == nil || !got.PolicyPassed || len(got.Vulnerabilities) != 0 {
		t.Fatalf("unexpected last scan: %+v", got)
	}
}

func TestConcurrentStartupsMigrateUnderLock(t *testing.T) {
	url := testDatabaseURL(t)
	const instances = 4
	errs := make(chan error, instances)
	for range instances {
		go func() {
			store, err := NewPostgresStore(url)
			if err == nil {
				err = store.Close()
			}
			errs <- err
		}()
	}
	for range instances {
		if err := <-errs; err != nil {
			t.Fatalf("concurrent NewPostgresStore: %v", err)
		}
	}
}

func TestMigrationWaitsForLockHolder(t *testing.T) {
	url := testDatabaseURL(t)
	holder, err := NewPostgresStore(url)
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Close()

	ctx := t.Context()
	conn, err := holder.db.DB.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.ExecContext(ctx, `SELECT pg_advisory_lock($1, $2)`, advisoryLockClass, migrationLockID); err != nil {
		t.Fatal(err)
	}

	opened := make(chan error, 1)
	go func() {
		store, err := NewPostgresStore(url)
		if err == nil {
			err = store.Close()
		}
		opened <- err
	}()

	select {
	case err := <-opened:
		t.Fatalf("NewPostgresStore finished while another session held the migration lock: %v", err)
	case <-time.After(500 * time.Millisecond):
	}

	discardConn(conn) // ends the session and releases the lock
	select {
	case err := <-opened:
		if err != nil {
			t.Fatalf("NewPostgresStore after lock release: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("NewPostgresStore still waiting after the lock holder went away")
	}
}

func TestDiscardConnEndsSession(t *testing.T) {
	store := newTestStore(t)
	ctx := t.Context()
	conn, err := store.db.DB.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var pid int
	if err := conn.QueryRowContext(ctx, `SELECT pg_backend_pid()`).Scan(&pid); err != nil {
		t.Fatal(err)
	}
	discardConn(conn)

	deadline := time.Now().Add(5 * time.Second)
	for {
		var alive bool
		if err := store.db.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE pid = ?)`, pid).Scan(&alive); err != nil {
			t.Fatal(err)
		}
		if !alive {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("backend %d still alive after discardConn", pid)
		}
		time.Sleep(50 * time.Millisecond)
	}
}
