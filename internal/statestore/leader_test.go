package statestore

import (
	"testing"
	"time"
)

func TestLeaderLockIsExclusive(t *testing.T) {
	url := testDatabaseURL(t)
	a := openStore(t, url)
	b := openStore(t, url)
	ctx := t.Context()

	lockA, lockB := a.LeaderLock(), b.LeaderLock()
	t.Cleanup(func() { _ = lockA.Release(ctx); _ = lockB.Release(ctx) })

	if got, err := lockA.TryAcquire(ctx); err != nil || !got {
		t.Fatalf("first TryAcquire = %v, %v; want true", got, err)
	}
	if got, err := lockB.TryAcquire(ctx); err != nil || got {
		t.Fatalf("second TryAcquire = %v, %v; want false while the first holds it", got, err)
	}
	if err := lockA.Check(ctx); err != nil {
		t.Fatalf("holder Check: %v", err)
	}
	if err := lockB.Check(ctx); err == nil {
		t.Fatal("non-holder Check succeeded")
	}

	if err := lockA.Release(ctx); err != nil {
		t.Fatalf("Release: %v", err)
	}
	if got, err := lockB.TryAcquire(ctx); err != nil || !got {
		t.Fatalf("TryAcquire after release = %v, %v; want true", got, err)
	}
}

func TestLeaderLockLostWhenSessionEnds(t *testing.T) {
	url := testDatabaseURL(t)
	a := openStore(t, url)
	b := openStore(t, url)
	ctx := t.Context()

	lockA, lockB := a.LeaderLock(), b.LeaderLock()
	t.Cleanup(func() { _ = lockA.Release(ctx); _ = lockB.Release(ctx) })
	if got, err := lockA.TryAcquire(ctx); err != nil || !got {
		t.Fatalf("TryAcquire = %v, %v", got, err)
	}
	if err := lockA.Advertise(ctx, "a", "http://10.0.0.1:8080"); err != nil {
		t.Fatalf("Advertise: %v", err)
	}

	// What a PostgreSQL failover or a dead node does to the holder's session.
	if _, err := b.db.ExecContext(ctx, `SELECT pg_terminate_backend(backend_pid) FROM leader WHERE id = 1`); err != nil {
		t.Fatalf("terminate holder session: %v", err)
	}

	waitFor(t, func() bool { return lockA.Check(ctx) != nil }, "holder still passes Check after its session ended")
	waitFor(t, func() bool {
		_, ok, err := b.CurrentLeader(ctx)
		return err == nil && !ok
	}, "stale leader row still trusted after its session ended")
	if got, err := lockB.TryAcquire(ctx); err != nil || !got {
		t.Fatalf("TryAcquire after holder died = %v, %v; want true", got, err)
	}
	if err := lockB.Advertise(ctx, "b", "http://10.0.0.2:8080"); err != nil {
		t.Fatalf("Advertise: %v", err)
	}
	leader, ok, err := a.CurrentLeader(ctx)
	if err != nil || !ok || leader.Holder != "b" || leader.Address != "http://10.0.0.2:8080" {
		t.Fatalf("CurrentLeader = %+v, %v, %v; want b", leader, ok, err)
	}
}

func TestCurrentLeaderWithoutRow(t *testing.T) {
	store := newTestStore(t)
	if _, ok, err := store.CurrentLeader(t.Context()); err != nil || ok {
		t.Fatalf("CurrentLeader on a fresh database = %v, %v; want none", ok, err)
	}
}

func TestCurrentLeaderIgnoresRowWithoutLock(t *testing.T) {
	store := newTestStore(t)
	ctx := t.Context()
	// A row left behind by a session that never held the lock (or lost it).
	if _, err := store.db.ExecContext(ctx, `
		INSERT INTO leader (id, holder, address, backend_pid, acquired_at)
		VALUES (1, 'ghost', 'http://10.0.0.9:8080', pg_backend_pid(), 0)`); err != nil {
		t.Fatal(err)
	}
	if leader, ok, err := store.CurrentLeader(ctx); err != nil || ok {
		t.Fatalf("CurrentLeader = %+v, %v, %v; want none", leader, ok, err)
	}
}

func openStore(t *testing.T, url string) *Store {
	t.Helper()
	store, err := NewPostgresStore(url)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func waitFor(t *testing.T, cond func() bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal(msg)
		}
		time.Sleep(50 * time.Millisecond)
	}
}
