package statestore

import (
	"context"
	"database/sql"
	"fmt"
	"sync"
	"time"
)

// Leader is the instance that currently holds the leader lock.
type Leader struct {
	Holder     string
	Address    string
	AcquiredAt time.Time
}

// LeaderLock is the session advisory lock that elects one leader per
// database (ADR 0004). It lives on a dedicated connection: the session is
// the lock, so losing the connection loses leadership.
type LeaderLock struct {
	store *Store

	mu   sync.Mutex
	conn *sql.Conn
}

// LeaderLock returns an unheld leader lock on this store's database.
func (s *Store) LeaderLock() *LeaderLock {
	return &LeaderLock{store: s}
}

// sessionKeepalives make PostgreSQL notice a vanished client within about
// 25 s, so a dead leader's session, and its lock, end instead of lingering
// for the kernel's default two hours.
var sessionKeepalives = []string{
	`SET tcp_keepalives_idle = 10`,
	`SET tcp_keepalives_interval = 5`,
	`SET tcp_keepalives_count = 3`,
}

func (l *LeaderLock) connect(ctx context.Context) (*sql.Conn, error) {
	if l.conn != nil {
		return l.conn, nil
	}
	conn, err := l.store.db.Conn(ctx)
	if err != nil {
		return nil, fmt.Errorf("open leader lock connection: %w", err)
	}
	for _, stmt := range sessionKeepalives {
		if _, err := conn.ExecContext(ctx, stmt); err != nil {
			discardConn(conn)
			return nil, fmt.Errorf("configure leader lock session: %w", err)
		}
	}
	l.conn = conn
	return conn, nil
}

// TryAcquire takes the lock if no other session holds it. It does not wait.
func (l *LeaderLock) TryAcquire(ctx context.Context) (bool, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	conn, err := l.connect(ctx)
	if err != nil {
		return false, err
	}
	var acquired bool
	if err := conn.QueryRowContext(ctx, `SELECT pg_try_advisory_lock($1, $2)`, advisoryLockClass, leaderLockID).Scan(&acquired); err != nil {
		discardConn(conn)
		l.conn = nil
		return false, fmt.Errorf("try leader lock: %w", err)
	}
	return acquired, nil
}

// Check returns an error unless this session still holds the lock. It runs on
// the lock's own connection, so a broken connection fails it too: a pinned
// *sql.Conn never reconnects behind the caller's back.
func (l *LeaderLock) Check(ctx context.Context) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.conn == nil {
		return fmt.Errorf("leader lock is not held")
	}
	var held bool
	if err := l.conn.QueryRowContext(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM pg_locks
			WHERE locktype = 'advisory'
			  AND classid::bigint = $1 AND objid::bigint = $2 AND objsubid = 2
			  AND pid = pg_backend_pid() AND granted
		)`, advisoryLockClass, leaderLockID).Scan(&held); err != nil {
		return fmt.Errorf("check leader lock: %w", err)
	}
	if !held {
		return fmt.Errorf("leader lock is no longer held by this session")
	}
	return nil
}

// Advertise records this session as the leader, reachable at address.
// Standbys trust the row only while the session that wrote it holds the lock.
func (l *LeaderLock) Advertise(ctx context.Context, holder, address string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.conn == nil {
		return fmt.Errorf("leader lock is not held")
	}
	if _, err := l.conn.ExecContext(ctx, `
		INSERT INTO leader (id, holder, address, backend_pid, acquired_at)
		VALUES (1, $1, $2, pg_backend_pid(), EXTRACT(EPOCH FROM CLOCK_TIMESTAMP())::BIGINT)
		ON CONFLICT (id) DO UPDATE SET
			holder = EXCLUDED.holder,
			address = EXCLUDED.address,
			backend_pid = EXCLUDED.backend_pid,
			acquired_at = EXCLUDED.acquired_at`, holder, address); err != nil {
		return fmt.Errorf("advertise leader: %w", err)
	}
	return nil
}

// Release gives up the lock and ends the session.
func (l *LeaderLock) Release(ctx context.Context) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.conn == nil {
		return nil
	}
	_, err := l.conn.ExecContext(ctx, `SELECT pg_advisory_unlock($1, $2)`, advisoryLockClass, leaderLockID)
	// Ending the session releases the lock even if the unlock failed.
	discardConn(l.conn)
	l.conn = nil
	if err != nil {
		return fmt.Errorf("release leader lock: %w", err)
	}
	return nil
}

// CurrentLeader returns the advertised leader, or false when there is none:
// no row, or the session that wrote the row no longer holds the lock. Pod IPs
// are reused, so a stale row must never be trusted.
func (s *Store) CurrentLeader(ctx context.Context) (Leader, bool, error) {
	var (
		leader     Leader
		acquiredAt int64
	)
	err := s.db.QueryRowContext(ctx, `
		SELECT l.holder, l.address, l.acquired_at
		FROM leader l
		WHERE l.id = 1 AND EXISTS (
			SELECT 1 FROM pg_locks k
			WHERE k.locktype = 'advisory'
			  AND k.classid::bigint = ? AND k.objid::bigint = ? AND k.objsubid = 2
			  AND k.pid = l.backend_pid AND k.granted
		)`, advisoryLockClass, leaderLockID).Scan(&leader.Holder, &leader.Address, &acquiredAt)
	if err == sql.ErrNoRows {
		return Leader{}, false, nil
	}
	if err != nil {
		return Leader{}, false, fmt.Errorf("read current leader: %w", err)
	}
	leader.AcquiredAt = time.Unix(acquiredAt, 0)
	return leader, true, nil
}
