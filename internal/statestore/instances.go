package statestore

import (
	"context"
	"fmt"
	"time"
)

// Instance is one running suppline process sharing this database.
type Instance struct {
	Holder    string
	Hostname  string
	Address   string
	Version   string
	StartedAt time.Time
	SeenAt    time.Time
	// Leader is true while this instance holds the leader lock.
	Leader bool
}

// instancesRetention drops rows of instances that stopped without removing
// themselves, long after any listing would show them.
const instancesRetention = 24 * time.Hour

// Heartbeat records that the instance is alive. Every instance calls it
// periodically, leader or standby.
func (s *Store) Heartbeat(ctx context.Context, in Instance) error {
	if _, err := s.db.ExecContext(ctx, `
		INSERT INTO instances (holder, hostname, address, version, started_at, seen_at)
		VALUES (?, ?, ?, ?, ?, EXTRACT(EPOCH FROM CLOCK_TIMESTAMP())::BIGINT)
		ON CONFLICT (holder) DO UPDATE SET
			hostname = EXCLUDED.hostname,
			address = EXCLUDED.address,
			version = EXCLUDED.version,
			seen_at = EXCLUDED.seen_at`,
		in.Holder, in.Hostname, in.Address, in.Version, in.StartedAt.Unix()); err != nil {
		return fmt.Errorf("record instance heartbeat: %w", err)
	}
	if _, err := s.db.ExecContext(ctx, `
		DELETE FROM instances WHERE seen_at < EXTRACT(EPOCH FROM CLOCK_TIMESTAMP())::BIGINT - ?`,
		int64(instancesRetention.Seconds())); err != nil {
		return fmt.Errorf("prune instances: %w", err)
	}
	return nil
}

// RemoveInstance deletes the instance's row when it shuts down cleanly.
func (s *Store) RemoveInstance(ctx context.Context, holder string) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM instances WHERE holder = ?`, holder); err != nil {
		return fmt.Errorf("remove instance: %w", err)
	}
	return nil
}

// ListInstances returns the instances seen within window, the leader
// first. Like CurrentLeader it trusts the leader row only while its session
// still holds the lock.
func (s *Store) ListInstances(ctx context.Context, window time.Duration) ([]Instance, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT i.holder, i.hostname, i.address, i.version, i.started_at, i.seen_at,
			EXISTS (
				SELECT 1 FROM leader l
				JOIN pg_locks k ON k.pid = l.backend_pid
				WHERE l.id = 1 AND l.holder = i.holder
				  AND k.locktype = 'advisory'
				  AND k.classid::bigint = ? AND k.objid::bigint = ? AND k.objsubid = 2
				  AND k.granted
			) AS leader
		FROM instances i
		WHERE i.seen_at >= EXTRACT(EPOCH FROM CLOCK_TIMESTAMP())::BIGINT - ?
		ORDER BY leader DESC, i.hostname`,
		advisoryLockClass, leaderLockID, int64(window.Seconds()))
	if err != nil {
		return nil, fmt.Errorf("list instances: %w", err)
	}
	defer rows.Close()

	var out []Instance
	for rows.Next() {
		var (
			in              Instance
			started, seenAt int64
		)
		if err := rows.Scan(&in.Holder, &in.Hostname, &in.Address, &in.Version, &started, &seenAt, &in.Leader); err != nil {
			return nil, fmt.Errorf("scan instance: %w", err)
		}
		in.StartedAt, in.SeenAt = time.Unix(started, 0), time.Unix(seenAt, 0)
		out = append(out, in)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list instances: %w", err)
	}
	return out, nil
}
