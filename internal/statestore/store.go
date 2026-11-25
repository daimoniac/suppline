package statestore

import (
	"context"
	"fmt"
)

// Store implements StateStore on PostgreSQL.
//
// Runtime usage follows each cluster's latest inventory report: an image is in
// use while the cluster's most recent report contains it. The cluster agent
// decides how long short-lived pods stay in its reports.
type Store struct {
	db *DB
}

type clusterImageIdentity struct {
	namespace string
	imageRef  string
	tag       string
}

type normalizedClusterImageGroup struct {
	identity   clusterImageIdentity
	digests    []string
	digestSeen map[string]struct{}
	hasEmpty   bool
	// workloads holds the merged owners per digest; "" is the digest-less entry.
	workloads map[string][]string
}

// Ping checks that PostgreSQL answers on a pooled connection.
func (s *Store) Ping(ctx context.Context) error {
	if err := s.db.PingContext(ctx); err != nil {
		return fmt.Errorf("ping postgres: %w", err)
	}
	return nil
}

// Close closes the database connection pool.
func (s *Store) Close() error {
	return s.db.Close()
}

// initSchema creates or migrates the schema.
func (s *Store) initSchema() error {
	return s.initPostgresSchema()
}
