package statestore

// SQLiteStore implements StateStore on PostgreSQL.
//
// Runtime usage follows each cluster's latest inventory report: an image is in
// use while the cluster's most recent report contains it. The cluster agent
// decides how long short-lived pods stay in its reports.
type SQLiteStore struct {
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

// Close closes the database connection pool.
func (s *SQLiteStore) Close() error {
	return s.db.Close()
}

// initSchema creates or migrates the schema.
func (s *SQLiteStore) initSchema() error {
	return s.initPostgresSchema()
}
