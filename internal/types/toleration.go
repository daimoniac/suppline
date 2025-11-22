package types

// CVEToleration represents the canonical CVE toleration type.
// This is the single source of truth for toleration data structures.
type CVEToleration struct {
	ID        string
	Statement string
	ExpiresAt *int64 // Unix timestamp in seconds, nil means no expiry
}

// ToleratedCVE extends CVEToleration with tracking metadata for storage.
// Used by StateStore to record when and where tolerations were applied.
// Note: This uses explicit fields instead of embedding to match statestore naming conventions.
type ToleratedCVE struct {
	CVEID       string
	Statement   string
	ToleratedAt int64  // Unix timestamp in seconds
	ExpiresAt   *int64 // Unix timestamp in seconds, nil means no expiry
}

// TolerationInfo extends ToleratedCVE with repository context for queries.
// Used by StateStore queries to show which repositories have which tolerations.
// Note: This uses explicit fields instead of embedding to match statestore naming conventions.
type TolerationInfo struct {
	CVEID       string
	Statement   string
	ToleratedAt int64  // Unix timestamp in seconds
	ExpiresAt   *int64 // Unix timestamp in seconds
	Repository  string
}
