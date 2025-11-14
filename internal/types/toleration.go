package types

import "time"

// CVEToleration represents the canonical CVE toleration type.
// This is the single source of truth for toleration data structures.
type CVEToleration struct {
	ID        string
	Statement string
	ExpiresAt *time.Time
}

// ToleratedCVE extends CVEToleration with tracking metadata for storage.
// Used by StateStore to record when and where tolerations were applied.
// Note: This uses explicit fields instead of embedding to match statestore naming conventions.
type ToleratedCVE struct {
	CVEID       string
	Statement   string
	ToleratedAt time.Time
	ExpiresAt   *time.Time // Nil means no expiry
}

// TolerationInfo extends ToleratedCVE with repository context for queries.
// Used by StateStore queries to show which repositories have which tolerations.
// Note: This uses explicit fields instead of embedding to match statestore naming conventions.
type TolerationInfo struct {
	CVEID       string
	Statement   string
	ToleratedAt time.Time
	ExpiresAt   *time.Time
	Repository  string
}
