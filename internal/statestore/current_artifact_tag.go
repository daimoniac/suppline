package statestore

// A current tag binding is the newest non-superseded artifact for each
// (repository_id, tag). Superseded rows are digests the tag no longer points
// at that are still referenced by cluster inventory, so attestation renewal
// can keep scanning them. Reads use this join as a defensive boundary even
// though RecordScan and EnsureArtifactTagBinding maintain the flag.
//
// Keep this as a query fragment rather than a view so the same SQL remains
// portable between SQLite and PostgreSQL and continues through DB's placeholder
// rewriting.
const currentArtifactTagBindingJoin = `
		INNER JOIN (
			SELECT a2.repository_id, a2.tag, MAX(a2.id) AS max_id
			FROM artifacts a2
			WHERE a2.superseded = 0
			GROUP BY a2.repository_id, a2.tag
		) latest ON a.repository_id = latest.repository_id
			AND a.tag IS NOT DISTINCT FROM latest.tag
			AND a.id = latest.max_id
`
