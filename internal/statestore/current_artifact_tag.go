package statestore

// A current tag binding is the artifact with the greatest id for each
// (repository_id, tag). Reads use this invariant as a defensive boundary even
// though RecordScan and EnsureArtifactTagBinding prune superseded bindings via
// pruneSupersededTagBindingsTx on the write side.
//
// Keep this as a query fragment rather than a view so the same SQL remains
// portable between SQLite and PostgreSQL and continues through DB's placeholder
// rewriting.
const currentArtifactTagBindingJoin = `
		INNER JOIN (
			SELECT a2.repository_id, a2.tag, MAX(a2.id) AS max_id
			FROM artifacts a2
			GROUP BY a2.repository_id, a2.tag
		) latest ON a.repository_id = latest.repository_id
			AND a.tag IS NOT DISTINCT FROM latest.tag
			AND a.id = latest.max_id
`
