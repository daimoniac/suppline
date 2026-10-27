package triage

// citeKind is what a recorded grep can prove. The tool result and the check both use it.
type citeKind string

const (
	citeRows    citeKind = "rows"
	citeAbsence citeKind = "absence"
	citeNone    citeKind = "no"
)

// cite records whether an empty search is proof. A non-empty search is the returned rows.
// absence is true only when the searched files would still have contained the name.
func cite(empty, absence bool) citeKind {
	if !empty {
		return citeRows
	}
	if absence {
		return citeAbsence
	}
	return citeNone
}

func (k citeKind) line() string {
	return "citable: " + string(k)
}

// evidenceContract is the only statement of how a grep may be cited.
func evidenceContract() string {
	return "Cite a grep by its grep_id and leave quote empty. The result line citable: rows means those lines. citable: absence is code_not_reachable for the files that were searched. citable: no stays uncertain. An empty grep is not proof unless its result says citable: absence. requires_configuration and requires_environment need citable: rows or a gitops or public line, not citable: absence. Other deployment justifications need a gitops line. A quote must match a line a tool returned. An absence claim without a grep_id is ignored."
}
