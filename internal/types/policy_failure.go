package types

// Policy failure finding kinds. An empty Kind is a vulnerability, so findings
// stored before kinds existed keep their meaning.
const (
	PolicyFailureKindVulnerability = "vulnerability"
	PolicyFailureKindMalicious     = "malicious"
)

// PolicyFailureFinding identifies one vulnerability/component pair that
// contributes to a CEL policy failure, or a malicious package that failed the
// built-in malicious-package gate. For a malicious finding CVEID holds the
// MAL id.
type PolicyFailureFinding struct {
	CVEID       string
	PackageName string
	Kind        string `json:",omitempty"`
}

// IsMalicious reports whether the finding comes from the malicious-package gate.
func (f PolicyFailureFinding) IsMalicious() bool {
	return f.Kind == PolicyFailureKindMalicious
}
