package types

// PolicyFailureFinding identifies one vulnerability/component pair that
// contributes to a CEL policy failure.
type PolicyFailureFinding struct {
	CVEID       string
	PackageName string
}
