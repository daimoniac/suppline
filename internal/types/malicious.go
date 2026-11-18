package types

// Malicious-package check statuses, recorded per scan.
const (
	MaliciousCheckOK          = "ok"
	MaliciousCheckUnavailable = "unavailable"
	MaliciousCheckStale       = "stale"
)

// MaliciousFinding is a package in an image that matches a known-malicious
// package advisory (OSV MAL-*). It has no severity and is not a vulnerability.
type MaliciousFinding struct {
	ID          string
	Ecosystem   string
	PackageName string
	Version     string
	PURL        string
	Summary     string
	URL         string
}

// MaliciousCheck is the outcome of one scan's malicious-package check.
type MaliciousCheck struct {
	// Status is MaliciousCheckOK, MaliciousCheckUnavailable or MaliciousCheckStale.
	Status string
	// Commit is the ossf/malicious-packages commit matched against; empty when unavailable.
	Commit string
	// SnapshotAt is the Unix time of the last successful sync of that data; 0 when unavailable.
	SnapshotAt int64
	Findings   []MaliciousFinding
}

// PackageRef is a language package recorded for an image digest, so new
// advisories can be matched without rescanning.
type PackageRef struct {
	Ecosystem string
	Name      string
	Version   string
	PURL      string
}
