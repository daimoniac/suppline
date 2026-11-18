package types

import (
	"fmt"
	"strings"
)

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
	// Exempted is true when a false_positive VEX statement covers the finding;
	// it is then shown but does not fail policy.
	Exempted bool `json:",omitempty"`
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

// IsMaliciousID reports whether an advisory id is a malicious-package
// advisory (OSV MAL-*).
func IsMaliciousID(id string) bool {
	return strings.HasPrefix(id, "MAL-")
}

// ValidateMaliciousVEXStatement checks the extra rules for statements about
// malicious-package advisories. Only false_positive can exempt one: "present
// but not reachable" is no defence for a package that runs install scripts.
// Automated statements (x-vex-auto) may never name one; exempting malware
// needs a person.
func ValidateMaliciousVEXStatement(v VEXStatement, automated bool) error {
	if !IsMaliciousID(v.ID) {
		return nil
	}
	if automated {
		return fmt.Errorf("%s is a malicious-package advisory; only hand-written x-vex may exempt it", v.ID)
	}
	if v.State != VEXStateFalsePositive {
		return fmt.Errorf("%s is a malicious-package advisory; its state must be %q (the image does not contain the malicious package), got %q", v.ID, VEXStateFalsePositive, v.State)
	}
	return nil
}
