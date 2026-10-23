package triage

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"time"

	"github.com/daimoniac/suppline/internal/statestore"
)

const (
	StatusDryRun     = "dry_run"
	StatusCommitted  = "committed"
	StatusWritten    = "written"
	StatusPushFailed = "push_failed"
	StatusRejected   = "rejected_by_guardrail"
	StatusError      = "error"
)

// Job is one repository and CVE pair waiting for triage.
type Job struct {
	Repository   string
	CVEID        string
	PackageName  string
	Version      string
	FixedVersion string
	Severity     string
	Description  string
	ImageRef     string
	Tag          string
	Digest       string
	Renewal      bool
}

func (j Job) key() string { return j.Repository + "\x00" + j.CVEID }

func (j Job) cveHash() string {
	sum := sha256.Sum256([]byte(j.PackageName + "\x00" + j.Version + "\x00" + j.FixedVersion + "\x00" + j.Severity + "\x00" + j.Description))
	return hex.EncodeToString(sum[:])
}

func cachedStatus(status string) bool {
	switch status {
	case StatusDryRun, StatusCommitted, StatusWritten, StatusRejected:
		return true
	default:
		return false
	}
}

// ShouldSkip reports whether this job was already decided for the current
// gitops commits and CVE text. A renewal inside the retriage interval is also
// skipped. A changed commit is triaged at most once per interval.
func ShouldSkip(last *statestore.TriageRun, renewal bool, shaKey, cveHash string, interval time.Duration, now time.Time) bool {
	if last == nil || !cachedStatus(last.Status) {
		return false
	}
	if last.Status == StatusRejected && strings.Contains(last.Reasoning, "CISA KEV feed") {
		return false
	}
	same := last.RepoSHAsJSON == shaKey && last.CVEHash == cveHash
	recent := now.Sub(last.CreatedAt) < interval
	if renewal {
		return same && recent
	}
	if same {
		return true
	}
	return last.RepoSHAsJSON != shaKey && recent
}
