package triage

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/daimoniac/suppline/internal/statestore"
)

// PackageFact is one installed package a CVE was reported in.
type PackageFact struct {
	Name      string
	Installed string
	Fixed     string
}

// DigestFact is one digest of the repository, with this CVE's packages on it.
type DigestFact struct {
	Digest         string
	Tag            string
	ImageCreatedAt int64
	InUse          bool
	Placements     int
	Packages       []PackageFact
}

const (
	StatusDryRun     = "dry_run"
	StatusCommitted  = "committed"
	StatusWritten    = "written"
	StatusPushFailed = "push_failed"
	StatusRejected   = "rejected_by_guardrail"
	StatusError      = "error"
)

// Job is one repository and CVE pair waiting for triage.
// Digest, tag, and package fields describe the representative image chosen
// when the job runs. The statement written from it covers the repository.
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
	// Packages is every (name, installed, fixed) reported for this CVE on
	// current scans of the repository. The cache key is built from it.
	Packages []PackageFact
	// InUse is every in-use digest of the repository, with this CVE's packages
	// on that digest. Empty Packages means the CVE was not reported there.
	InUse []DigestFact
	// PlacementText is where the representative digest is running.
	PlacementText string
	// Upstream is the catalog source image, such as docker.io/supabase/studio.
	Upstream string
	// Platform is the sync platform, such as linux/amd64. Empty means linux/amd64.
	Platform string
	Renewal  bool
	// Force runs again even when a cached decision exists. Manual "Triage now" sets it.
	Force bool
}

func (j Job) key() string { return j.Repository + "\x00" + j.CVEID }

// cveHash identifies the repository-level facts for this CVE: the id, the
// sorted package set, and the highest severity. Description and digest are
// not part of it, so two digests of the same image do not invalidate each other.
func (j Job) cveHash() string {
	facts := append([]PackageFact(nil), j.Packages...)
	if len(facts) == 0 && (j.PackageName != "" || j.Version != "" || j.FixedVersion != "") {
		facts = []PackageFact{{Name: j.PackageName, Installed: j.Version, Fixed: j.FixedVersion}}
	}
	sort.Slice(facts, func(a, b int) bool {
		if facts[a].Name != facts[b].Name {
			return facts[a].Name < facts[b].Name
		}
		if facts[a].Installed != facts[b].Installed {
			return facts[a].Installed < facts[b].Installed
		}
		return facts[a].Fixed < facts[b].Fixed
	})
	deduped := facts[:0]
	for _, fact := range facts {
		if len(deduped) > 0 {
			last := deduped[len(deduped)-1]
			if last.Name == fact.Name && last.Installed == fact.Installed && last.Fixed == fact.Fixed {
				continue
			}
		}
		deduped = append(deduped, fact)
	}
	var b strings.Builder
	b.WriteString(j.CVEID)
	for _, fact := range deduped {
		fmt.Fprintf(&b, "\x00%s\x00%s\x00%s", fact.Name, fact.Installed, fact.Fixed)
	}
	b.WriteString("\x00")
	b.WriteString(strings.ToUpper(strings.TrimSpace(j.Severity)))
	sum := sha256.Sum256([]byte(b.String()))
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
