package triage

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/daimoniac/suppline/internal/gitops"
	"github.com/daimoniac/suppline/internal/types"
)

// headerRule names the deterministic kernel-header decision in triage runs.
const headerRule = "rule:kernel-headers"

// kernelPackage reports whether a package is built from the Linux kernel
// source. Scanners map kernel CVEs onto these packages.
func kernelPackage(name string) bool {
	if kernelHeaderPackage(name) {
		return true
	}
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "linux", "kernel":
		return true
	default:
		return false
	}
}

// kernelHeaderPackage reports whether a package ships only kernel headers.
// A container runs the node's kernel, so a kernel CVE reported against one of
// these packages is in code the image does not contain.
func kernelHeaderPackage(name string) bool {
	n := strings.ToLower(strings.TrimSpace(name))
	switch n {
	case "linux-libc-dev", "linux-headers", "kernel-headers", "linux-api-headers", "linux-uapi-headers":
		return true
	}
	return strings.HasPrefix(n, "linux-headers-")
}

// headerOnly reports whether every package this CVE was reported in, on any
// current digest of the repository, is a kernel header package.
func headerOnly(job Job) bool {
	packages := job.Packages
	if len(packages) == 0 && job.PackageName != "" {
		packages = []PackageFact{{Name: job.PackageName}}
	}
	if len(packages) == 0 {
		return false
	}
	for _, fact := range packages {
		if !kernelHeaderPackage(fact.Name) {
			return false
		}
	}
	for _, digest := range job.InUse {
		for _, fact := range digest.Packages {
			if !kernelHeaderPackage(fact.Name) {
				return false
			}
		}
	}
	return true
}

// headerVerdict is the fixed verdict for a header-only kernel finding.
func headerVerdict(job Job) modelVerdict {
	names := map[string]struct{}{}
	for _, fact := range job.Packages {
		names[fact.Name] = struct{}{}
	}
	if len(names) == 0 {
		names[job.PackageName] = struct{}{}
	}
	list := make([]string, 0, len(names))
	for name := range names {
		list = append(list, name)
	}
	sort.Strings(list)
	return modelVerdict{
		Verdict:             "not_affected",
		Justification:       string(types.VEXJustCodeNotPresent),
		Confidence:          1,
		CoversListedDigests: true,
		Reasoning: fmt.Sprintf("%s ships kernel headers only and no kernel code. A container runs on the node's kernel, so the vulnerable kernel code is not present in this image on any digest. Node kernel exposure is a host patching concern and is not covered by image VEX.",
			strings.Join(list, ", ")),
	}
}

// decideHeader applies the KEV rule, then accepts the fixed verdict.
func decideHeader(settings Settings, job Job, kev bool, kevErr error, existing *types.VEXStatement, checkouts []gitops.Checkout, triageID string, now time.Time) verdictDecision {
	if settings.BlockKEV && kevErr != nil {
		return flipOrReject(existing, job, "CISA KEV feed unavailable: "+kevErr.Error(), settings, checkouts, triageID, now)
	}
	if settings.BlockKEV && kev {
		return flipOrReject(existing, job, "CVE is listed in the CISA Known Exploited Vulnerabilities catalog", settings, checkouts, triageID, now)
	}
	verdict := headerVerdict(job)
	expires := now.Add(settings.Expiry).Unix()
	return verdictDecision{
		Action: outcomeNotAffected,
		Statement: types.VEXStatement{
			ID:            job.CVEID,
			State:         types.VEXStateNotAffected,
			Justification: types.VEXJustCodeNotPresent,
			Detail:        provenance(triageID, headerRule, checkouts, verdict, now),
			ExpiresAt:     &expires,
			Source:        types.VEXSourceAuto,
		},
	}
}

// triageHeaders decides header-only kernel findings without the model and
// returns the jobs that still need a session.
func (s *Service) triageHeaders(ctx context.Context, jobs []Job, checkouts []gitops.Checkout, shas string) []Job {
	var rest, headers []Job
	for _, job := range jobs {
		if headerOnly(job) {
			headers = append(headers, job)
			continue
		}
		rest = append(rest, job)
	}
	if len(headers) == 0 {
		return rest
	}
	existing := map[string]*types.VEXStatement{}
	if s.catalog != nil {
		for _, statement := range s.catalog.AutoVEX(headers[0].Repository) {
			copied := statement
			existing[statement.ID] = &copied
		}
	}
	sessionID := fmt.Sprintf("ts-%d", s.now().UnixNano())
	var writing []pendingWrite
	for _, job := range headers {
		var kevHit bool
		var kevErr error
		if s.settings.BlockKEV && s.kev != nil {
			kevHit, kevErr = s.kev.Contains(ctx, job.CVEID)
		}
		decision := decideHeader(s.settings, job, kevHit, kevErr, existing[job.CVEID], checkouts, sessionID, s.now())
		verdict := headerVerdict(job)
		if decision.Action == outcomeNotAffected || decision.Action == outcomeAffected {
			writing = append(writing, pendingWrite{turn: sessionTurn{Job: job, Verdict: verdict}, decision: decision})
			continue
		}
		s.record(ctx, job, verdict, 0, StatusRejected, sessionID, "", shas, decision.Reason)
	}
	s.writeVerdicts(ctx, headers[0].Repository, writing, sessionID, shas)
	return rest
}
