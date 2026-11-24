package api

import (
	"context"
	"errors"
	"sort"

	"github.com/daimoniac/suppline/internal/statestore"
	"github.com/daimoniac/suppline/internal/types"
)

// syncVEXReader lists the sync-entry statements of a repository that are the
// only copy of their id and not overridden by defaults.vex.
type syncVEXReader interface {
	SyncVEX(repository string) []types.VEXStatement
}

// addVEXExpiryFacts fills what decides each entry's actions: whether the
// statement can be edited on its own, whether the repository's scans still
// report the CVE, whether a newer tag no longer does, the KEV rule, and the
// latest triage run.
func (s *APIServer) addVEXExpiryFacts(ctx context.Context, entries []VEXExpiryTaskEntry) {
	if len(entries) == 0 {
		return
	}
	editable := map[string]map[string]bool{}
	reports := map[string]map[string][]taggedScan{}
	kev := map[string]bool{}
	runs := s.latestRunsByPair(ctx)
	for i := range entries {
		entry := &entries[i]
		if _, ok := editable[entry.Repository]; !ok {
			editable[entry.Repository] = s.syncVEXIDs(entry.Repository)
		}
		entry.Editable = editable[entry.Repository][entry.CVEID+"\n"+entry.Source]

		if _, ok := reports[entry.Repository]; !ok {
			reports[entry.Repository] = s.cveReportsByTag(ctx, entry.Repository)
		}
		entry.InScans, entry.AffectedTags, entry.FixedTag = cveTagFacts(reports[entry.Repository], entry.CVEID)

		if listed, ok := kev[entry.CVEID]; ok {
			entry.KEV = listed
		} else if s.triageService != nil {
			listed, err := s.triageService.KEVBlocked(ctx, entry.CVEID)
			if err != nil {
				s.logger.Warn("vex expiry KEV lookup failed", "cve", entry.CVEID, "error", err)
			}
			kev[entry.CVEID] = listed
			entry.KEV = listed
		}
		if run, ok := runs[entry.Repository+"\n"+entry.CVEID]; ok {
			attached := run
			entry.LastRun = &attached
		}
	}
}

func (s *APIServer) syncVEXIDs(repository string) map[string]bool {
	out := map[string]bool{}
	reader, ok := s.policyCatalog.(syncVEXReader)
	if !ok {
		return out
	}
	for _, statement := range reader.SyncVEX(repository) {
		out[statement.ID+"\n"+statement.Source] = true
	}
	return out
}

func (s *APIServer) latestRunsByPair(ctx context.Context) map[string]TriageRunResponse {
	out := map[string]TriageRunResponse{}
	store, ok := s.stateStore.(statestore.TriageStore)
	if !ok {
		return out
	}
	runs, err := store.ListTriageRuns(ctx, statestore.TriageFilter{LatestOnly: true, Limit: 5000})
	if err != nil {
		s.logger.Warn("vex expiry triage runs", "error", err)
		return out
	}
	for _, run := range triageRunResponses(runs) {
		out[run.Repository+"\n"+run.CVEID] = run
	}
	return out
}

// taggedScan is one scanned tag and when its image was built.
type taggedScan struct {
	Tag     string
	BuiltAt int64
	Reports bool
}

// cveReportsByTag returns, per CVE, every scanned tag of repository and
// whether that tag's latest scan reports the CVE. A CVE counts as reported
// when it is a finding, a policy failure, or an applied exemption: an
// exempted CVE can be filtered out of the findings by the scanner.
func (s *APIServer) cveReportsByTag(ctx context.Context, repository string) map[string][]taggedScan {
	scans, err := s.stateStore.ListScans(ctx, statestore.ScanFilter{Repository: repository, IncludeExemptions: true})
	if err != nil {
		s.logger.Warn("vex expiry list scans", "repository", repository, "error", err)
		return nil
	}
	type tagFacts struct {
		builtAt int64
		cves    map[string]bool
	}
	byTag := map[string]*tagFacts{}
	for _, scan := range scans {
		if scan == nil || scan.Tag == "" || scan.Repository != repository {
			continue
		}
		facts := &tagFacts{builtAt: scan.ImageCreatedAt, cves: map[string]bool{}}
		if facts.builtAt == 0 {
			facts.builtAt = scan.CreatedAt
		}
		if prev, ok := byTag[scan.Tag]; ok && prev.builtAt >= facts.builtAt {
			continue
		}
		vulns := scan.Vulnerabilities
		if len(vulns) == 0 && scan.Digest != "" {
			full, err := s.stateStore.GetLastRepositoryScan(ctx, repository, scan.Digest)
			if err != nil && !errors.Is(err, statestore.ErrScanNotFound) {
				s.logger.Warn("vex expiry load findings", "repository", repository, "digest", scan.Digest, "error", err)
			}
			if full != nil {
				vulns = full.Vulnerabilities
			}
		}
		for _, vuln := range vulns {
			facts.cves[vuln.CVEID] = true
		}
		for _, finding := range scan.PolicyFailureFindings {
			facts.cves[finding.CVEID] = true
		}
		for _, applied := range scan.AppliedVEXStatements {
			facts.cves[applied.CVEID] = true
		}
		byTag[scan.Tag] = facts
	}
	out := map[string][]taggedScan{}
	all := map[string]bool{}
	for _, facts := range byTag {
		for cve := range facts.cves {
			all[cve] = true
		}
	}
	for cve := range all {
		for tag, facts := range byTag {
			out[cve] = append(out[cve], taggedScan{Tag: tag, BuiltAt: facts.builtAt, Reports: facts.cves[cve]})
		}
	}
	return out
}

// cveTagFacts says whether any tag reports cve, which tags do, and the newest
// tag that does not when it is newer than every tag that does.
func cveTagFacts(byCVE map[string][]taggedScan, cve string) (bool, []string, string) {
	tags, ok := byCVE[cve]
	if !ok {
		return false, nil, ""
	}
	var affected []string
	var newestAffected int64
	fixed, fixedAt := "", int64(0)
	for _, tag := range tags {
		if tag.Reports {
			affected = append(affected, tag.Tag)
			if tag.BuiltAt > newestAffected {
				newestAffected = tag.BuiltAt
			}
			continue
		}
		if tag.BuiltAt > fixedAt || (tag.BuiltAt == fixedAt && tag.Tag > fixed) {
			fixed, fixedAt = tag.Tag, tag.BuiltAt
		}
	}
	sort.Strings(affected)
	if len(affected) == 0 {
		return false, nil, ""
	}
	if fixedAt <= newestAffected {
		fixed = ""
	}
	return true, affected, fixed
}
