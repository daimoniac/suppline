package api

import (
	"net/http"
	"sort"
	"strings"

	"github.com/daimoniac/suppline/internal/statestore"
	"github.com/daimoniac/suppline/internal/triage"
	"github.com/daimoniac/suppline/internal/types"
)

// Phases of one CVE on a repository card.
const (
	phaseUncertain  = "uncertain"
	phaseError      = "error"
	phaseNotTriaged = "not_triaged"
	phaseRunning    = "running"
	phaseQueued     = "queued"
	phaseDecided    = "decided"
	phaseExempt     = "exempt"
)

// TriageRepositoryTag is one running image tag of a repository.
type TriageRepositoryTag struct {
	Tag          string `json:"Tag"`
	Digest       string `json:"Digest"`
	PolicyPassed bool   `json:"PolicyPassed"`
	PolicyStatus string `json:"PolicyStatus"`
}

// TriageRepositoryCounts summarises the CVEs on one card.
type TriageRepositoryCounts struct {
	Blocking       int `json:"Blocking"`
	NeedsAttention int `json:"NeedsAttention"`
	NotTriaged     int `json:"NotTriaged"`
	Uncertain      int `json:"Uncertain"`
	Failed         int `json:"Failed"`
	InProgress     int `json:"InProgress"`
	Decided        int `json:"Decided"`
	ExemptAuto     int `json:"ExemptAuto"`
	ExemptManual   int `json:"ExemptManual"`
}

// TriageRepositoryCVE is one CVE that blocks or is exempt on a running image.
// Phase says what happens next. Reason is one plain sentence for the reader.
// ReasonCode and ReasonAt are set when triage recorded why it left the CVE alone.
// Run is the latest stored decision. Older runs are never returned.
type TriageRepositoryCVE struct {
	CVEID         string             `json:"CVEID"`
	Phase         string             `json:"Phase"`
	Blocking      bool               `json:"Blocking"`
	Packages      []string           `json:"Packages,omitempty"`
	Tags          []string           `json:"Tags"`
	Origin        string             `json:"Origin,omitempty"`
	State         string             `json:"State,omitempty"`
	Justification string             `json:"Justification,omitempty"`
	Detail        string             `json:"Detail,omitempty"`
	ExpiresAt     int64              `json:"ExpiresAt,omitempty"`
	Reason        string             `json:"Reason"`
	ReasonCode    string             `json:"ReasonCode,omitempty"`
	ReasonAt      int64              `json:"ReasonAt,omitempty"`
	Run           *TriageRunResponse `json:"Run,omitempty"`
}

// TriageRepository is one running repository with the CVEs that matter for triage.
type TriageRepository struct {
	Repository   string                 `json:"Repository"`
	PolicyPassed bool                   `json:"PolicyPassed"`
	Tags         []TriageRepositoryTag  `json:"Tags"`
	Counts       TriageRepositoryCounts `json:"Counts"`
	CVEs         []TriageRepositoryCVE  `json:"CVEs"`
}

// repositoryCardInput is everything the card builder reads.
type repositoryCardInput struct {
	Scans           []*statestore.ScanRecord
	Runs            map[string]TriageRunResponse
	Statements      func(repository string) []types.VEXStatement
	Running         map[string]bool
	Queued          map[string]bool
	Skips           map[string]triage.Skip
	BudgetExhausted bool
}

// handleListTriageRepositories lists running repositories with their CVE states.
// @Summary List triage by repository
// @Description One card per running repository: its tags, policy result, and every blocking or exempt CVE with its triage state and the reason it is in that state. Only the latest triage run of each CVE is returned.
// @Tags Triage
// @Produce json
// @Success 200 {array} TriageRepository
// @Failure 401 {object} map[string]string "Unauthorized"
// @Failure 500 {object} map[string]string "Internal server error"
// @Security BearerAuth
// @Router /triage/repositories [get]
func (s *APIServer) handleListTriageRepositories(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	store, ok := s.stateStore.(statestore.TriageStore)
	if !ok {
		s.respondError(w, http.StatusNotImplemented, "triage store is not available")
		return
	}
	scans, err := s.stateStore.ListScans(r.Context(), statestore.ScanFilter{ImageUsage: statestore.ImageUsageInUse, IncludeExemptions: true})
	if err != nil {
		s.respondError(w, http.StatusInternalServerError, "Failed to list running images")
		s.logger.Error("triage repositories list scans", "error", err)
		return
	}
	runs, err := store.ListTriageRuns(r.Context(), statestore.TriageFilter{LatestOnly: true, Limit: 5000})
	if err != nil {
		s.respondError(w, http.StatusInternalServerError, "Failed to list triage runs")
		s.logger.Error("triage repositories list runs", "error", err)
		return
	}
	input := repositoryCardInput{
		Scans:   scans,
		Runs:    map[string]TriageRunResponse{},
		Running: map[string]bool{},
		Queued:  map[string]bool{},
		Statements: func(repository string) []types.VEXStatement {
			if s.policyCatalog == nil {
				return nil
			}
			return s.policyCatalog.ResolveEvidence(repository).VEXStatements
		},
	}
	for _, run := range triageRunResponses(runs) {
		input.Runs[triage.SkipKey(run.Repository, run.CVEID)] = run
	}
	if s.triageService != nil {
		for _, session := range s.triageService.Sessions() {
			for _, cve := range session.CVEs {
				input.Running[triage.SkipKey(session.Repository, cve.CVEID)] = cve.Status == "running"
			}
		}
		for _, job := range s.triageService.Queued() {
			input.Queued[triage.SkipKey(job.Repository, job.CVEID)] = true
		}
		input.Skips = s.triageService.Skips()
		input.BudgetExhausted = s.triageService.BudgetStatus(r.Context()).Exhausted
	}
	s.respondJSON(w, http.StatusOK, buildTriageRepositories(input))
}

func buildTriageRepositories(in repositoryCardInput) []TriageRepository {
	byRepo := map[string][]*statestore.ScanRecord{}
	for _, scan := range in.Scans {
		if scan == nil || !scan.RuntimeUsed {
			continue
		}
		byRepo[scan.Repository] = append(byRepo[scan.Repository], scan)
	}
	cards := make([]TriageRepository, 0, len(byRepo))
	for repository, scans := range byRepo {
		cards = append(cards, buildRepositoryCard(repository, scans, in))
	}
	sort.Slice(cards, func(i, j int) bool {
		a, b := cards[i], cards[j]
		if a.Counts.NeedsAttention != b.Counts.NeedsAttention {
			return a.Counts.NeedsAttention > b.Counts.NeedsAttention
		}
		if a.Counts.Blocking != b.Counts.Blocking {
			return a.Counts.Blocking > b.Counts.Blocking
		}
		return a.Repository < b.Repository
	})
	return cards
}

type cveAccumulator struct {
	cveID    string
	packages map[string]struct{}
	tags     map[string]struct{}
	blocking bool
	applied  *types.AppliedVEXStatement
}

func buildRepositoryCard(repository string, scans []*statestore.ScanRecord, in repositoryCardInput) TriageRepository {
	card := TriageRepository{Repository: repository, PolicyPassed: true, Tags: []TriageRepositoryTag{}, CVEs: []TriageRepositoryCVE{}}
	sort.Slice(scans, func(i, j int) bool { return scans[i].Tag < scans[j].Tag })
	acc := map[string]*cveAccumulator{}
	get := func(id string) *cveAccumulator {
		item, ok := acc[id]
		if !ok {
			item = &cveAccumulator{cveID: id, packages: map[string]struct{}{}, tags: map[string]struct{}{}}
			acc[id] = item
		}
		return item
	}
	for _, scan := range scans {
		passed := scan.PolicyStatus == "passed" || (scan.PolicyStatus == "" && scan.PolicyPassed)
		if !passed {
			card.PolicyPassed = false
		}
		card.Tags = append(card.Tags, TriageRepositoryTag{Tag: scan.Tag, Digest: scan.Digest, PolicyPassed: passed, PolicyStatus: scan.PolicyStatus})
		for _, finding := range scan.PolicyFailureFindings {
			item := get(finding.CVEID)
			item.blocking = true
			item.tags[scan.Tag] = struct{}{}
			if finding.PackageName != "" {
				item.packages[finding.PackageName] = struct{}{}
			}
		}
		for i := range scan.AppliedVEXStatements {
			applied := scan.AppliedVEXStatements[i]
			item := get(applied.CVEID)
			item.tags[scan.Tag] = struct{}{}
			if item.applied == nil {
				item.applied = &applied
			}
		}
	}
	sources := map[string]string{}
	if in.Statements != nil {
		for _, statement := range in.Statements(repository) {
			if _, seen := sources[statement.ID]; !seen {
				sources[statement.ID] = statementSource(statement.Source)
			}
		}
	}
	for _, item := range acc {
		cve := repositoryCVE(repository, item, sources, in)
		card.CVEs = append(card.CVEs, cve)
		countCVE(&card.Counts, cve)
	}
	sort.Slice(card.CVEs, func(i, j int) bool {
		a, b := card.CVEs[i], card.CVEs[j]
		if phaseOrder(a.Phase) != phaseOrder(b.Phase) {
			return phaseOrder(a.Phase) < phaseOrder(b.Phase)
		}
		return a.CVEID < b.CVEID
	})
	return card
}

func repositoryCVE(repository string, item *cveAccumulator, sources map[string]string, in repositoryCardInput) TriageRepositoryCVE {
	key := triage.SkipKey(repository, item.cveID)
	cve := TriageRepositoryCVE{
		CVEID:    item.cveID,
		Blocking: item.blocking,
		Packages: sortedKeys(item.packages),
		Tags:     sortedKeys(item.tags),
	}
	if run, ok := in.Runs[key]; ok {
		attached := run
		cve.Run = &attached
	}
	if !item.blocking {
		cve.Phase = phaseExempt
		cve.Origin = sources[item.cveID]
		if cve.Origin == "" {
			cve.Origin = "manual"
		}
		if item.applied != nil {
			cve.State = string(item.applied.State)
			cve.Justification = string(item.applied.Justification)
			cve.Detail = item.applied.Detail
			if item.applied.ExpiresAt != nil {
				cve.ExpiresAt = *item.applied.ExpiresAt
			}
		}
		cve.Reason = "Covered by an exemption, so it does not block the policy."
		return cve
	}

	skip, hasSkip := in.Skips[key]
	if hasSkip {
		cve.ReasonCode = skip.Code
		cve.ReasonAt = skip.At.Unix()
	}
	running, inSession := in.Running[key]
	switch {
	case inSession && running:
		cve.Phase = phaseRunning
		cve.Reason = "Being decided by the model now."
	case inSession:
		cve.Phase = phaseRunning
		cve.Reason = "In this repository's model session, waiting for its turn."
	case in.Queued[key]:
		cve.Phase = phaseQueued
		if in.BudgetExhausted {
			cve.Reason = "Queued, but the daily token budget is used up. It continues after a reset or at UTC midnight."
		} else {
			cve.Reason = "Queued. It starts when the worker is free."
		}
	case cve.Run != nil:
		cve.Phase, cve.Reason = runPhase(*cve.Run, skip, hasSkip)
	default:
		cve.Phase = phaseNotTriaged
		cve.Reason = notTriagedReason(skip, hasSkip)
	}
	return cve
}

func runPhase(run TriageRunResponse, skip triage.Skip, hasSkip bool) (string, string) {
	retry := ""
	if hasSkip && skip.Code == triage.SkipCached {
		retry = " It was not retried because the gitops commits and the package set are unchanged. Run it again to retry."
	}
	if hasSkip && skip.Code == triage.SkipBudget {
		retry = " A later attempt stopped because the daily token budget ran out."
	}
	switch {
	case run.Status == "error" || run.Status == "push_failed":
		return phaseError, "The last attempt failed." + retry
	case run.Status == "rejected_by_guardrail" || run.Verdict == "uncertain":
		return phaseUncertain, "The model could not show this is unaffected, so nothing was written." + retry
	case run.Status == "dry_run":
		return phaseDecided, "Decided in dry-run mode, so nothing was written to gitops."
	default:
		return phaseDecided, "Written to gitops. It stops blocking after the image is scanned again."
	}
}

func notTriagedReason(skip triage.Skip, hasSkip bool) string {
	if hasSkip {
		switch skip.Code {
		case triage.SkipBudget:
			return "Skipped because the daily token budget ran out before this CVE."
		case triage.SkipNotInScans:
			return "Skipped because the CVE is no longer in the current scans of this repository."
		case triage.SkipNotInUse:
			return "Skipped because triage only looks at repositories that are running."
		case triage.SkipExempt:
			return "An exemption already covers it. The block clears after the next scan."
		}
	}
	return "Not triaged yet. It is queued the next time this image is scanned, or use Triage now."
}

func countCVE(counts *TriageRepositoryCounts, cve TriageRepositoryCVE) {
	if cve.Blocking {
		counts.Blocking++
	}
	switch cve.Phase {
	case phaseUncertain:
		counts.Uncertain++
		counts.NeedsAttention++
	case phaseError:
		counts.Failed++
		counts.NeedsAttention++
	case phaseNotTriaged:
		counts.NotTriaged++
		counts.NeedsAttention++
	case phaseRunning, phaseQueued:
		counts.InProgress++
	case phaseDecided:
		counts.Decided++
	case phaseExempt:
		if cve.Origin == "auto" {
			counts.ExemptAuto++
		} else {
			counts.ExemptManual++
		}
	}
}

func phaseOrder(phase string) int {
	switch phase {
	case phaseUncertain:
		return 0
	case phaseError:
		return 1
	case phaseNotTriaged:
		return 2
	case phaseRunning:
		return 3
	case phaseQueued:
		return 4
	case phaseDecided:
		return 5
	default:
		return 6
	}
}

func sortedKeys(set map[string]struct{}) []string {
	out := make([]string, 0, len(set))
	for key := range set {
		if strings.TrimSpace(key) != "" {
			out = append(out, key)
		}
	}
	sort.Strings(out)
	return out
}
