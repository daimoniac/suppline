package api

import (
	"strings"

	"github.com/daimoniac/suppline/internal/types"
)

// TriageStatement is one repository and CVE on the triage list.
// Source is auto, manual, or open. NeedsFix is the single meaning of an open triage:
// the latest run is uncertain, rejected, or failed, and a later run has not replaced it.
// AffectedImageCount is how many current image digests contain the finding.
// TriagedAt is the latest stored triage run for this repository and CVE.
// A newer run replaces it. It stays zero when no run exists.
// CreatedAt is when a statement was applied to a scan, which is a different time.
type TriageStatement struct {
	CVEID              string             `json:"CVEID"`
	Repository         string             `json:"Repository"`
	State              string             `json:"State"`
	Justification      string             `json:"Justification,omitempty"`
	Detail             string             `json:"Detail,omitempty"`
	ExpiresAt          int64              `json:"ExpiresAt"`
	CreatedAt          int64              `json:"CreatedAt"`
	TriagedAt          int64              `json:"TriagedAt"`
	AffectedImageCount int                `json:"AffectedImageCount"`
	Source             string             `json:"Source"`
	NeedsFix           bool               `json:"NeedsFix"`
	Run                *TriageRunResponse `json:"Run,omitempty"`
}

func statementCVEIDs(statements []*types.VEXInfo, runs []TriageRunResponse) []string {
	seen := make(map[string]struct{})
	ids := make([]string, 0, len(statements)+len(runs))
	add := func(raw string) {
		cveID := strings.TrimSpace(raw)
		if cveID == "" {
			return
		}
		if _, ok := seen[cveID]; ok {
			return
		}
		seen[cveID] = struct{}{}
		ids = append(ids, cveID)
	}
	for _, statement := range statements {
		if statement != nil {
			add(statement.CVEID)
		}
	}
	for _, run := range runs {
		add(run.CVEID)
	}
	return ids
}

// statementList builds one row per repository and CVE. statements holds one
// entry per repository and CVE, so each row carries that repository's own
// state, justification, detail, and expiry. Grouping by CVE first would give
// every repository the statement of whichever one was seen first.
func statementList(statements []*types.VEXInfo, runs []TriageRunResponse, findingImages map[string]int) []TriageStatement {
	runsByPair := map[string]TriageRunResponse{}
	for _, run := range runs {
		key := run.Repository + "\n" + run.CVEID
		prev, ok := runsByPair[key]
		if !ok || betterStatementRun(run, prev) {
			runsByPair[key] = run
		}
	}

	rows := []TriageStatement{}
	seen := map[string]bool{}
	for _, statement := range statements {
		if statement == nil {
			continue
		}
		key := statement.Repository + "\n" + statement.CVEID
		if seen[key] {
			continue
		}
		seen[key] = true
		expires := int64(0)
		if statement.ExpiresAt != nil {
			expires = *statement.ExpiresAt
		}
		run, hasRun := runsByPair[key]
		created := statement.AppliedAt
		var attached *TriageRunResponse
		triagedAt := int64(0)
		if hasRun {
			if created == 0 {
				created = run.CreatedAt
			}
			attached = &run
			triagedAt = run.CreatedAt
		}
		rows = append(rows, TriageStatement{
			CVEID:              statement.CVEID,
			Repository:         statement.Repository,
			State:              string(statement.State),
			Justification:      string(statement.Justification),
			Detail:             statement.Detail,
			ExpiresAt:          expires,
			CreatedAt:          created,
			TriagedAt:          triagedAt,
			AffectedImageCount: findingImages[statement.CVEID],
			Source:             statementSource(statement.Source),
			NeedsFix:           hasRun && runNeedsFix(run),
			Run:                attached,
		})
	}
	for key, run := range runsByPair {
		if seen[key] || run.Superseded {
			continue
		}
		state := ""
		switch {
		case knownStatementState(run.WrittenState):
			state = run.WrittenState
		case knownStatementState(run.Verdict):
			state = run.Verdict
		}
		rows = append(rows, TriageStatement{
			CVEID:              run.CVEID,
			Repository:         run.Repository,
			State:              state,
			Justification:      run.Justification,
			Detail:             run.Reasoning,
			CreatedAt:          run.CreatedAt,
			TriagedAt:          run.CreatedAt,
			AffectedImageCount: findingImages[run.CVEID],
			Source:             "open",
			NeedsFix:           runNeedsFix(run),
			Run:                &run,
		})
	}
	return rows
}

func betterStatementRun(next, prev TriageRunResponse) bool {
	if prev.Superseded != next.Superseded {
		return !next.Superseded
	}
	return next.CreatedAt > prev.CreatedAt
}

func statementSource(source string) string {
	if source == types.VEXSourceAuto {
		return "auto"
	}
	return "manual"
}

func runNeedsFix(run TriageRunResponse) bool {
	if run.Superseded {
		return false
	}
	switch run.Status {
	case "rejected_by_guardrail", "error", "push_failed":
		return true
	}
	return run.Verdict == "uncertain"
}

func knownStatementState(state string) bool {
	switch types.VEXAnalysisState(state) {
	case types.VEXStateNotAffected, types.VEXStateAffected, types.VEXStateInTriage,
		types.VEXStateFalsePositive, types.VEXStateResolved, types.VEXStateResolvedWithPedigree:
		return true
	default:
		return false
	}
}
