package api

import (
	"github.com/daimoniac/suppline/internal/types"
)

// TriageStatement is one repository and CVE on the triage list.
// Source is auto, manual, or open. NeedsFix is the single meaning of an open triage:
// the latest run is uncertain, rejected, or failed, and a later run has not replaced it.
type TriageStatement struct {
	CVEID              string             `json:"CVEID"`
	Repository         string             `json:"Repository"`
	State              string             `json:"State"`
	Justification      string             `json:"Justification,omitempty"`
	Detail             string             `json:"Detail,omitempty"`
	ExpiresAt          int64              `json:"ExpiresAt"`
	CreatedAt          int64              `json:"CreatedAt"`
	AffectedImageCount int                `json:"AffectedImageCount"`
	Source             string             `json:"Source"`
	NeedsFix           bool               `json:"NeedsFix"`
	Run                *TriageRunResponse `json:"Run,omitempty"`
}

func statementList(active, inactive []*types.VEXSummary, runs []TriageRunResponse) []TriageStatement {
	runsByPair := map[string]TriageRunResponse{}
	for _, run := range runs {
		key := run.Repository + "\n" + run.CVEID
		prev, ok := runsByPair[key]
		if !ok || betterStatementRun(run, prev) {
			runsByPair[key] = run
		}
	}
	imageCount := map[string]int{}
	for _, summary := range active {
		if summary == nil {
			continue
		}
		if summary.AffectedImageCount > imageCount[summary.CVEID] {
			imageCount[summary.CVEID] = summary.AffectedImageCount
		}
	}
	for _, summary := range inactive {
		if summary == nil || imageCount[summary.CVEID] > 0 {
			continue
		}
		if summary.AffectedImageCount > imageCount[summary.CVEID] {
			imageCount[summary.CVEID] = summary.AffectedImageCount
		}
	}

	rows := []TriageStatement{}
	seen := map[string]bool{}
	for _, summary := range append(append([]*types.VEXSummary{}, active...), inactive...) {
		if summary == nil {
			continue
		}
		expires := int64(0)
		if summary.ExpiresAt != nil {
			expires = *summary.ExpiresAt
		}
		for _, repo := range summary.Repositories {
			key := repo.Repository + "\n" + summary.CVEID
			if seen[key] {
				continue
			}
			seen[key] = true
			run, hasRun := runsByPair[key]
			created := repo.AppliedAt
			if created == 0 && hasRun {
				created = run.CreatedAt
			}
			var attached *TriageRunResponse
			if hasRun {
				attached = &run
			}
			rows = append(rows, TriageStatement{
				CVEID:              summary.CVEID,
				Repository:         repo.Repository,
				State:              string(summary.State),
				Justification:      string(summary.Justification),
				Detail:             summary.Detail,
				ExpiresAt:          expires,
				CreatedAt:          created,
				AffectedImageCount: imageCount[summary.CVEID],
				Source:             statementSource(repo.Source),
				NeedsFix:           hasRun && runNeedsFix(run),
				Run:                attached,
			})
		}
	}
	for key, run := range runsByPair {
		if seen[key] || run.Superseded {
			continue
		}
		state := ""
		if knownStatementState(run.Verdict) {
			state = run.Verdict
		}
		rows = append(rows, TriageStatement{
			CVEID:              run.CVEID,
			Repository:         run.Repository,
			State:              state,
			Justification:      run.Justification,
			Detail:             run.Reasoning,
			CreatedAt:          run.CreatedAt,
			AffectedImageCount: imageCount[run.CVEID],
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
