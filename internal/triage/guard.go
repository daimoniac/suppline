package triage

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/daimoniac/suppline/internal/gitops"
	"github.com/daimoniac/suppline/internal/types"
)

type outcome string

const (
	outcomeReject      outcome = "reject"
	outcomeNotAffected outcome = "not_affected"
	outcomeAffected    outcome = "affected"
)

type verdictDecision struct {
	Action    outcome
	Reason    string
	Statement types.VEXStatement
}

// kevLookup reports whether a CVE is in the CISA KEV catalog.
type kevLookup interface {
	Contains(ctx context.Context, cveID string) (bool, error)
}

// guard decides what a model verdict may change. It checks the cited evidence
// against what the session's tools returned, consults the KEV catalog, and
// applies the confidence, justification and flip rules, in that order.
type guard struct {
	settings Settings
	kev      kevLookup // nil skips the KEV check
	now      func() time.Time
}

// judge returns the decision for one verdict. It filters verdict.Evidence down
// to the citations that check out, so the caller records what was accepted.
func (g guard) judge(ctx context.Context, tools *toolbox, job Job, verdict *modelVerdict, existing *types.VEXStatement, checkouts []gitops.Checkout, triageID string) verdictDecision {
	tools = tools.ready()
	evidenceErr := ""
	if err := verifyEvidence(*tools.roots, tools.pub, job, verdict); err != nil {
		evidenceErr = err.Error()
	}
	var kevHit bool
	var kevErr error
	if g.settings.BlockKEV && g.kev != nil {
		kevHit, kevErr = g.kev.Contains(ctx, job.CVEID)
	}
	return decide(g.settings, job, *verdict, evidenceErr, kevHit, kevErr, existing, checkouts, triageID, g.now())
}

func decide(settings Settings, job Job, verdict modelVerdict, evidenceErr string, kev bool, kevErr error, existing *types.VEXStatement, checkouts []gitops.Checkout, triageID string, now time.Time) verdictDecision {
	if settings.BlockKEV && kevErr != nil {
		// An unreachable feed says nothing about this CVE, so an existing
		// statement stays until it expires.
		return verdictDecision{Action: outcomeReject, Reason: "CISA KEV feed unavailable: " + kevErr.Error()}
	}
	if settings.BlockKEV && kev {
		return flipOrReject(existing, job, verdict, "CVE is listed in the CISA Known Exploited Vulnerabilities catalog", settings, checkouts, triageID, now)
	}

	reason := ""
	switch {
	case verdict.Verdict != "not_affected":
		reason = "model verdict is " + verdict.Verdict
	case verdict.Confidence < settings.MinConfidence:
		reason = fmt.Sprintf("confidence %.2f is below %.2f", verdict.Confidence, settings.MinConfidence)
	case evidenceErr != "":
		reason = evidenceErr
	case len(verdict.Evidence) == 0:
		reason = "not_affected requires evidence"
	case len(job.InUse) > 1 && !verdict.CoversListedDigests:
		reason = "covers_listed_digests is not true"
	default:
		justification := types.NormalizeVEXJustification(types.VEXJustification(verdict.Justification))
		if _, ok := settings.Allowed[justification]; !ok {
			reason = fmt.Sprintf("justification %q is not allowed", verdict.Justification)
			break
		}
		expires := now.Add(settings.Expiry).Unix()
		return verdictDecision{
			Action: outcomeNotAffected,
			Statement: types.VEXStatement{
				ID:            job.CVEID,
				State:         types.VEXStateNotAffected,
				Justification: justification,
				Detail:        provenance(triageID, settings.Model, checkouts, types.VEXStateNotAffected, verdict, "", now),
				ExpiresAt:     &expires,
				Source:        types.VEXSourceAuto,
			},
		}
	}
	// Only a verdict that finds the deployment affected overturns an existing
	// statement. uncertain, or a not_affected the guard could not check, means
	// the session could not prove the case again, often because a tool failed;
	// the existing statement stays until it expires or a person decides.
	if verdict.Verdict == "affected" {
		return flipOrReject(existing, job, verdict, reason, settings, checkouts, triageID, now)
	}
	return verdictDecision{Action: outcomeReject, Reason: reason + ": " + verdict.Reasoning}
}

// flipOrReject turns an existing not_affected auto statement into affected.
// Without one there is nothing to change, so the run is rejected.
func flipOrReject(existing *types.VEXStatement, job Job, verdict modelVerdict, reason string, settings Settings, checkouts []gitops.Checkout, triageID string, now time.Time) verdictDecision {
	full := reason
	if strings.TrimSpace(verdict.Reasoning) != "" {
		full = reason + ": " + verdict.Reasoning
	}
	if existing == nil || existing.State != types.VEXStateNotAffected {
		return verdictDecision{Action: outcomeReject, Reason: full}
	}
	expires := now.Add(settings.Expiry).Unix()
	return verdictDecision{
		Action: outcomeAffected,
		Reason: full,
		Statement: types.VEXStatement{
			ID:        job.CVEID,
			State:     types.VEXStateAffected,
			Detail:    provenance(triageID, settings.Model, checkouts, types.VEXStateAffected, verdict, reason, now),
			ExpiresAt: &expires,
			Source:    types.VEXSourceAuto,
		},
	}
}

// provenance is the detail of an auto statement. state is what was written;
// model_verdict and confidence are what the model returned; guard is set when
// the guard, not the model, decided the state.
func provenance(triageID, model string, checkouts []gitops.Checkout, state types.VEXAnalysisState, verdict modelVerdict, guardReason string, now time.Time) string {
	var repos []string
	for _, checkout := range checkouts {
		repos = append(repos, checkout.Name+"@"+checkout.SHA)
	}
	var evidence []string
	for _, item := range verdict.Evidence {
		if item.Line < 1 && item.Pattern != "" {
			evidence = append(evidence, fmt.Sprintf("%s:%s:%s", item.Repo, item.Path, item.Pattern))
			continue
		}
		evidence = append(evidence, fmt.Sprintf("%s:%s:%d", item.Repo, item.Path, item.Line))
	}
	cited := strings.Join(evidence, "; ")
	if cited == "" {
		cited = "none"
	}
	modelVerdict := verdict.Verdict
	if modelVerdict == "" {
		modelVerdict = "none"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "auto-generated by suppline triage\ntriage_id: %s\nmodel: %s\ntimestamp: %s\nrepos: %s\nstate: %s\nmodel_verdict: %s\nconfidence: %.2f\nevidence: %s\n",
		triageID, model, now.UTC().Format(time.RFC3339), strings.Join(repos, " "), state, modelVerdict, verdict.Confidence, cited)
	if strings.TrimSpace(guardReason) != "" {
		fmt.Fprintf(&b, "guard: %s\n", strings.TrimSpace(guardReason))
	}
	fmt.Fprintf(&b, "reasoning: %s", strings.TrimSpace(verdict.Reasoning))
	text := b.String()
	if len(text) > 4000 {
		text = text[:4000]
	}
	return text
}

func verifyEvidence(roots Roots, pub *publicSource, job Job, verdict *modelVerdict) error {
	if verdict == nil || verdict.Verdict != "not_affected" {
		return nil
	}
	justification := types.NormalizeVEXJustification(types.VEXJustification(verdict.Justification))
	gitopsHits := 0
	publicHits := 0
	absenceHits := 0
	filtered := make([]modelEvidence, 0, len(verdict.Evidence))
	for i, item := range verdict.Evidence {
		if id := strings.TrimSpace(item.GrepID); id != "" {
			hit, ok := pub.grep(id)
			if pub == nil || !ok {
				verdict.Evidence = filtered
				return fmt.Errorf("evidence[%d] grep_id %s was not returned by a public grep", i, id)
			}
			if hit.Phase != "" && hit.Phase != phaseContext && job.CVEID != "" && hit.Phase != job.CVEID {
				verdict.Evidence = filtered
				return fmt.Errorf("evidence[%d] grep_id %s was recorded for %s", i, id, hit.Phase)
			}
			switch hit.Cite {
			case citeAbsence:
				filtered = append(filtered, modelEvidence{
					Repo: hit.Repo, Path: hit.Path, Pattern: hit.Pattern, Commit: hit.Commit, GrepID: hit.ID,
				})
				absenceHits++
				continue
			case citeRows:
				if len(hit.Rows) == 0 {
					verdict.Evidence = filtered
					return fmt.Errorf("evidence[%d] grep_id %s returned no citable lines", i, id)
				}
			default:
				verdict.Evidence = filtered
				return fmt.Errorf("evidence[%d] grep_id %s is not absence", i, id)
			}
			for _, row := range hit.Rows {
				filtered = append(filtered, modelEvidence{
					Repo: hit.Repo, Path: row.Path, Line: row.Line, Quote: row.Text, GrepID: hit.ID,
				})
				publicHits++
			}
			continue
		}
		if strings.TrimSpace(item.Quote) == "" && strings.TrimSpace(item.Pattern) != "" {
			continue
		}
		if strings.TrimSpace(item.Quote) == "" || item.Line < 1 || strings.TrimSpace(item.Path) == "" {
			verdict.Evidence = filtered
			return fmt.Errorf("evidence[%d] needs repo, path, line, and quote", i)
		}
		line, fromPublic := "", false
		if pub != nil {
			if text, ok := pub.line(item.Repo, item.Path, item.Line); ok {
				line, fromPublic = text, true
			}
		}
		if !fromPublic {
			got, err := roots.Line(item.Repo, item.Path, item.Line)
			if err != nil {
				verdict.Evidence = filtered
				return fmt.Errorf("evidence[%d]: %w", i, err)
			}
			line = got
			gitopsHits++
		} else {
			publicHits++
		}
		if !strings.Contains(line, strings.TrimSpace(item.Quote)) && !strings.Contains(strings.TrimSpace(item.Quote), strings.TrimSpace(line)) {
			verdict.Evidence = filtered
			return fmt.Errorf("evidence[%d] quote does not match %s:%d", i, item.Path, item.Line)
		}
		filtered = append(filtered, item)
	}
	verdict.Evidence = filtered
	if justification == types.VEXJustCodeNotReachable || justification == types.VEXJustCodeNotPresent {
		if publicHits > 0 || absenceHits > 0 {
			return nil
		}
		return fmt.Errorf("%s requires a public checkout line, a recorded image or package-database line, or a citable absence", justification)
	}
	if justification == types.VEXJustRequiresConfiguration || justification == types.VEXJustRequiresEnvironment {
		if gitopsHits == 0 && publicHits == 0 {
			return fmt.Errorf("%s requires a gitops or public checkout line", justification)
		}
		return nil
	}
	if gitopsHits == 0 {
		return fmt.Errorf("%s requires a gitops checkout line", justification)
	}
	return nil
}
