package triage

import (
	"context"
	"fmt"

	"github.com/daimoniac/suppline/internal/types"
)

type sessionTurn struct {
	Job     Job
	Verdict modelVerdict
	Tokens  int
	Err     error
}

type sessionResult struct {
	ContextTokens int
	Turns         []sessionTurn
	Err           error
}

type sessionHooks struct {
	onContext func()
	onCVE     func(string)
}

// runSession gathers image context once, then asks for one verdict per CVE.
// A CVE turn that fails does not discard verdicts already parsed. CVEs not
// started because the token budget is spent are omitted from Turns.
func runSession(ctx context.Context, llm completer, roots *Roots, runtime clusterQuerier, pub *publicSource, upstream *publicCheckouts, images imageLabeler, manifests manifestSource, allowed []string, policy string, minConfidence float64, jobs []Job, repoNames []string, existing map[string]*types.VEXStatement, maxSteps int, allow func() bool, hooks sessionHooks) sessionResult {
	if len(jobs) == 0 {
		return sessionResult{}
	}
	if pub == nil {
		pub = newPublicSource()
	}
	if allow == nil {
		allow = func() bool { return true }
	}
	if existing == nil {
		existing = map[string]*types.VEXStatement{}
	}
	messages := []chatMessage{
		{Role: "system", Content: systemPrompt(allowed, runtime != nil, policy, minConfidence)},
		{Role: "user", Content: contextPrompt(jobs, repoNames)},
	}
	tools := toolDefinitions(runtime != nil)
	if hooks.onContext != nil {
		hooks.onContext()
	}
	pub.setPhase(phaseContext)
	contextJob := jobs[0]
	contextJob.PackageName = ""
	_, contextTokens, err := runPhase(ctx, llm, roots, runtime, pub, upstream, images, manifests, &messages, tools, contextJob, maxSteps,
		"Context gathering stops here. Do not return a verdict.")
	if err != nil {
		return sessionResult{ContextTokens: contextTokens, Err: err}
	}
	result := sessionResult{ContextTokens: contextTokens}
	for _, job := range jobs {
		if ctx.Err() != nil {
			result.Turns = append(result.Turns, sessionTurn{Job: job, Err: ctx.Err()})
			return result
		}
		if !allow() {
			return result
		}
		if hooks.onCVE != nil {
			hooks.onCVE(job.CVEID)
		}
		pub.setPhase(job.CVEID)
		messages = append(messages, chatMessage{Role: "user", Content: cvePrompt(job, existing[job.CVEID])})
		content, tokens, err := runPhase(ctx, llm, roots, runtime, pub, upstream, images, manifests, &messages, tools, job, maxSteps,
			"No more tool calls. Return only the JSON verdict now. Accept a low residual risk with requires_configuration or requires_environment when a line you read supports it. "+evidenceContract()+" Use uncertain when a fact you need was not returned by a tool.")
		turn := sessionTurn{Job: job, Tokens: tokens}
		if err != nil {
			turn.Err = err
			result.Turns = append(result.Turns, turn)
			continue
		}
		verdict, err := parseVerdict(content)
		if err != nil {
			turn.Err = err
			result.Turns = append(result.Turns, turn)
			continue
		}
		turn.Verdict = verdict
		result.Turns = append(result.Turns, turn)
	}
	return result
}

func splitContextTokens(contextTokens int, turns []sessionTurn) []int {
	out := make([]int, len(turns))
	decided := 0
	for _, turn := range turns {
		if turn.Err == nil {
			decided++
		}
	}
	if len(turns) == 0 || contextTokens == 0 {
		return out
	}
	targets := decided
	if targets == 0 {
		targets = len(turns)
	}
	share := contextTokens / targets
	rem := contextTokens - share*targets
	given := false
	for i, turn := range turns {
		if decided > 0 && turn.Err != nil {
			continue
		}
		out[i] = share
		if !given {
			out[i] += rem
			given = true
		}
	}
	return out
}

func sessionFailure(err error) string {
	if err == nil {
		return ""
	}
	return fmt.Sprintf("triage session: %s", err.Error())
}
