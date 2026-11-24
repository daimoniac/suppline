package triage

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/daimoniac/suppline/internal/statestore"
	"github.com/daimoniac/suppline/internal/types"
)

// priorEvidence is what the run that wrote an existing auto statement cited.
type priorEvidence struct {
	TriageID string
	State    types.VEXAnalysisState
	Items    []modelEvidence
	// Missing says why the citations could not be loaded.
	Missing string
}

// statementTriageID reads the triage_id line of an auto statement's detail.
func statementTriageID(detail string) string {
	for _, line := range strings.Split(detail, "\n") {
		if value, ok := strings.CutPrefix(strings.TrimSpace(line), "triage_id:"); ok {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

// loadPriorEvidence finds the run that wrote each existing statement and
// returns its accepted citations, so a later session can replay them.
func loadPriorEvidence(ctx context.Context, runs statestore.TriageStore, repository string, existing map[string]*types.VEXStatement) map[string]priorEvidence {
	out := map[string]priorEvidence{}
	for cve, statement := range existing {
		if statement == nil {
			continue
		}
		prior := priorEvidence{TriageID: statementTriageID(statement.Detail), State: statement.State}
		switch {
		case prior.TriageID == "":
			prior.Missing = "the statement detail names no triage_id"
		case runs == nil:
			prior.Missing = "triage runs are not stored"
		default:
			items, err := writtenRunEvidence(ctx, runs, repository, cve, prior.TriageID)
			if err != nil {
				prior.Missing = err.Error()
			}
			prior.Items = items
		}
		out[cve] = prior
	}
	return out
}

func writtenRunEvidence(ctx context.Context, runs statestore.TriageStore, repository, cve, triageID string) ([]modelEvidence, error) {
	list, err := runs.ListTriageRuns(ctx, statestore.TriageFilter{Repository: repository, CVEID: cve, Limit: 200})
	if err != nil {
		return nil, fmt.Errorf("load triage runs: %w", err)
	}
	for _, run := range list {
		if run.SessionID != triageID || (run.Status != StatusWritten && run.Status != StatusCommitted) {
			continue
		}
		var items []modelEvidence
		if strings.TrimSpace(run.EvidenceJSON) != "" && run.EvidenceJSON != "null" {
			if err := json.Unmarshal([]byte(run.EvidenceJSON), &items); err != nil {
				return nil, fmt.Errorf("decode evidence of %s: %w", triageID, err)
			}
		}
		if len(items) == 0 {
			return nil, fmt.Errorf("run %s stored no citations", triageID)
		}
		return items, nil
	}
	return nil, fmt.Errorf("no written run %s is stored for %s", triageID, cve)
}

// recheckEvidence replays the existing statement's citations against this
// session's image and checkouts. Each replayed search is recorded in this
// turn, so its new grep_id can be cited.
func recheckEvidence(ctx context.Context, t *toolbox, job Job) (string, error) {
	if t.pub.currentPhase() == phaseContext {
		return "", fmt.Errorf("call recheck_evidence in the decision turn of the CVE, not in the context phase")
	}
	prior, ok := t.prior[job.CVEID]
	if !ok {
		return "", fmt.Errorf("%s has no existing auto statement to recheck", job.CVEID)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "existing statement: %s from triage_id %s\n", prior.State, firstNonEmpty(prior.TriageID, "(unknown)"))
	if prior.Missing != "" {
		fmt.Fprintf(&b, "citations unavailable: %s\nGather the evidence again with the other tools.\n", prior.Missing)
		return b.String(), nil
	}
	files := checkouts{roots: t.roots, ledger: t.pub, job: job}
	for i, item := range prior.Items {
		fmt.Fprintf(&b, "\nevidence[%d]: ", i)
		out, err := t.replay(ctx, files, job, item, &b)
		if err != nil {
			fmt.Fprintf(&b, "error: %s\n", oneLine(err.Error(), 300))
			continue
		}
		b.WriteString(out)
		if !strings.HasSuffix(out, "\n") {
			b.WriteByte('\n')
		}
	}
	return b.String(), nil
}

// replay runs one earlier citation again and returns the tool output.
func (t *toolbox) replay(ctx context.Context, files checkouts, job Job, item modelEvidence, b *strings.Builder) (string, error) {
	pattern := strings.TrimSpace(item.Pattern)
	repo := strings.TrimSpace(item.Repo)
	switch {
	case pattern != "" && repo == imageCheckoutName:
		if name, ok := strings.CutPrefix(pattern, imageNamePrefix); ok {
			fmt.Fprintf(b, "file search %q in %s of the current image\n", name, cleanRel(item.Path))
			return imageFiles(ctx, t.roots, t.pub, job, name, item.Path)
		}
		if name, ok := strings.CutPrefix(pattern, packagePrefix); ok {
			fmt.Fprintf(b, "package files of %s in the current image\n", name)
			return packageFiles(ctx, t.roots, t.pub, job, name)
		}
		fmt.Fprintf(b, "grep %q in %s of the current image\n", pattern, cleanRel(item.Path))
		return imageGrep(ctx, t.roots, t.pub, job, pattern, item.Path)
	case pattern != "" && strings.Contains(repo, "/"):
		return t.replayPublicGrep(ctx, item, b)
	case item.Line > 0 && t.gitopsCheckout(repo):
		fmt.Fprintf(b, "line %s:%s:%d\n", repo, item.Path, item.Line)
		line, err := t.roots.Line(repo, item.Path, item.Line)
		if err != nil {
			return "", err
		}
		quote := strings.TrimSpace(item.Quote)
		if quote != "" && !strings.Contains(line, quote) && !strings.Contains(quote, strings.TrimSpace(line)) {
			return fmt.Sprintf("changed; the line now reads: %s\nearlier quote: %s\n", oneLine(line, 200), oneLine(quote, 200)), nil
		}
		return fmt.Sprintf("unchanged: %s\ncite it as repo %s, path %s, line %d, quote from this line\n", oneLine(line, 200), repo, item.Path, item.Line), nil
	default:
		fmt.Fprintf(b, "line %s:%s:%d\n", repo, item.Path, item.Line)
		return "not replayable: read it again with public_code or read_file before citing it\n", nil
	}
}

// replayPublicGrep greps the same path of a public repository. It uses the
// commit this session already checked out, so the replay never moves the
// model's checkout to an older commit.
func (t *toolbox) replayPublicGrep(ctx context.Context, item modelEvidence, b *strings.Builder) (string, error) {
	owner, repo, _ := strings.Cut(item.Repo, "/")
	commit := strings.TrimSpace(item.Commit)
	note := "at the earlier run's commit; cite it only if image_source names this commit"
	if t.roots != nil {
		if root, err := t.roots.checkout(item.Repo); err == nil && root.Public && root.SHA != "" {
			if root.SHA != strings.ToLower(commit) {
				note = fmt.Sprintf("at this session's checkout %s; the earlier run used %s", root.SHA, firstNonEmpty(commit, "an unrecorded commit"))
			} else {
				note = "at this session's checkout, the same commit the earlier run used"
			}
			commit = root.SHA
		}
	}
	fmt.Fprintf(b, "grep %q in %s:%s %s\n", item.Pattern, item.Repo, cleanRel(item.Path), note)
	if commit == "" {
		return "", fmt.Errorf("the earlier citation names no commit")
	}
	if t.upstream == nil || t.roots == nil {
		return "", fmt.Errorf("public checkout is unavailable")
	}
	root, err := t.roots.checkout(item.Repo)
	_, covered := root.covers(item.Path)
	if err != nil || root.SHA != commit || !covered {
		if _, err := t.upstream.Checkout(ctx, t.roots, owner, repo, commit, cleanRel(item.Path)); err != nil {
			return "", err
		}
	}
	return publicGrep(t.roots, t.pub, item.Repo, item.Pattern, item.Path)
}

// gitopsCheckout reports whether repo is one of the session's gitops checkouts.
func (t *toolbox) gitopsCheckout(repo string) bool {
	if t.roots == nil {
		return false
	}
	root, err := t.roots.checkout(repo)
	return err == nil && !root.Public && root.Name != imageCheckoutName
}
