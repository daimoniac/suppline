package triage

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/daimoniac/suppline/internal/types"
)

type completer interface {
	Complete(ctx context.Context, messages []chatMessage, tools []toolDef) (completion, error)
}

type modelVerdict struct {
	Verdict       string          `json:"verdict"`
	Justification string          `json:"justification"`
	Confidence    float64         `json:"confidence"`
	Evidence      []modelEvidence `json:"evidence"`
	Reasoning     string          `json:"reasoning"`
}

type modelEvidence struct {
	Repo    string `json:"repo"`
	Path    string `json:"path"`
	Line    int    `json:"line"`
	Quote   string `json:"quote"`
	Pattern string `json:"pattern,omitempty"`
	Commit  string `json:"commit,omitempty"`
	GrepID  string `json:"grep_id,omitempty"`
}

func runAgent(ctx context.Context, llm completer, roots *Roots, runtime clusterQuerier, pub *publicSource, upstream *publicCheckouts, images imageLabeler, manifests manifestSource, allowed []string, policy string, minConfidence float64, job Job, placements string, repoNames []string, existing *types.VEXStatement, maxSteps int) (modelVerdict, int, error) {
	if maxSteps < 1 {
		maxSteps = 1
	}
	if pub == nil {
		pub = newPublicSource()
	}
	messages := []chatMessage{
		{Role: "system", Content: systemPrompt(allowed, runtime != nil, policy, minConfidence)},
		{Role: "user", Content: userPrompt(job, placements, repoNames, existing)},
	}
	tools := toolDefinitions(runtime != nil)
	tokens := 0
	for step := 0; step < maxSteps; step++ {
		stepTools := tools
		if step == maxSteps-1 {
			messages = append(messages, chatMessage{
				Role:    "user",
				Content: "No more tool calls. Return only the JSON verdict now. Accept a low residual risk with requires_configuration or requires_environment when a line you read supports it. " + evidenceContract() + " Use uncertain when a fact you need was not returned by a tool.",
			})
			stepTools = nil
		}
		result, err := llm.Complete(ctx, messages, stepTools)
		if err != nil {
			return modelVerdict{}, tokens, err
		}
		tokens += result.Tokens
		if len(result.ToolCalls) == 0 || step == maxSteps-1 {
			verdict, err := parseVerdict(result.Content)
			return verdict, tokens, err
		}
		messages = append(messages, chatMessage{Role: "assistant", Content: result.Content, ToolCalls: result.ToolCalls})
		for _, call := range result.ToolCalls {
			output := dispatchTool(ctx, roots, runtime, pub, upstream, images, manifests, job, call)
			messages = append(messages, chatMessage{Role: "tool", ToolCallID: call.ID, Content: untrusted("tool "+call.Function.Name, output)})
		}
	}
	return modelVerdict{}, tokens, fmt.Errorf("triage agent exceeded %d steps", maxSteps)
}

type clusterQuerier interface {
	Query(ctx context.Context, cluster, namespace, image string) (string, error)
}

func dispatchTool(ctx context.Context, roots *Roots, runtime clusterQuerier, pub *publicSource, upstream *publicCheckouts, images imageLabeler, manifests manifestSource, job Job, call toolCall) string {
	var args struct {
		Repo      string `json:"repo"`
		Path      string `json:"path"`
		Pattern   string `json:"pattern"`
		StartLine int    `json:"start_line"`
		EndLine   int    `json:"end_line"`
		Cluster   string `json:"cluster"`
		Namespace string `json:"namespace"`
		Image     string `json:"image"`
		ID        string `json:"id"`
		Owner     string `json:"owner"`
		GitRepo   string `json:"git_repo"`
		Ref       string `json:"ref"`
		Query     string `json:"query"`
	}
	if err := json.Unmarshal([]byte(call.Function.Arguments), &args); err != nil {
		return "invalid arguments: " + err.Error()
	}
	if roots == nil {
		roots = &Roots{}
	}
	var (
		out string
		err error
	)
	switch call.Function.Name {
	case "list_dir":
		if args.Repo == imageCheckoutName {
			err = roots.mountImage(ctx)
			if err != nil {
				break
			}
		}
		out, err = roots.ListDir(args.Repo, args.Path)
	case "read_file":
		if args.Repo == imageCheckoutName {
			err = roots.mountImage(ctx)
			if err != nil {
				break
			}
		}
		out, err = roots.ReadFile(args.Repo, args.Path, args.StartLine, args.EndLine)
		if err == nil && pub != nil && roots.public(args.Repo) {
			pub.remember(args.Repo, args.Path, out)
		}
	case "grep":
		if args.Repo == imageCheckoutName {
			out, err = imageGrep(ctx, roots, pub, job, args.Pattern, args.Path)
			break
		}
		if pub != nil && roots.public(args.Repo) {
			out, err = publicGrep(roots, pub, args.Repo, args.Pattern, args.Path)
			break
		}
		out, err = roots.Grep(args.Repo, args.Pattern, args.Path)
	case "cluster_runtime":
		if runtime == nil {
			err = fmt.Errorf("cluster runtime is unavailable")
			break
		}
		out, err = runtime.Query(ctx, args.Cluster, args.Namespace, args.Image)
	case "cve_advisory":
		out, err = pub.Advisory(ctx, args.ID)
	case "public_code":
		out, err = pub.GitHubFile(ctx, args.Owner, args.GitRepo, args.Ref, args.Path, args.StartLine, args.EndLine)
	case "public_search":
		out, err = pub.GitHubSearch(ctx, args.Owner, args.GitRepo, args.Path, args.Query)
	case "image_source":
		out, err = explainImageSource(ctx, images, pub, manifests, job)
	case "dependency_sources":
		out, err = dependencySources(ctx, roots, upstream, pub, job, args.Owner, args.GitRepo, args.Ref)
	case "public_checkout":
		if roots == nil {
			err = fmt.Errorf("public checkout is unavailable")
			break
		}
		out, err = upstream.Checkout(ctx, roots, args.Owner, args.GitRepo, args.Ref, args.Path)
	default:
		err = fmt.Errorf("unknown tool %s", call.Function.Name)
	}
	if err != nil {
		return "error: " + err.Error()
	}
	if strings.TrimSpace(out) == "" {
		return "(no results)"
	}
	return out
}

func publicGrep(roots *Roots, pub *publicSource, repo, pattern, rel string) (string, error) {
	if roots == nil {
		return "", fmt.Errorf("unknown repository %q", repo)
	}
	root, err := roots.checkout(repo)
	if err != nil {
		return "", err
	}
	searched, ok := root.covers(rel)
	if !ok {
		return fmt.Sprintf("path %s is not fully checked out; fetched: %s\n", cleanRel(rel), root.fetchedLabel()), nil
	}
	if strings.TrimSpace(root.SHA) == "" {
		return "", fmt.Errorf("public checkout has no commit")
	}
	rows, err := roots.Grep(repo, pattern, searched)
	if err != nil {
		return "", err
	}
	id := pub.recordGrep(repo, pattern, searched, root.SHA, rows)
	if id == "" {
		return "", fmt.Errorf("grep was not recorded")
	}
	if strings.TrimSpace(rows) != "" {
		pub.rememberGrep(repo, rows)
	}
	return formatGrepResult(id, repo, root.SHA, pattern, searched, rows), nil
}

func formatGrepResult(id, repo, commit, pattern, searched, rows string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "grep_id: %s\nrepo: %s\ncommit: %s\npattern: %s\npath: %s\nmatches: %d\n%s\n", id, repo, commit, pattern, searched, matchCount(rows), cite(strings.TrimSpace(rows) == "", true).line())
	if strings.TrimSpace(rows) != "" {
		b.WriteString(rows)
		if !strings.HasSuffix(rows, "\n") {
			b.WriteByte('\n')
		}
	}
	return b.String()
}

func matchCount(rows string) int {
	if strings.TrimSpace(rows) == "" {
		return 0
	}
	return strings.Count(strings.TrimRight(rows, "\n"), "\n") + 1
}

func parseVerdict(content string) (modelVerdict, error) {
	content = strings.TrimSpace(content)
	content = strings.TrimPrefix(content, "```json")
	content = strings.TrimPrefix(content, "```")
	content = strings.TrimSuffix(content, "```")
	content = strings.TrimSpace(content)
	start := strings.Index(content, "{")
	end := strings.LastIndex(content, "}")
	if start < 0 || end <= start {
		return modelVerdict{}, fmt.Errorf("model output is not JSON")
	}
	var verdict modelVerdict
	if err := json.Unmarshal([]byte(content[start:end+1]), &verdict); err != nil {
		return modelVerdict{}, fmt.Errorf("decode verdict: %w", err)
	}
	verdict.Verdict = strings.ToLower(strings.TrimSpace(verdict.Verdict))
	if verdict.Verdict != "not_affected" && verdict.Verdict != "affected" && verdict.Verdict != "uncertain" {
		return modelVerdict{}, fmt.Errorf("verdict %q is not not_affected, affected, or uncertain", verdict.Verdict)
	}
	if strings.TrimSpace(verdict.Reasoning) == "" {
		return modelVerdict{}, fmt.Errorf("reasoning is required")
	}
	return verdict, nil
}

func toolDefinitions(withRuntime bool) []toolDef {
	object := func(props map[string]any, required ...string) map[string]any {
		return map[string]any{"type": "object", "properties": props, "required": required}
	}
	repo := map[string]any{"type": "string", "description": "Checkout name"}
	pathProp := map[string]any{"type": "string", "description": "Path relative to the checkout root"}
	defs := []struct {
		name, desc string
		params     map[string]any
	}{
		{"list_dir", "List one directory level. Excluded paths are omitted.", object(map[string]any{"repo": repo, "path": pathProp}, "repo")},
		{"grep", "Search file contents with a regular expression. A recorded search returns grep_id and a citable line. repo image searches the scanned image: scripts, source files, and Go binaries. A directory that was not fully fetched is not an empty result.", object(map[string]any{
			"repo": repo, "pattern": map[string]any{"type": "string"}, "path": pathProp,
		}, "repo", "pattern")},
		{"read_file", "Read a line range of one file. Lines are numbered and redacted. At most 200 lines.", object(map[string]any{
			"repo": repo, "path": pathProp,
			"start_line": map[string]any{"type": "integer"},
			"end_line":   map[string]any{"type": "integer"},
		}, "repo", "path")},
		{"image_source", "Resolve the GitHub repository and revision of the image being triaged, from OCI labels, otherwise the upstream SLSA provenance, otherwise a unique commit search.", object(map[string]any{})},
		{"dependency_sources", "Check out the direct npm or pnpm dependents of the vulnerable package at the image commit. Pass the owner, repository, and revision from image_source.", object(map[string]any{
			"owner":    map[string]any{"type": "string", "description": "GitHub owner from image_source"},
			"git_repo": map[string]any{"type": "string", "description": "GitHub repository from image_source"},
			"ref":      map[string]any{"type": "string", "description": "Commit from image_source"},
		}, "owner", "git_repo", "ref")},
		{"public_checkout", "Fetch one directory of a public GitHub repository at a commit, tag, or branch. Then grep and read_file it with repo owner/repo. A short commit prefix is resolved. Submodules are not fetched.", object(map[string]any{
			"owner":    map[string]any{"type": "string", "description": "GitHub owner"},
			"git_repo": map[string]any{"type": "string", "description": "GitHub repository"},
			"ref":      map[string]any{"type": "string", "description": "Commit, tag, or branch. A short commit prefix is accepted."},
			"path":     map[string]any{"type": "string", "description": "Directory prefix to check out, such as apps/studio"},
		}, "owner", "git_repo", "ref", "path")},
		{"cve_advisory", "Fetch a public CVE or GHSA advisory: summary, affected package ranges, severity, and references.", object(map[string]any{
			"id": map[string]any{"type": "string", "description": "CVE-YYYY-NNNN or GHSA-xxxx-xxxx-xxxx"},
		}, "id")},
		{"public_search", "Search the default branch of one public GitHub repository for a symbol. Returns matching paths. Read a path with public_code before citing it.", object(map[string]any{
			"owner":    map[string]any{"type": "string", "description": "GitHub owner"},
			"git_repo": map[string]any{"type": "string", "description": "GitHub repository"},
			"query":    map[string]any{"type": "string", "description": "One symbol, such as SAFE_FOR_TEMPLATES or DOMPurify.sanitize"},
			"path":     map[string]any{"type": "string", "description": "Optional directory prefix inside the repository"},
		}, "owner", "git_repo", "query")},
		{"public_code", "Read a file or list a directory in a public GitHub repository. Content is line-numbered and capped at 200 lines.", object(map[string]any{
			"owner":      map[string]any{"type": "string", "description": "GitHub owner"},
			"git_repo":   map[string]any{"type": "string", "description": "GitHub repository"},
			"ref":        map[string]any{"type": "string", "description": "Branch, tag, or commit. Omit for the default branch."},
			"path":       map[string]any{"type": "string", "description": "File or directory path. Omit to list the repository root."},
			"start_line": map[string]any{"type": "integer"},
			"end_line":   map[string]any{"type": "integer"},
		}, "owner", "git_repo")},
	}
	if withRuntime {
		defs = append(defs, struct {
			name, desc string
			params     map[string]any
		}{
			"cluster_runtime",
			"Read the latest image snapshots reported by suppline cluster agents. Omit filters to list clusters. Pass image, and optionally cluster or namespace, to list running images. Results are capped.",
			object(map[string]any{
				"cluster":   map[string]any{"type": "string", "description": "Cluster name"},
				"namespace": map[string]any{"type": "string", "description": "Namespace"},
				"image":     map[string]any{"type": "string", "description": "Substring of the image reference, tag, or digest"},
			}),
		})
	}
	out := make([]toolDef, 0, len(defs))
	for _, def := range defs {
		item := toolDef{Type: "function"}
		item.Function.Name = def.name
		item.Function.Description = def.desc
		item.Function.Parameters = def.params
		out = append(out, item)
	}
	return out
}
