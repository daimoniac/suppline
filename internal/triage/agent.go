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
	Repo  string `json:"repo"`
	Path  string `json:"path"`
	Line  int    `json:"line"`
	Quote string `json:"quote"`
}

func runAgent(ctx context.Context, llm completer, roots Roots, runtime clusterQuerier, pub *publicSource, allowed []string, job Job, placements string, repoNames []string, existing *types.VEXStatement, maxSteps int) (modelVerdict, int, error) {
	if maxSteps < 1 {
		maxSteps = 1
	}
	if pub == nil {
		pub = newPublicSource()
	}
	messages := []chatMessage{
		{Role: "system", Content: systemPrompt(allowed, runtime != nil)},
		{Role: "user", Content: userPrompt(job, placements, repoNames, existing)},
	}
	tools := toolDefinitions(runtime != nil)
	tokens := 0
	for step := 0; step < maxSteps; step++ {
		stepTools := tools
		if step == maxSteps-1 {
			messages = append(messages, chatMessage{
				Role:    "user",
				Content: "No more tool calls. Return only the JSON verdict now. Use uncertain if the evidence is incomplete.",
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
			output := dispatchTool(ctx, roots, runtime, pub, call)
			messages = append(messages, chatMessage{Role: "tool", ToolCallID: call.ID, Content: untrusted("tool "+call.Function.Name, output)})
		}
	}
	return modelVerdict{}, tokens, fmt.Errorf("triage agent exceeded %d steps", maxSteps)
}

type clusterQuerier interface {
	Query(ctx context.Context, cluster, namespace, image string) (string, error)
}

func dispatchTool(ctx context.Context, roots Roots, runtime clusterQuerier, pub *publicSource, call toolCall) string {
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
	}
	if err := json.Unmarshal([]byte(call.Function.Arguments), &args); err != nil {
		return "invalid arguments: " + err.Error()
	}
	var (
		out string
		err error
	)
	switch call.Function.Name {
	case "list_dir":
		out, err = roots.ListDir(args.Repo, args.Path)
	case "read_file":
		out, err = roots.ReadFile(args.Repo, args.Path, args.StartLine, args.EndLine)
	case "grep":
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
		{"grep", "Search file contents with a regular expression. Returns redacted path:line:text rows.", object(map[string]any{
			"repo": repo, "pattern": map[string]any{"type": "string"}, "path": pathProp,
		}, "repo", "pattern")},
		{"read_file", "Read a line range of one file. Lines are numbered and redacted. At most 200 lines.", object(map[string]any{
			"repo": repo, "path": pathProp,
			"start_line": map[string]any{"type": "integer"},
			"end_line":   map[string]any{"type": "integer"},
		}, "repo", "path")},
		{"cve_advisory", "Fetch a public CVE or GHSA advisory: summary, affected package ranges, severity, and references.", object(map[string]any{
			"id": map[string]any{"type": "string", "description": "CVE-YYYY-NNNN or GHSA-xxxx-xxxx-xxxx"},
		}, "id")},
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
