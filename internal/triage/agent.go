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

func runAgent(ctx context.Context, llm completer, roots Roots, allowed []string, job Job, placements string, repoNames []string, existing *types.VEXStatement, maxSteps int) (modelVerdict, int, error) {
	if maxSteps < 1 {
		maxSteps = 1
	}
	messages := []chatMessage{
		{Role: "system", Content: systemPrompt(allowed)},
		{Role: "user", Content: userPrompt(job, placements, repoNames, existing)},
	}
	tools := toolDefinitions()
	tokens := 0
	for step := 0; step < maxSteps; step++ {
		result, err := llm.Complete(ctx, messages, tools)
		if err != nil {
			return modelVerdict{}, tokens, err
		}
		tokens += result.Tokens
		if len(result.ToolCalls) == 0 {
			verdict, err := parseVerdict(result.Content)
			return verdict, tokens, err
		}
		messages = append(messages, chatMessage{Role: "assistant", Content: result.Content, ToolCalls: result.ToolCalls})
		for _, call := range result.ToolCalls {
			output := dispatchTool(roots, call)
			messages = append(messages, chatMessage{Role: "tool", ToolCallID: call.ID, Content: untrusted("tool "+call.Function.Name, output)})
		}
	}
	return modelVerdict{}, tokens, fmt.Errorf("triage agent exceeded %d steps", maxSteps)
}

func dispatchTool(roots Roots, call toolCall) string {
	var args struct {
		Repo      string `json:"repo"`
		Path      string `json:"path"`
		Pattern   string `json:"pattern"`
		StartLine int    `json:"start_line"`
		EndLine   int    `json:"end_line"`
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

func toolDefinitions() []toolDef {
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
