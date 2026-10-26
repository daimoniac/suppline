package yamledit

import (
	"fmt"
	"strings"
	"time"

	"github.com/daimoniac/suppline/internal/types"
	"gopkg.in/yaml.v3"
)

type matchedEntry struct {
	node  *yaml.Node
	limit int
}

func sequenceDelta(text string, root, sync *yaml.Node) int {
	lines := strings.Split(text, "\n")
	if len(sync.Content) == 0 || sync.Content[0].Line < 1 {
		return 2
	}
	dash := strings.Index(lineAt(lines, sync.Content[0].Line), "-")
	if dash < 0 {
		return 2
	}
	keyIndent := 0
	if key := mappingKey(root, "sync"); key != nil {
		keyIndent = len(leadingSpaces(lineAt(lines, key.Line)))
	}
	if dash < keyIndent {
		return 0
	}
	return dash - keyIndent
}

func spliceEntry(text string, entry matchedEntry, key string, statement types.VEXStatement, delta int) (string, error) {
	lines := strings.Split(text, "\n")
	keyIndent := entryKeyIndent(lines, entry.node)
	seq := mappingChild(entry.node, key)
	dashPrefix := keyIndent + strings.Repeat(" ", delta)
	if seq != nil && len(seq.Content) > 0 {
		if prefix, ok := dashPrefixOf(lineAt(lines, seq.Content[0].Line)); ok {
			dashPrefix = prefix
		}
	}
	block := formatStatement(dashPrefix, statement)
	if seq == nil || len(seq.Content) == 0 {
		at := entryLastLine(lines, entry.node.Line, entry.limit)
		if seq != nil {
			if keyNode := mappingKey(entry.node, key); keyNode != nil && keyNode.Line > 0 {
				lines[keyNode.Line-1] = keyIndent + key + ":"
				at = keyNode.Line
			}
		} else {
			block = keyIndent + key + ":\n" + block
		}
		return joinLines(insertAfter(lines, at, block)), nil
	}
	for i, item := range seq.Content {
		if item.Kind != yaml.MappingNode || mappingScalar(item, "id") != statement.ID {
			continue
		}
		next := entry.limit
		if i+1 < len(seq.Content) && seq.Content[i+1].Line > item.Line {
			next = seq.Content[i+1].Line
		} else if keyLine := nextKeyLine(entry.node, item.Line, entry.limit); keyLine > 0 {
			next = keyLine
		}
		end := entryLastLine(lines, item.Line, next)
		return joinLines(replaceLines(lines, item.Line, end, block)), nil
	}
	last := seq.Content[len(seq.Content)-1]
	at := entryLastLine(lines, last.Line, nextBoundary(entry, last.Line))
	return joinLines(insertAfter(lines, at, block)), nil
}

func nextRootLine(root *yaml.Node, after int) int {
	best := 0
	for i := 0; i+1 < len(root.Content); i += 2 {
		line := root.Content[i].Line
		if line <= after {
			continue
		}
		if best == 0 || line < best {
			best = line
		}
	}
	return best
}

func nextBoundary(entry matchedEntry, after int) int {
	if keyLine := nextKeyLine(entry.node, after, entry.limit); keyLine > 0 {
		return keyLine
	}
	return entry.limit
}

func nextKeyLine(entry *yaml.Node, after, limit int) int {
	best := 0
	for i := 0; i+1 < len(entry.Content); i += 2 {
		line := entry.Content[i].Line
		if line <= after {
			continue
		}
		if limit > 0 && line >= limit {
			continue
		}
		if best == 0 || line < best {
			best = line
		}
	}
	return best
}

func entryKeyIndent(lines []string, entry *yaml.Node) string {
	fallback := ""
	for i := 0; i+1 < len(entry.Content); i += 2 {
		line := lineAt(lines, entry.Content[i].Line)
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		indent := leadingSpaces(line)
		if strings.HasPrefix(trimmed, "-") {
			fallback = indent + "  "
			continue
		}
		return indent
	}
	if fallback != "" {
		return fallback
	}
	return "  "
}

func entryLastLine(lines []string, start, limit int) int {
	end := len(lines)
	if limit > 0 && limit-1 < end {
		end = limit - 1
	} else if end > 0 && lines[end-1] == "" {
		end--
	}
	for end > start && strings.TrimSpace(lines[end-1]) == "" {
		end--
	}
	if end < start {
		return start
	}
	return end
}

func formatStatement(dashPrefix string, statement types.VEXStatement) string {
	nested := dashPrefix + "  "
	var b strings.Builder
	fmt.Fprintf(&b, "%s- id: %s\n", dashPrefix, yamlScalar(statement.ID, ""))
	fmt.Fprintf(&b, "%sstate: %s\n", nested, yamlScalar(string(statement.State), ""))
	if statement.Justification != "" {
		fmt.Fprintf(&b, "%sjustification: %s\n", nested, yamlScalar(string(statement.Justification), ""))
	}
	if statement.Detail != "" {
		fmt.Fprintf(&b, "%sdetail: %s\n", nested, yamlScalar(statement.Detail, nested+"  "))
	}
	if statement.ExpiresAt != nil {
		when := time.Unix(*statement.ExpiresAt, 0).UTC().Format(time.RFC3339)
		fmt.Fprintf(&b, "%sexpires_at: %s\n", nested, yamlScalar(when, ""))
	}
	return b.String()
}

func yamlScalar(value, continuation string) string {
	raw, err := yaml.Marshal(value)
	if err != nil {
		return strconvQuote(value)
	}
	text := strings.TrimRight(string(raw), "\n")
	if !strings.Contains(text, "\n") {
		return text
	}
	lines := strings.Split(text, "\n")
	var b strings.Builder
	b.WriteString(lines[0])
	for _, line := range lines[1:] {
		b.WriteByte('\n')
		b.WriteString(continuation)
		b.WriteString(strings.TrimLeft(line, " "))
	}
	return b.String()
}

func strconvQuote(value string) string {
	return fmt.Sprintf("%q", value)
}

func dashPrefixOf(line string) (string, bool) {
	index := strings.Index(line, "-")
	if index < 0 {
		return "", false
	}
	return line[:index], true
}

func leadingSpaces(line string) string {
	index := 0
	for index < len(line) && line[index] == ' ' {
		index++
	}
	return line[:index]
}

func lineAt(lines []string, line int) string {
	if line < 1 || line > len(lines) {
		return ""
	}
	return lines[line-1]
}

func replaceLines(lines []string, start, end int, block string) []string {
	if start < 1 {
		start = 1
	}
	if end > len(lines) {
		end = len(lines)
	}
	if end < start {
		end = start
	}
	repl := strings.Split(strings.TrimRight(block, "\n"), "\n")
	out := append([]string{}, lines[:start-1]...)
	out = append(out, repl...)
	return append(out, lines[end:]...)
}

func insertAfter(lines []string, after int, block string) []string {
	if after < 0 {
		after = 0
	}
	if after > len(lines) {
		after = len(lines)
	}
	repl := strings.Split(strings.TrimRight(block, "\n"), "\n")
	out := append([]string{}, lines[:after]...)
	out = append(out, repl...)
	return append(out, lines[after:]...)
}

func joinLines(lines []string) string {
	return strings.Join(lines, "\n")
}
