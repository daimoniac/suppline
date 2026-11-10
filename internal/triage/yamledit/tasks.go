package yamledit

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/daimoniac/suppline/internal/config"
	"gopkg.in/yaml.v3"
)

// ErrNoMatch means the edit did not touch any sync entry or VEX statement.
var ErrNoMatch = errors.New("no matching config entries")

// SemverRangeUpdate replaces tags.semverRange on sync entries for one target.
type SemverRangeUpdate struct {
	Target string
	Ranges []string
}

type spanEdit struct {
	start int
	end   int
	block string
}

// SetSemverRanges replaces tags.semverRange on every sync entry whose target
// matches an update. Other keys, including tags.deny, stay in place.
func SetSemverRanges(document []byte, updates []SemverRangeUpdate) ([]byte, int, error) {
	if len(updates) == 0 {
		return nil, 0, fmt.Errorf("no semver updates")
	}
	for _, update := range updates {
		if strings.TrimSpace(update.Target) == "" || len(update.Ranges) == 0 {
			return nil, 0, fmt.Errorf("each semver update needs a target and at least one range")
		}
		for _, rang := range update.Ranges {
			if strings.TrimSpace(rang) == "" {
				return nil, 0, fmt.Errorf("semver range must not be empty")
			}
		}
	}
	root, lines, err := parseDocument(document)
	if err != nil {
		return nil, 0, err
	}
	sync := mappingChild(root, "sync")
	if sync == nil || sync.Kind != yaml.SequenceNode {
		return nil, 0, fmt.Errorf("suppline document has no sync list")
	}
	var edits []spanEdit
	for i, entry := range sync.Content {
		if entry.Kind != yaml.MappingNode {
			continue
		}
		ranges, ok, err := lastMatchingRanges(mappingScalar(entry, "target"), mappingScalar(entry, "type"), updates)
		if err != nil {
			return nil, 0, err
		}
		if !ok {
			continue
		}
		tags := mappingChild(entry, "tags")
		if tags == nil || tags.Kind != yaml.MappingNode {
			return nil, 0, fmt.Errorf("sync entry %s has no tags block", mappingScalar(entry, "target"))
		}
		key := mappingKey(tags, "semverRange")
		seq := mappingChild(tags, "semverRange")
		if key == nil || key.Line < 1 || seq == nil || seq.Kind != yaml.SequenceNode {
			return nil, 0, fmt.Errorf("sync entry %s has no tags.semverRange list", mappingScalar(entry, "target"))
		}
		bound := entryLimit(root, sync, i, entry)
		limit := boundedLimit(nextKeyLine(tags, key.Line, bound), bound)
		edits = append(edits, spanEdit{
			start: key.Line,
			end:   nodeEnd(lines, key.Line, seq, limit),
			block: formatSemverRange(leadingSpaces(lineAt(lines, key.Line)), ranges),
		})
	}
	text, err := applySpans(lines, edits)
	if err != nil {
		return nil, 0, err
	}
	return []byte(text), len(edits), nil
}

// RemoveSyncTargets deletes sync entries whose target matches one of targets.
func RemoveSyncTargets(document []byte, targets []string) ([]byte, int, error) {
	wanted, err := cleanList(targets, "sync target")
	if err != nil {
		return nil, 0, err
	}
	root, lines, err := parseDocument(document)
	if err != nil {
		return nil, 0, err
	}
	sync := mappingChild(root, "sync")
	if sync == nil || sync.Kind != yaml.SequenceNode {
		return nil, 0, fmt.Errorf("suppline document has no sync list")
	}
	var edits []spanEdit
	for i, entry := range sync.Content {
		if entry.Kind != yaml.MappingNode || entry.Line < 1 {
			continue
		}
		matched, err := matchesAnyTarget(mappingScalar(entry, "target"), mappingScalar(entry, "type"), wanted)
		if err != nil {
			return nil, 0, err
		}
		if !matched {
			continue
		}
		limit := entryLimit(root, sync, i, entry)
		edits = append(edits, spanEdit{
			start: entry.Line,
			end:   entryLastLine(lines, entry.Line, limit),
		})
	}
	text, err := applySpans(lines, edits)
	if err != nil {
		return nil, 0, err
	}
	return []byte(text), len(edits), nil
}

// RemoveVEXStatements deletes x-vex and x-vex-auto items with the given ids
// from defaults and every sync entry.
func RemoveVEXStatements(document []byte, ids []string) ([]byte, int, error) {
	wanted, err := cleanList(ids, "VEX id")
	if err != nil {
		return nil, 0, err
	}
	root, lines, err := parseDocument(document)
	if err != nil {
		return nil, 0, err
	}
	var edits []spanEdit
	if defaults := mappingChild(root, "defaults"); defaults != nil && defaults.Kind == yaml.MappingNode {
		limit := nextRootLine(root, defaults.Line)
		edits = append(edits, vexSpans(lines, defaults, wanted, limit)...)
	}
	if sync := mappingChild(root, "sync"); sync != nil && sync.Kind == yaml.SequenceNode {
		for i, entry := range sync.Content {
			if entry.Kind != yaml.MappingNode {
				continue
			}
			edits = append(edits, vexSpans(lines, entry, wanted, entryLimit(root, sync, i, entry))...)
		}
	}
	text, err := applySpans(lines, edits)
	if err != nil {
		return nil, 0, err
	}
	return []byte(text), len(edits), nil
}

// SyncVEXRef names one statement stored on the sync entries of a repository.
// Source is the key it is written under: "x-vex" or "x-vex-auto".
type SyncVEXRef struct {
	Repository string
	ID         string
	Source     string
}

// RemoveSyncVEXStatements deletes the referenced statements from sync entries
// whose repository matches. Each ref only touches the list named by its
// Source, so a statement with the same id under the other key stays in place.
// defaults and other repositories are never changed.
func RemoveSyncVEXStatements(document []byte, refs []SyncVEXRef) ([]byte, int, error) {
	if len(refs) == 0 {
		return nil, 0, fmt.Errorf("no VEX statements")
	}
	wanted := make(map[string]map[string][]string)
	for _, ref := range refs {
		repository := strings.TrimSpace(ref.Repository)
		id := strings.TrimSpace(ref.ID)
		if repository == "" || id == "" {
			return nil, 0, fmt.Errorf("VEX repository and id must not be empty")
		}
		if ref.Source != "x-vex" && ref.Source != "x-vex-auto" {
			return nil, 0, fmt.Errorf("unknown VEX source %q", ref.Source)
		}
		if wanted[repository] == nil {
			wanted[repository] = make(map[string][]string)
		}
		wanted[repository][ref.Source] = append(wanted[repository][ref.Source], id)
	}
	root, lines, err := parseDocument(document)
	if err != nil {
		return nil, 0, err
	}
	sync := mappingChild(root, "sync")
	if sync == nil || sync.Kind != yaml.SequenceNode {
		return nil, 0, fmt.Errorf("suppline document has no sync list")
	}
	var edits []spanEdit
	for i, entry := range sync.Content {
		if entry.Kind != yaml.MappingNode {
			continue
		}
		byKey, err := matchedVEXKeys(mappingScalar(entry, "target"), mappingScalar(entry, "type"), wanted)
		if err != nil {
			return nil, 0, err
		}
		if len(byKey) == 0 {
			continue
		}
		edits = append(edits, vexSpansByKey(lines, entry, byKey, entryLimit(root, sync, i, entry))...)
	}
	text, err := applySpans(lines, edits)
	if err != nil {
		return nil, 0, err
	}
	return []byte(text), len(edits), nil
}

// matchedVEXKeys returns the statement ids to delete from one sync entry.
// Targets are matched after template expansion, and image targets match on the
// repository with the tag removed.
func matchedVEXKeys(target, kind string, wanted map[string]map[string][]string) (map[string][]string, error) {
	matched := make(map[string][]string)
	for repository, byKey := range wanted {
		ok, err := config.SyncTargetMatches(target, kind, repository)
		if err != nil {
			return nil, err
		}
		if !ok {
			continue
		}
		for key, ids := range byKey {
			matched[key] = append(matched[key], ids...)
		}
	}
	return matched, nil
}

func lastMatchingRanges(target, kind string, updates []SemverRangeUpdate) ([]string, bool, error) {
	var ranges []string
	found := false
	for _, update := range updates {
		ok, err := config.SyncTargetMatches(target, kind, update.Target)
		if err != nil {
			return nil, false, err
		}
		if !ok {
			continue
		}
		ranges = append([]string(nil), update.Ranges...)
		found = true
	}
	return ranges, found, nil
}

func matchesAnyTarget(target, kind string, wanted []string) (bool, error) {
	for _, item := range wanted {
		ok, err := config.SyncTargetMatches(target, kind, item)
		if err != nil {
			return false, err
		}
		if ok {
			return true, nil
		}
	}
	return false, nil
}

func vexSpans(lines []string, mapping *yaml.Node, ids []string, limit int) []spanEdit {
	return vexSpansByKey(lines, mapping, map[string][]string{"x-vex": ids, "x-vex-auto": ids}, limit)
}

// vexSpansByKey finds items to delete under each VEX list key, using the ids
// wanted for that key only.
func vexSpansByKey(lines []string, mapping *yaml.Node, idsByKey map[string][]string, limit int) []spanEdit {
	var edits []spanEdit
	for _, key := range []string{"x-vex", "x-vex-auto"} {
		ids := idsByKey[key]
		if len(ids) == 0 {
			continue
		}
		seq := mappingChild(mapping, key)
		keyNode := mappingKey(mapping, key)
		if seq == nil || seq.Kind != yaml.SequenceNode || keyNode == nil {
			continue
		}
		listLimit := boundedLimit(nextKeyLine(mapping, keyNode.Line, limit), limit)
		for i, item := range seq.Content {
			if item.Kind != yaml.MappingNode || item.Line < 1 {
				continue
			}
			if !idWanted(mappingScalar(item, "id"), ids) {
				continue
			}
			next := listLimit
			if i+1 < len(seq.Content) && seq.Content[i+1].Line > item.Line {
				next = seq.Content[i+1].Line
			}
			edits = append(edits, spanEdit{
				start: item.Line,
				end:   entryLastLine(lines, item.Line, next),
			})
		}
	}
	return edits
}

func idWanted(id string, ids []string) bool {
	id = strings.TrimSpace(id)
	for _, wanted := range ids {
		if id == wanted {
			return true
		}
	}
	return false
}

func cleanList(values []string, label string) ([]string, error) {
	if len(values) == 0 {
		return nil, fmt.Errorf("no %s", label)
	}
	out := make([]string, 0, len(values))
	seen := map[string]struct{}{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			return nil, fmt.Errorf("%s must not be empty", label)
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out, nil
}

func parseDocument(document []byte) (*yaml.Node, []string, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(document, &doc); err != nil {
		return nil, nil, fmt.Errorf("parse suppline yaml: %w", err)
	}
	if len(doc.Content) == 0 || doc.Content[0].Kind != yaml.MappingNode {
		return nil, nil, fmt.Errorf("suppline document must be a mapping")
	}
	return doc.Content[0], strings.Split(string(document), "\n"), nil
}

func boundedLimit(next, fallback int) int {
	if next > 0 {
		return next
	}
	return fallback
}

func entryLimit(root, sync *yaml.Node, index int, entry *yaml.Node) int {
	limit := nextRootLine(root, entry.Line)
	for j := index + 1; j < len(sync.Content); j++ {
		if sync.Content[j].Line > entry.Line {
			return sync.Content[j].Line
		}
	}
	return limit
}

func nodeEnd(lines []string, keyLine int, seq *yaml.Node, limit int) int {
	end := keyLine
	for _, item := range seq.Content {
		if item.Line > end {
			end = entryLastLine(lines, item.Line, limit)
		}
	}
	if end < keyLine {
		return keyLine
	}
	return end
}

func formatSemverRange(indent string, ranges []string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%ssemverRange:\n", indent)
	for _, rang := range ranges {
		fmt.Fprintf(&b, "%s  - %s\n", indent, yamlScalar(rang, ""))
	}
	return strings.TrimRight(b.String(), "\n")
}

func applySpans(lines []string, edits []spanEdit) (string, error) {
	if len(edits) == 0 {
		return "", ErrNoMatch
	}
	sort.Slice(edits, func(i, j int) bool { return edits[i].start > edits[j].start })
	for i, edit := range edits {
		if edit.start < 1 || edit.end < edit.start {
			return "", fmt.Errorf("invalid config edit span")
		}
		if i > 0 && edit.end >= edits[i-1].start {
			return "", fmt.Errorf("overlapping config edits")
		}
		if edit.block == "" {
			lines = deleteLines(lines, edit.start, edit.end)
			continue
		}
		lines = replaceLines(lines, edit.start, edit.end, edit.block)
	}
	return joinLines(lines), nil
}

func deleteLines(lines []string, start, end int) []string {
	if start < 1 {
		start = 1
	}
	if end > len(lines) {
		end = len(lines)
	}
	if end < start {
		return lines
	}
	out := append([]string{}, lines[:start-1]...)
	return append(out, lines[end:]...)
}
