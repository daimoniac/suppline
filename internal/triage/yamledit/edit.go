// Package yamledit updates one VEX list in a suppline document.
// Comments, anchors, and untouched keys stay in place.
package yamledit

import (
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/daimoniac/suppline/internal/config"
	"github.com/daimoniac/suppline/internal/types"
	"gopkg.in/yaml.v3"
)

// Upsert inserts or replaces one auto-VEX statement on every sync entry whose
// target repository matches. vex is never modified.
func Upsert(document []byte, repository string, statement types.VEXStatement) ([]byte, error) {
	return upsertList(document, repository, "vex-auto", statement)
}

// UpsertMany inserts or replaces several auto-VEX statements in one pass over
// the resulting document. Each statement is applied to the output of the previous.
func UpsertMany(document []byte, repository string, statements []types.VEXStatement) ([]byte, error) {
	out := document
	for _, statement := range statements {
		var err error
		out, err = Upsert(out, repository, statement)
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}

// UpsertManual inserts or replaces one hand-written vex statement.
// vex-auto is never modified.
func UpsertManual(document []byte, repository string, statement types.VEXStatement) ([]byte, error) {
	return upsertList(document, repository, "vex", statement)
}

func upsertList(document []byte, repository, key string, statement types.VEXStatement) ([]byte, error) {
	if strings.TrimSpace(repository) == "" {
		return nil, fmt.Errorf("repository is required")
	}
	if err := types.ValidateVEXStatement(statement); err != nil {
		return nil, err
	}

	return spliceMatching(document, repository, key, func(text string, entry matchedEntry, delta int) (string, error) {
		return spliceEntry(text, entry, key, statement, delta)
	})
}

// spliceMatching runs splice on every sync entry whose target repository is
// repository, last entry first so earlier line numbers stay valid. key must
// be a list or missing on each matched entry.
func spliceMatching(document []byte, repository, key string, splice func(text string, entry matchedEntry, delta int) (string, error)) ([]byte, error) {
	return spliceMatchingIn(document, repository, key, nil, splice)
}

// spliceMatchingIn is spliceMatching limited to the named top-level lists.
// No names means every list.
func spliceMatchingIn(document []byte, repository, key string, listKeys []string, splice func(text string, entry matchedEntry, delta int) (string, error)) ([]byte, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(document, &doc); err != nil {
		return nil, fmt.Errorf("parse suppline yaml: %w", err)
	}
	if len(doc.Content) == 0 || doc.Content[0].Kind != yaml.MappingNode {
		return nil, fmt.Errorf("suppline document must be a mapping")
	}
	root := doc.Content[0]
	lists := repositoryLists(root)
	if len(lists) == 0 {
		return nil, errNoRepositoryLists
	}

	text := string(document)
	matched := make([]matchedEntry, 0, 1)
	for _, list := range lists {
		if len(listKeys) > 0 && !slices.Contains(listKeys, list.key) {
			continue
		}
		delta := sequenceDelta(text, root, list.key, list.seq)
		for i, entry := range list.seq.Content {
			if entry.Kind != yaml.MappingNode {
				continue
			}
			target, err := targetRepository(list.entryTarget(entry))
			if err != nil {
				return nil, err
			}
			if target != repository {
				continue
			}
			seq := mappingChild(entry, key)
			if seq != nil && !isVEXList(seq) {
				return nil, fmt.Errorf("%s must be a list", key)
			}
			matched = append(matched, matchedEntry{node: entry, limit: entryLimit(root, list.seq, i, entry), delta: delta})
		}
	}
	if len(matched) == 0 {
		return nil, fmt.Errorf("no sync or in-place entry for repository %s", repository)
	}
	sort.Slice(matched, func(i, j int) bool { return matched[i].node.Line > matched[j].node.Line })
	for _, entry := range matched {
		var err error
		text, err = splice(text, entry, entry.delta)
		if err != nil {
			return nil, err
		}
	}
	return []byte(text), nil
}

// errNoRepositoryLists means the document has neither a sync nor an in-place list.
var errNoRepositoryLists = fmt.Errorf("suppline document has no sync or in-place list")

// repositoryList is one top-level list of per-repository entries: sync,
// keyed by target and type, or in-place, keyed by repository.
type repositoryList struct {
	key string
	seq *yaml.Node
}

func repositoryLists(root *yaml.Node) []repositoryList {
	var lists []repositoryList
	for _, key := range []string{"sync", "in-place"} {
		if seq := mappingChild(root, key); seq != nil && seq.Kind == yaml.SequenceNode {
			lists = append(lists, repositoryList{key: key, seq: seq})
		}
	}
	return lists
}

// entryTarget returns an entry's target and type as config.SyncTargetMatches
// expects them. An in-place entry names its repository and has no type.
func (l repositoryList) entryTarget(entry *yaml.Node) (string, string) {
	if l.key == "in-place" {
		return mappingScalar(entry, "repository"), ""
	}
	return mappingScalar(entry, "target"), mappingScalar(entry, "type")
}

// isVEXList reports a sequence, or a null left after every entry was removed.
// A cleared list is often left as "vex-auto:" or "vex-auto: null".
func isVEXList(node *yaml.Node) bool {
	if node == nil {
		return false
	}
	if node.Kind == yaml.SequenceNode {
		return true
	}
	return node.Kind == yaml.ScalarNode && node.ShortTag() == "!!null"
}

func mappingChild(mapping *yaml.Node, key string) *yaml.Node {
	if mapping == nil || mapping.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(mapping.Content); i += 2 {
		if mapping.Content[i].Value == key {
			return mapping.Content[i+1]
		}
	}
	return nil
}

func mappingKey(mapping *yaml.Node, key string) *yaml.Node {
	if mapping == nil || mapping.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(mapping.Content); i += 2 {
		if mapping.Content[i].Value == key {
			return mapping.Content[i]
		}
	}
	return nil
}

func mappingScalar(mapping *yaml.Node, key string) string {
	child := mappingChild(mapping, key)
	if child == nil || child.Kind != yaml.ScalarNode {
		return ""
	}
	return child.Value
}

func targetRepository(target, kind string) (string, error) {
	expanded, err := config.ExpandEnvTemplate(target)
	if err != nil {
		return "", fmt.Errorf("expand sync target: %w", err)
	}
	if kind == "image" {
		if index := strings.LastIndex(expanded, ":"); index != -1 {
			return expanded[:index], nil
		}
	}
	return expanded, nil
}
