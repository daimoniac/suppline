// Package yamledit updates one VEX list in a suppline document.
// Comments, anchors, and untouched keys stay in place.
package yamledit

import (
	"fmt"
	"sort"
	"strings"

	"github.com/daimoniac/suppline/internal/config"
	"github.com/daimoniac/suppline/internal/types"
	"gopkg.in/yaml.v3"
)

// Upsert inserts or replaces one auto-VEX statement on every sync entry whose
// target repository matches. x-vex is never modified.
func Upsert(document []byte, repository string, statement types.VEXStatement) ([]byte, error) {
	return upsertList(document, repository, "x-vex-auto", statement)
}

// UpsertManual inserts or replaces one hand-written x-vex statement.
// x-vex-auto is never modified.
func UpsertManual(document []byte, repository string, statement types.VEXStatement) ([]byte, error) {
	return upsertList(document, repository, "x-vex", statement)
}

func upsertList(document []byte, repository, key string, statement types.VEXStatement) ([]byte, error) {
	if strings.TrimSpace(repository) == "" {
		return nil, fmt.Errorf("repository is required")
	}
	if err := types.ValidateVEXStatement(statement); err != nil {
		return nil, err
	}

	var doc yaml.Node
	if err := yaml.Unmarshal(document, &doc); err != nil {
		return nil, fmt.Errorf("parse suppline yaml: %w", err)
	}
	if len(doc.Content) == 0 || doc.Content[0].Kind != yaml.MappingNode {
		return nil, fmt.Errorf("suppline document must be a mapping")
	}
	root := doc.Content[0]
	sync := mappingChild(root, "sync")
	if sync == nil || sync.Kind != yaml.SequenceNode {
		return nil, fmt.Errorf("suppline document has no sync list")
	}

	matched := make([]matchedEntry, 0, 1)
	for i, entry := range sync.Content {
		if entry.Kind != yaml.MappingNode {
			continue
		}
		target, err := targetRepository(mappingScalar(entry, "target"), mappingScalar(entry, "type"))
		if err != nil {
			return nil, err
		}
		if target != repository {
			continue
		}
		seq := mappingChild(entry, key)
		if seq != nil && seq.Kind != yaml.SequenceNode {
			return nil, fmt.Errorf("%s must be a list", key)
		}
		limit := nextRootLine(root, entry.Line)
		for j := i + 1; j < len(sync.Content); j++ {
			if sync.Content[j].Line > entry.Line {
				limit = sync.Content[j].Line
				break
			}
		}
		matched = append(matched, matchedEntry{node: entry, limit: limit})
	}
	if len(matched) == 0 {
		return nil, fmt.Errorf("no sync entry for repository %s", repository)
	}
	sort.Slice(matched, func(i, j int) bool { return matched[i].node.Line > matched[j].node.Line })
	text := string(document)
	delta := sequenceDelta(text, root, sync)
	for _, entry := range matched {
		var err error
		text, err = spliceEntry(text, entry, key, statement, delta)
		if err != nil {
			return nil, err
		}
	}
	return []byte(text), nil
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
