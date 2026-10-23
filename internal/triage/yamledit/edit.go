// Package yamledit updates one VEX list in a suppline document.
// Comments, anchors, and untouched keys stay in place.
package yamledit

import (
	"bytes"
	"fmt"
	"strings"
	"time"

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

	matched := 0
	for _, entry := range sync.Content {
		if entry.Kind != yaml.MappingNode {
			continue
		}
		if targetRepository(mappingScalar(entry, "target"), mappingScalar(entry, "type")) != repository {
			continue
		}
		if err := upsertEntry(entry, key, statement); err != nil {
			return nil, err
		}
		matched++
	}
	if matched == 0 {
		return nil, fmt.Errorf("no sync entry for repository %s", repository)
	}

	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(&doc); err != nil {
		return nil, fmt.Errorf("encode suppline yaml: %w", err)
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func upsertEntry(entry *yaml.Node, key string, statement types.VEXStatement) error {
	seq := mappingChild(entry, key)
	if seq == nil {
		entry.Content = append(entry.Content,
			&yaml.Node{Kind: yaml.ScalarNode, Value: key, Tag: "!!str"},
			&yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"},
		)
		seq = mappingChild(entry, key)
	}
	if seq.Kind != yaml.SequenceNode {
		return fmt.Errorf("%s must be a list", key)
	}
	item := statementNode(statement)
	for i, existing := range seq.Content {
		if existing.Kind == yaml.MappingNode && mappingScalar(existing, "id") == statement.ID {
			seq.Content[i] = item
			return nil
		}
	}
	seq.Content = append(seq.Content, item)
	return nil
}

func statementNode(statement types.VEXStatement) *yaml.Node {
	content := []*yaml.Node{
		scalar("id"), scalar(statement.ID),
		scalar("state"), scalar(string(statement.State)),
	}
	if statement.Justification != "" {
		content = append(content, scalar("justification"), scalar(string(statement.Justification)))
	}
	if statement.Detail != "" {
		detail := scalar(statement.Detail)
		if strings.Contains(statement.Detail, "\n") {
			detail.Style = yaml.LiteralStyle
		}
		content = append(content, scalar("detail"), detail)
	}
	if statement.ExpiresAt != nil {
		content = append(content,
			scalar("expires_at"),
			scalar(time.Unix(*statement.ExpiresAt, 0).UTC().Format(time.RFC3339)),
		)
	}
	return &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map", Content: content}
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

func mappingScalar(mapping *yaml.Node, key string) string {
	child := mappingChild(mapping, key)
	if child == nil || child.Kind != yaml.ScalarNode {
		return ""
	}
	return child.Value
}

func scalar(value string) *yaml.Node {
	return &yaml.Node{Kind: yaml.ScalarNode, Value: value, Tag: "!!str"}
}

func targetRepository(target, kind string) string {
	if kind == "image" {
		if index := strings.LastIndex(target, ":"); index != -1 {
			return target[:index]
		}
	}
	return target
}
