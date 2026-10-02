package cliproxy

import (
	"github.com/router-for-me/CLIProxyAPI/v8/internal/grouping"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/config"
	"gopkg.in/yaml.v3"
)

func prepareGroupingActivationConfig(path string, before []byte, cfg *config.Config) (*groupingFileChange, error) {
	var doc yaml.Node
	if cfg == nil || yaml.Unmarshal(before, &doc) != nil || len(doc.Content) != 1 || doc.Content[0].Kind != yaml.MappingNode {
		return nil, grouping.ErrInvalid
	}
	settings := groupingDocumentField(doc.Content[0], "grouping", yaml.MappingNode, "!!map")
	if err := isolateGroupingActivationSettings(&doc, settings); err != nil {
		return nil, err
	}
	if settings.Kind == yaml.ScalarNode && settings.Tag == "!!null" {
		settings.Kind, settings.Tag, settings.Value, settings.Style = yaml.MappingNode, "!!map", "", 0
	}
	if settings.Kind != yaml.MappingNode {
		return nil, grouping.ErrInvalid
	}
	enabled := groupingDocumentField(settings, "enabled", yaml.ScalarNode, "!!bool")
	if err := enabled.Encode(cfg.Grouping.Enabled); err != nil {
		return nil, grouping.ErrInvalid
	}
	after, err := yaml.Marshal(&doc)
	if err != nil {
		return nil, grouping.ErrInvalid
	}
	return &groupingFileChange{path: path, before: before, after: after}, nil
}

func isolateGroupingActivationSettings(doc, settings *yaml.Node) error {
	affected := make(map[*yaml.Node]bool)
	collectGroupingActivationNodes(settings, affected)
	// Freeze references to the old grouping subtree before removing its anchors.
	// Unrelated aliases and opaque configuration retain their original nodes.
	if err := detachGroupingActivationReferences(doc, affected); err != nil {
		return err
	}
	isolated, err := cloneGroupingActivationValue(settings, make(map[*yaml.Node]bool))
	if err != nil {
		return err
	}
	*settings = *isolated
	return nil
}

func collectGroupingActivationNodes(node *yaml.Node, nodes map[*yaml.Node]bool) {
	nodes[node] = true
	for _, child := range node.Content {
		collectGroupingActivationNodes(child, nodes)
	}
}

func detachGroupingActivationReferences(node *yaml.Node, affected map[*yaml.Node]bool) error {
	if node.Kind == yaml.AliasNode && affected[node.Alias] {
		isolated, err := cloneGroupingActivationValue(node, make(map[*yaml.Node]bool))
		if err != nil {
			return err
		}
		*node = *isolated
		return nil
	}
	for _, child := range node.Content {
		if err := detachGroupingActivationReferences(child, affected); err != nil {
			return err
		}
	}
	return nil
}

func cloneGroupingActivationValue(node *yaml.Node, visiting map[*yaml.Node]bool) (*yaml.Node, error) {
	if node == nil || visiting[node] {
		return nil, grouping.ErrInvalid
	}
	visiting[node] = true
	defer delete(visiting, node)
	if node.Kind == yaml.AliasNode {
		cloned, err := cloneGroupingActivationValue(node.Alias, visiting)
		if err != nil {
			return nil, err
		}
		if node.HeadComment != "" {
			cloned.HeadComment = node.HeadComment
		}
		if node.LineComment != "" {
			cloned.LineComment = node.LineComment
		}
		if node.FootComment != "" {
			cloned.FootComment = node.FootComment
		}
		return cloned, nil
	}
	cloned := *node
	cloned.Anchor, cloned.Alias = "", nil
	cloned.Content = make([]*yaml.Node, len(node.Content))
	for index, child := range node.Content {
		copy, err := cloneGroupingActivationValue(child, visiting)
		if err != nil {
			return nil, err
		}
		cloned.Content[index] = copy
	}
	return &cloned, nil
}

func groupingDocumentField(parent *yaml.Node, name string, kind yaml.Kind, tag string) *yaml.Node {
	for i := 0; i+1 < len(parent.Content); i += 2 {
		if parent.Content[i].Value == name {
			return parent.Content[i+1]
		}
	}
	value := &yaml.Node{Kind: kind, Tag: tag}
	parent.Content = append(parent.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: name}, value)
	return value
}
