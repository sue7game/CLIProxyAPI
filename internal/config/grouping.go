package config

import (
	"fmt"
	"strings"

	"github.com/google/uuid"
)

// GroupingConfig enables local access groups without changing legacy defaults.
type GroupingConfig struct {
	Enabled   bool   `yaml:"enabled" json:"enabled"`
	StorePath string `yaml:"store-path,omitempty" json:"store-path,omitempty"`
}

// ValidateGroupingMode rejects Home deployments until both ends enforce the group
// policy protocol. It does not change either mode or validate credential identities.
func ValidateGroupingMode(cfg *Config) error {
	if cfg == nil {
		return fmt.Errorf("grouping: configuration is nil")
	}
	if cfg.Home.Enabled && cfg.Grouping.Enabled {
		return fmt.Errorf("grouping: Home mode cannot be combined with grouping until dual-end policy enforcement is supported")
	}
	return nil
}

// EnsureGroupingCredentialIDs initializes missing source identities on an explicitly
// supplied configuration. It does not enable grouping or persist configuration.
// Existing invalid or duplicate identities abort without changing any records.
func EnsureGroupingCredentialIDs(cfg *Config) (bool, error) {
	refs, err := groupingCredentialIDRefs(cfg)
	if err != nil {
		return false, err
	}
	if err = validateGroupingIDRefs(refs, false); err != nil {
		return false, err
	}
	pending := make(map[*string]string)
	for _, ref := range refs {
		if *ref.id != "" || !ref.required {
			continue
		}
		id, errNew := uuid.NewRandom()
		if errNew != nil {
			return false, fmt.Errorf("grouping: generate identity for %s: %w", ref.path, errNew)
		}
		pending[ref.id] = id.String()
	}
	for dst, id := range pending {
		*dst = id
	}
	return len(pending) > 0, nil
}

// ValidateGroupingCredentialIDs validates source identities without filling missing
// values. Callers must run it before publishing enabled configuration reloads.
func ValidateGroupingCredentialIDs(cfg *Config) error {
	refs, err := groupingCredentialIDRefs(cfg)
	if err != nil {
		return err
	}
	return validateGroupingIDRefs(refs, true)
}

// GroupingCredentialSources maps persistent IDs to nonsecret configuration paths.
func GroupingCredentialSources(cfg *Config) map[string]string {
	refs, err := groupingCredentialIDRefs(cfg)
	if err != nil {
		return nil
	}
	paths := make(map[string]string, len(refs))
	for _, ref := range refs {
		if *ref.id != "" {
			paths[*ref.id] = strings.TrimSuffix(ref.path, ".grouping-id")
		}
	}
	return paths
}

type groupingIDRef struct {
	id       *string
	path     string
	required bool
}

func validateGroupingIDRefs(refs []groupingIDRef, requireAll bool) error {
	seen := make(map[uuid.UUID]string, len(refs))
	for _, ref := range refs {
		value := *ref.id
		if value == "" && (!requireAll || !ref.required) {
			continue
		}
		id, err := uuid.Parse(value)
		if err != nil || id == uuid.Nil || !strings.EqualFold(value, id.String()) {
			return fmt.Errorf("grouping: %s requires a nonzero canonical UUID", ref.path)
		}
		if previous, ok := seen[id]; ok {
			return fmt.Errorf("grouping: duplicate credential identity at %s and %s", previous, ref.path)
		}
		seen[id] = ref.path
	}
	return nil
}

func groupingCredentialIDRefs(cfg *Config) ([]groupingIDRef, error) {
	if cfg == nil {
		return nil, fmt.Errorf("grouping: configuration is nil")
	}
	var refs []groupingIDRef
	add := func(path string, index int, id *string) {
		refs = append(refs, groupingIDRef{id, fmt.Sprintf("%s[%d].grouping-id", path, index), true})
	}
	for i := range cfg.GeminiKey {
		add("gemini-api-key", i, &cfg.GeminiKey[i].GroupingID)
	}
	for i := range cfg.InteractionsKey {
		add("interactions-api-key", i, &cfg.InteractionsKey[i].GroupingID)
	}
	for i := range cfg.ClaudeKey {
		add("claude-api-key", i, &cfg.ClaudeKey[i].GroupingID)
	}
	for i := range cfg.CodexKey {
		add("codex-api-key", i, &cfg.CodexKey[i].GroupingID)
	}
	for i := range cfg.XAIKey {
		add("xai-api-key", i, &cfg.XAIKey[i].GroupingID)
	}
	for i := range cfg.MetaKey {
		add("meta-api-key", i, &cfg.MetaKey[i].GroupingID)
	}
	for i := range cfg.VertexCompatAPIKey {
		add("vertex-api-key", i, &cfg.VertexCompatAPIKey[i].GroupingID)
	}
	for i := range cfg.OpenAICompatibility {
		entry := &cfg.OpenAICompatibility[i]
		path := fmt.Sprintf("openai-compatibility[%d]", i)
		refs = append(refs, groupingIDRef{&entry.GroupingID, path + ".grouping-id", len(entry.APIKeyEntries) == 0})
		for j := range entry.APIKeyEntries {
			add(path+".api-key-entries", j, &entry.APIKeyEntries[j].GroupingID)
		}
	}
	return refs, nil
}
