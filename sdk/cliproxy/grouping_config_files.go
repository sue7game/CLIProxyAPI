package cliproxy

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/config"
	"gopkg.in/yaml.v3"
)

// prepareGroupingConfig preserves duplicate source records from the original YAML.
// Normalized legacy configurations can already have collapsed identical keys.
func prepareGroupingConfig(path string, current *config.Config) (*config.Config, *groupingFileChange, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("grouping: cannot read configuration for initialization")
	}
	var raw config.Config
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, nil, fmt.Errorf("grouping: invalid initialization configuration")
	}
	working := current.CloneForRuntime()
	copyGroupingCredentialLists(working, &raw)
	if _, err := config.EnsureGroupingCredentialIDs(working); err != nil {
		return nil, nil, err
	}
	after, err := config.PrepareGroupingConfigDocument(data, working)
	if err != nil {
		return nil, nil, err
	}
	normalizeGroupingCredentialLists(working)
	return working, &groupingFileChange{path: path, before: data, after: after}, nil
}

func normalizeGroupingCredentialLists(cfg *config.Config) {
	cfg.SanitizeGeminiKeys()
	cfg.SanitizeInteractionsKeys()
	cfg.SanitizeClaudeKeys()
	cfg.SanitizeCodexKeys()
	cfg.SanitizeXAIKeys()
	cfg.SanitizeMetaKeys()
	cfg.SanitizeOpenAICompatibility()
	cfg.SanitizeVertexCompatKeys()
}

func copyGroupingCredentialLists(dst, source *config.Config) {
	dst.GeminiKey = source.GeminiKey
	dst.InteractionsKey = source.InteractionsKey
	dst.ClaudeKey = source.ClaudeKey
	dst.CodexKey = source.CodexKey
	dst.XAIKey = source.XAIKey
	dst.MetaKey = source.MetaKey
	dst.VertexCompatAPIKey = source.VertexCompatAPIKey
	dst.OpenAICompatibility = source.OpenAICompatibility
}

func prepareGroupingConfigWrite(path string, before []byte, cfg *config.Config) (_ *groupingFileChange, err error) {
	file, err := os.CreateTemp(filepath.Dir(path), ".grouping-config-*")
	if err != nil {
		return nil, fmt.Errorf("grouping: cannot prepare configuration update")
	}
	name := file.Name()
	defer func() {
		if errRemove := os.Remove(name); errRemove != nil && !errors.Is(errRemove, os.ErrNotExist) {
			err = errors.Join(err, fmt.Errorf("grouping: cannot remove configuration temporary file"))
		}
	}()
	if err := writeGroupingTemp(file, before); err != nil {
		return nil, err
	}
	if err := config.SaveConfigPreserveComments(name, cfg); err != nil {
		return nil, fmt.Errorf("grouping: cannot render configuration update")
	}
	after, err := os.ReadFile(name)
	if err != nil {
		return nil, fmt.Errorf("grouping: cannot read configuration update")
	}
	return &groupingFileChange{path: path, before: before, after: after}, nil
}
