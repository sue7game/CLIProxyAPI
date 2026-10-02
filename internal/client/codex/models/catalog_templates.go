package models

import (
	"encoding/json"
	"strings"
	"sync"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/registry"
)

type codexClientModelsPayload struct {
	Models []map[string]any `json:"models"`
}

var (
	codexClientModelTemplatesMu       sync.Mutex
	codexClientModelTemplatesLoaded   bool
	codexClientModelTemplatesRevision uint64
	codexClientModelTemplates         map[string]map[string]any
	codexClientDefaultTemplate        map[string]any
	codexClientModelTemplatesErr      error
)

func loadCodexClientModelTemplates() (map[string]map[string]any, map[string]any, error) {
	raw, revision := registry.GetCodexClientModelsSnapshot()
	return loadCodexClientModelTemplatesSnapshot(raw, revision)
}

func loadCodexClientModelTemplatesSnapshot(raw []byte, revision uint64) (map[string]map[string]any, map[string]any, error) {
	codexClientModelTemplatesMu.Lock()
	defer codexClientModelTemplatesMu.Unlock()
	if codexClientModelTemplatesLoaded && codexClientModelTemplatesRevision == revision {
		return codexClientModelTemplates, codexClientDefaultTemplate, codexClientModelTemplatesErr
	}

	var payload codexClientModelsPayload
	err := json.Unmarshal(raw, &payload)
	var templates map[string]map[string]any
	var defaultTemplate map[string]any
	if err == nil {
		templates = make(map[string]map[string]any, len(payload.Models))
		for _, model := range payload.Models {
			slug := strings.TrimSpace(stringModelValue(model, "slug"))
			if slug == "" {
				continue
			}
			templates[slug] = cloneCodexClientModelMap(model)
			if slug == "gpt-5.5" {
				defaultTemplate = cloneCodexClientModelMap(model)
			}
		}
	}

	codexClientModelTemplatesLoaded = true
	codexClientModelTemplatesRevision = revision
	codexClientModelTemplates = templates
	codexClientDefaultTemplate = defaultTemplate
	codexClientModelTemplatesErr = err
	return codexClientModelTemplates, codexClientDefaultTemplate, codexClientModelTemplatesErr
}
