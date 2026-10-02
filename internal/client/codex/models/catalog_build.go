package models

import (
	"sort"
	"strings"
)

func buildCodexClientModels(models []map[string]any, providersForModel ProvidersForModelFunc, webSearchCapabilityForModel WebSearchCapabilityForModelFunc, optimizeMultiAgentV2 bool, clientVersion string, lookup modelInfoLookupFunc) []map[string]any {
	templates, defaultTemplate, err := loadCodexClientModelTemplates()
	if err != nil || defaultTemplate == nil {
		return nil
	}

	result := make([]map[string]any, 0, len(models))
	for _, model := range models {
		id := strings.TrimSpace(stringModelValue(model, "id"))
		if id == "" {
			continue
		}

		metadataID := codexClientMetadataModelID(id, lookup)

		if template, ok := templates[metadataID]; ok {
			entry := cloneCodexClientModelMap(template)
			entry["slug"] = id
			info := lookup(id)
			applyCodexClientModelCapabilities(entry, id, metadataID, info, providersForModel, clientVersion, lookup)
			applyCodexClientDisplayName(entry, model)
			applyCodexClientDescription(entry, model)
			applyCodexClientBaseInstructions(entry, model)
			applyCodexClientMaxContextLengthOverride(entry, model)
			applyCodexClientMaxTokens(entry, model)
			if thinkingSupport := codexClientThinkingSupport(model); thinkingSupport != nil {
				applyCodexClientThinkingMetadata(entry, thinkingSupport, clientVersion)
			}
			applyCodexClientProviderCapabilities(entry, id, true, providersForModel)
			applyCPAWebSearchCapability(entry, id, webSearchCapabilityForModel, clientVersion)
			sanitizeCodexClientReasoningMetadata(entry, clientVersion)
			applyCodexClientVisibilityOverride(entry, id)
			if optimizeMultiAgentV2 {
				entry["multi_agent_version"] = "v2"
			}
			applyCodexClientDevinDisplayName(entry, id, model, providersForModel, lookup)
			result = append(result, entry)
			continue
		}

		entry := cloneCodexClientModelMap(defaultTemplate)
		applyCodexClientModelMetadataWithLookup(entry, id, model, optimizeMultiAgentV2, clientVersion, lookup)
		applyCodexClientMaxTokens(entry, model)
		applyCodexClientProviderCapabilities(entry, id, false, providersForModel)
		applyCPAWebSearchCapability(entry, id, webSearchCapabilityForModel, clientVersion)
		sanitizeCodexClientReasoningMetadata(entry, clientVersion)
		applyCodexClientVisibilityOverride(entry, id)
		applyCodexClientDevinDisplayName(entry, id, model, providersForModel, lookup)
		result = append(result, entry)
	}

	applyCodexClientNonTemplatePriorities(result, templates, lookup)

	sort.SliceStable(result, func(i, j int) bool {
		return codexClientModelPriority(result[i]) < codexClientModelPriority(result[j])
	})

	return result
}

func maxCodexClientTemplatePriority(templates map[string]map[string]any) int {
	maxPriority := 0
	for _, template := range templates {
		priority := codexClientModelPriority(template)
		if priority > maxPriority {
			maxPriority = priority
		}
	}
	return maxPriority
}

func applyCodexClientNonTemplatePriorities(result []map[string]any, templates map[string]map[string]any, lookup modelInfoLookupFunc) {
	if len(result) == 0 {
		return
	}

	basePriority := maxCodexClientTemplatePriority(templates)
	type nonTemplateEntry struct {
		index       int
		displayName string
		slug        string
	}

	pending := make([]nonTemplateEntry, 0)
	for index, entry := range result {
		slug := stringModelValue(entry, "slug")
		if _, ok := templates[codexClientMetadataModelID(slug, lookup)]; ok {
			continue
		}
		displayName := stringModelValue(entry, "display_name")
		if displayName == "" {
			displayName = slug
		}
		pending = append(pending, nonTemplateEntry{
			index:       index,
			displayName: displayName,
			slug:        slug,
		})
	}

	sort.SliceStable(pending, func(i, j int) bool {
		left := strings.ToLower(pending[i].displayName)
		right := strings.ToLower(pending[j].displayName)
		if left == right {
			return pending[i].slug < pending[j].slug
		}
		return left < right
	})

	for rank, entry := range pending {
		result[entry.index]["priority"] = basePriority + 100*(rank+1)
	}
}
