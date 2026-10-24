package models

import (
	"sort"
	"strings"
)

func buildCodexClientModelsWithToolCapabilities(models []map[string]any, providersForModel, searchToolProvidersForModel ProvidersForModelFunc, webSearchCapabilityForModel WebSearchCapabilityForModelFunc, applyPatchCapabilityForModel ApplyPatchCapabilityForModelFunc, toolSearchCapabilityForModel ToolSearchCapabilityForModelFunc, optimizeMultiAgentV2 bool, clientVersion string, lookup modelInfoLookupFunc) []map[string]any {
	templates, defaultTemplate, err := loadCodexClientModelTemplates()
	if err != nil || defaultTemplate == nil {
		return nil
	}
	if searchToolProvidersForModel == nil {
		searchToolProvidersForModel = providersForModel
	}

	result := make([]map[string]any, 0, len(models))
	for _, model := range models {
		id := strings.TrimSpace(stringModelValue(model, "id"))
		if id == "" {
			continue
		}

		metadataID := codexClientMetadataModelID(id, lookup)
		template, isTemplate := templates[metadataID]
		var entry map[string]any
		if isTemplate {
			entry = buildCodexClientTemplateEntry(template, model, id, metadataID, providersForModel, clientVersion, lookup)
			applyCodexClientProviderCapabilities(entry, id, providersForModel)
		} else {
			entry = cloneCodexClientModelMap(defaultTemplate)
			applyCodexClientModelMetadataWithLookup(entry, id, model, optimizeMultiAgentV2, clientVersion, lookup)
		}
		applyCodexClientMaxTokens(entry, model)
		applyCodexClientSearchToolSupport(entry, id, isTemplate, searchToolProvidersForModel, toolSearchCapabilityForModel)
		applyCPAWebSearchCapability(entry, id, webSearchCapabilityForModel, clientVersion)
		sanitizeCodexClientReasoningMetadata(entry, clientVersion)
		applyCodexClientVisibilityOverride(entry, id)
		if optimizeMultiAgentV2 {
			entry["multi_agent_version"] = "v2"
		}
		applyCodexClientDevinDisplayName(entry, id, model, providersForModel, lookup)
		applyCodexClientApplyPatchCapability(entry, id, applyPatchCapabilityForModel)
		result = append(result, entry)
	}

	applyCodexClientNonTemplatePriorities(result, templates, lookup)

	sort.SliceStable(result, func(i, j int) bool {
		return codexClientModelPriority(result[i]) < codexClientModelPriority(result[j])
	})

	return result
}

func buildCodexClientTemplateEntry(template, model map[string]any, id, metadataID string, providersForModel ProvidersForModelFunc, clientVersion string, lookup modelInfoLookupFunc) map[string]any {
	entry := cloneCodexClientModelMap(template)
	entry["slug"] = id
	applyCodexClientModelCapabilities(entry, id, metadataID, lookup(id), providersForModel, clientVersion, lookup)
	applyCodexClientDisplayName(entry, model)
	applyCodexClientDescription(entry, model)
	applyCodexClientBaseInstructions(entry, model)
	applyCodexClientMaxContextLengthOverride(entry, model)
	if thinkingSupport := codexClientThinkingSupport(model); thinkingSupport != nil {
		applyCodexClientThinkingMetadata(entry, thinkingSupport, clientVersion)
	}
	return entry
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
