package models

import (
	"encoding/json"
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
)

func codexClientMetadataModelID(id string, lookup modelInfoLookupFunc) string {
	id = strings.TrimSpace(id)
	if info := lookup(id); info != nil {
		if metadataID := strings.TrimSpace(info.MetadataModelID); metadataID != "" {
			return metadataID
		}
	}
	if idx := strings.Index(id, "/"); idx != -1 {
		base := strings.TrimSpace(id[idx+1:])
		if info := lookup(base); info != nil && strings.TrimSpace(info.MetadataModelID) != "" {
			return strings.TrimSpace(info.MetadataModelID)
		}
		return base
	}
	return id
}

func applyCodexClientDisplayName(entry map[string]any, model map[string]any) {
	if displayName := stringModelValue(model, "display_name"); displayName != "" {
		entry["display_name"] = displayName
	}
}

func applyCodexClientDescription(entry map[string]any, model map[string]any) {
	if description := stringModelValue(model, "description"); description != "" {
		entry["description"] = description
	}
}

func applyCodexClientBaseInstructions(entry map[string]any, model map[string]any) {
	if baseInstructions := stringModelValue(model, "base_instructions"); baseInstructions != "" {
		entry["base_instructions"] = baseInstructions
	}
}

func applyCodexClientMaxContextLengthOverride(entry map[string]any, model map[string]any) {
	if maxContextLength := intModelValue(model, "max_context_length"); maxContextLength > 0 {
		entry["context_window"] = maxContextLength
		entry["max_context_window"] = maxContextLength
	}
}

func applyCodexClientMaxTokens(entry map[string]any, model map[string]any) {
	if maxCompletionTokens := intModelValue(model, "max_completion_tokens"); maxCompletionTokens > 0 {
		entry["max_tokens"] = maxCompletionTokens
	}
}

func applyCodexClientModelMetadata(entry map[string]any, id string, model map[string]any, optimizeMultiAgentV2 bool, clientVersion string) {
	applyCodexClientModelMetadataWithLookup(entry, id, model, optimizeMultiAgentV2, clientVersion, registry.LookupModelInfo)
}

func applyCodexClientModelMetadataWithLookup(entry map[string]any, id string, model map[string]any, optimizeMultiAgentV2 bool, clientVersion string, lookup modelInfoLookupFunc) {
	info := lookup(id)

	displayName := stringModelValue(model, "display_name")
	description := stringModelValue(model, "description")
	contextWindow := intModelValue(model, "context_length")
	thinkingSupport := codexClientThinkingSupport(model)

	if info != nil {
		if info.DisplayName != "" {
			displayName = info.DisplayName
		}
		if info.Description != "" {
			description = info.Description
		}
		if contextWindow <= 0 && info.ContextLength > 0 {
			contextWindow = info.ContextLength
		}
		if info.Type == registry.OpenAIImageModelType {
			entry["visibility"] = "hide"
			delete(entry, "input_modalities")
			delete(entry, "supports_image_detail_original")
		} else {
			applyCodexClientInputModalitiesMetadata(entry, info.SupportedInputModalities)
		}
		if thinkingSupport == nil {
			thinkingSupport = info.Thinking
		}
	}
	applyCodexClientThinkingMetadata(entry, thinkingSupport, clientVersion)
	applyCodexClientCustomPresentation(entry, id, model, displayName, description, contextWindow, optimizeMultiAgentV2)
}

func applyCodexClientCustomPresentation(entry map[string]any, id string, model map[string]any, displayName, description string, contextWindow int, optimizeMultiAgentV2 bool) {
	if maxContextWindow := intModelValue(model, "max_context_length"); maxContextWindow > 0 {
		contextWindow = maxContextWindow
	}

	if displayName == "" {
		displayName = id
	}
	if description == "" {
		description = id
	}

	entry["slug"] = id
	entry["display_name"] = displayName
	entry["description"] = description
	entry["prefer_websockets"] = false
	if optimizeMultiAgentV2 {
		entry["multi_agent_version"] = "v2"
	}
	entry["service_tiers"] = []any{}
	nullCodexClientRequiredOptions(entry)

	if contextWindow > 0 {
		entry["context_window"] = contextWindow
		entry["max_context_window"] = contextWindow
	}

	if plans, ok := model["available_in_plans"]; ok {
		entry["available_in_plans"] = cloneCodexClientModelValue(plans)
	}
	// Codex 0.156+ caps an explicit model_catalog_url body at 1MiB. Cloning the
	// full template instructions onto every non-template model exceeds that limit
	// and the client keeps its bundled catalog.
	useCompactCodexClientInstructions(entry)
}

func codexClientThinkingSupport(model map[string]any) *registry.ThinkingSupport {
	raw, ok := model["thinking"]
	if !ok || raw == nil {
		return nil
	}
	switch thinking := raw.(type) {
	case *registry.ThinkingSupport:
		return thinking
	case registry.ThinkingSupport:
		return &thinking
	}
	data, errMarshal := json.Marshal(raw)
	if errMarshal != nil {
		return nil
	}
	var thinking registry.ThinkingSupport
	if errUnmarshal := json.Unmarshal(data, &thinking); errUnmarshal != nil {
		return nil
	}
	return &thinking
}

func applyCodexClientVisibilityOverride(entry map[string]any, id string) {
	if isCodexClientImageOrVideoModel(id) {
		entry["visibility"] = "hide"
	}
}

func isCodexClientImageOrVideoModel(id string) bool {
	target := strings.TrimSpace(id)
	if idx := strings.Index(target, "/"); idx != -1 {
		target = strings.TrimSpace(target[idx+1:])
	}
	switch target {
	case "grok-imagine-image-quality", "gpt-image-1.5", "gpt-image-2", "gpt-image-2.5-flare", "gpt-image-2.5-sunburst", "gpt-image-2.5", "grok-imagine-image", "grok-imagine-image-2.0", "grok-imagine-video", "grok-imagine-video-1.5", "grok-imagine-video-1.5-preview":
		return true
	default:
		return false
	}
}

func applyCodexClientInputModalitiesMetadata(entry map[string]any, modalities []string) {
	if len(modalities) == 0 {
		return
	}
	codexModalities := filterCodexInputModalities(modalities)
	if len(codexModalities) == 0 {
		return
	}
	entry["input_modalities"] = codexModalities
	if hasImageModality(codexModalities) {
		entry["supports_image_detail_original"] = true
	} else {
		delete(entry, "supports_image_detail_original")
	}
}

func filterCodexInputModalities(modalities []string) []any {
	if len(modalities) == 0 {
		return []any{}
	}
	codexModalities := make([]any, 0, 2)
	seen := make(map[string]struct{}, 2)
	for _, raw := range modalities {
		switch modality := strings.ToLower(strings.TrimSpace(raw)); modality {
		case "text", "image":
			if _, ok := seen[modality]; ok {
				continue
			}
			seen[modality] = struct{}{}
			codexModalities = append(codexModalities, modality)
		}
	}
	return codexModalities
}

func hasImageModality(modalities []any) bool {
	for _, m := range modalities {
		if s, ok := m.(string); ok && s == "image" {
			return true
		}
	}
	return false
}
