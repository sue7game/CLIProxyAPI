package models

import (
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
)

func applyCodexClientModelCapabilities(entry map[string]any, id, metadataID string, info *registry.ModelInfo, providersForModel ProvidersForModelFunc, clientVersion string, lookup modelInfoLookupFunc) {
	if info != nil && info.Type == registry.OpenAIImageModelType {
		entry["visibility"] = "hide"
		delete(entry, "input_modalities")
		delete(entry, "supports_image_detail_original")
		return
	}

	var providers []string
	if providersForModel != nil {
		providers = providersForModel(id)
		if len(providers) == 0 && strings.Contains(id, "/") {
			idx := strings.Index(id, "/")
			base := strings.TrimSpace(id[idx+1:])
			providers = providersForModel(base)
		}
	}

	isAlias := metadataID != "" && !strings.EqualFold(id, metadataID)
	applyCodexClientInputConstraints(entry, id, info, providers, isAlias, lookup)
	applyCodexClientThinkingConstraints(entry, id, info, providers, isAlias, clientVersion, lookup)
}

func applyCodexClientInputConstraints(entry map[string]any, id string, info *registry.ModelInfo, providers []string, isAlias bool, lookup modelInfoLookupFunc) {
	var constrainedModalities []string
	hasModalitiesConstraint := false
	for _, p := range providers {
		pInfo := lookup(id, p)
		if pInfo == nil && strings.Contains(id, "/") {
			idx := strings.Index(id, "/")
			pInfo = lookup(strings.TrimSpace(id[idx+1:]), p)
		}
		if pInfo == nil {
			continue
		}
		isCodex := strings.EqualFold(strings.TrimSpace(p), "codex")
		if (!isCodex && isAlias) || pInfo.ExplicitInputModalities {
			mods := pInfo.SupportedInputModalities
			if mods == nil {
				mods = []string{}
			}
			if !hasModalitiesConstraint {
				constrainedModalities = append([]string(nil), mods...)
				hasModalitiesConstraint = true
			} else {
				constrainedModalities = intersectStringSlices(constrainedModalities, mods)
			}
		}
	}
	if !hasModalitiesConstraint && info != nil && info.ExplicitInputModalities {
		mods := info.SupportedInputModalities
		if mods == nil {
			mods = []string{}
		}
		constrainedModalities = append([]string(nil), mods...)
		hasModalitiesConstraint = true
	}
	if hasModalitiesConstraint {
		codexModalities := filterCodexInputModalities(constrainedModalities)
		entry["input_modalities"] = codexModalities
		if hasImageModality(codexModalities) {
			entry["supports_image_detail_original"] = true
		} else {
			delete(entry, "supports_image_detail_original")
		}
	}

}

func applyCodexClientThinkingConstraints(entry map[string]any, id string, info *registry.ModelInfo, providers []string, isAlias bool, clientVersion string, lookup modelInfoLookupFunc) {
	var constrainedThinking *registry.ThinkingSupport
	hasThinkingConstraint := false
	for _, p := range providers {
		pInfo := lookup(id, p)
		if pInfo == nil && strings.Contains(id, "/") {
			idx := strings.Index(id, "/")
			pInfo = lookup(strings.TrimSpace(id[idx+1:]), p)
		}
		if pInfo == nil {
			continue
		}
		isCodex := strings.EqualFold(strings.TrimSpace(p), "codex")
		if (!isCodex && isAlias) || pInfo.ExplicitThinking {
			hasThinkingConstraint = true
			pThinking := pInfo.Thinking
			if pThinking == nil {
				pThinking = &registry.ThinkingSupport{Levels: []string{}}
			}
			if constrainedThinking == nil {
				constrainedThinking = pThinking
			} else {
				constrainedThinking = intersectThinkingSupport(constrainedThinking, pThinking)
			}
		}
	}
	if !hasThinkingConstraint && info != nil && info.ExplicitThinking {
		pThinking := info.Thinking
		if pThinking == nil {
			pThinking = &registry.ThinkingSupport{Levels: []string{}}
		}
		constrainedThinking = pThinking
		hasThinkingConstraint = true
	}
	if hasThinkingConstraint && constrainedThinking != nil {
		applyCodexClientThinkingMetadata(entry, constrainedThinking, clientVersion)
	}
}

func intersectThinkingSupport(a, b *registry.ThinkingSupport) *registry.ThinkingSupport {
	if a == nil {
		return b
	}
	if b == nil {
		return a
	}
	levels := intersectStringSlices(a.Levels, b.Levels)
	min := a.Min
	if b.Min > min {
		min = b.Min
	}
	max := a.Max
	if b.Max > 0 && (max == 0 || b.Max < max) {
		max = b.Max
	}
	return &registry.ThinkingSupport{
		Min:            min,
		Max:            max,
		ZeroAllowed:    a.ZeroAllowed && b.ZeroAllowed,
		DynamicAllowed: a.DynamicAllowed && b.DynamicAllowed,
		Levels:         levels,
	}
}

func intersectStringSlices(a, b []string) []string {
	if len(a) == 0 || len(b) == 0 {
		return []string{}
	}
	bMap := make(map[string]struct{}, len(b))
	for _, item := range b {
		bMap[strings.ToLower(strings.TrimSpace(item))] = struct{}{}
	}
	out := make([]string, 0, len(a))
	seen := make(map[string]struct{}, len(a))
	for _, item := range a {
		key := strings.ToLower(strings.TrimSpace(item))
		if _, inB := bMap[key]; inB {
			if _, inSeen := seen[key]; !inSeen {
				seen[key] = struct{}{}
				out = append(out, item)
			}
		}
	}
	return out
}

func applyCPAWebSearchCapability(entry map[string]any, id string, capabilityForModel WebSearchCapabilityForModelFunc, clientVersion string) {
	// Templates must not supply runtime capability claims or leak CPA-only fields.
	delete(entry, "cpa_capabilities")
	if clientVersion != "cpa" || capabilityForModel == nil {
		return
	}
	if supported := capabilityForModel(strings.TrimSpace(id)); supported != nil {
		entry["cpa_capabilities"] = map[string]any{"web_search": *supported}
	}
}

func applyCodexClientProviderCapabilities(entry map[string]any, id string, providersForModel ProvidersForModelFunc) {
	if providersForModel != nil && !isPureCodexProvider(id, providersForModel) {
		entry["prefer_websockets"] = false
		entry["service_tiers"] = []any{}
		nullCodexClientRequiredOptions(entry)
	}
}

// nullCodexClientRequiredOptions clears capabilities that non-Codex models must not advertise.
// Codex requires these keys to be present; omitting them rejects the entire catalog.
func nullCodexClientRequiredOptions(entry map[string]any) {
	entry["apply_patch_tool_type"] = nil
	entry["tool_mode"] = "direct"
	entry["use_responses_lite"] = false
	entry["supports_reasoning_effort_updates"] = false
	entry["upgrade"] = nil
	entry["availability_nux"] = nil
}

const codexClientFallbackInstructions = "You are Codex, a coding agent. You and the user share one workspace."

// useCompactCodexClientInstructions replaces cloned template prompts with a short literal.
// Both the legacy and canonical instruction fields must be present for catalog decoding.
func useCompactCodexClientInstructions(entry map[string]any) {
	entry["base_instructions"] = codexClientFallbackInstructions
	entry["model_messages"] = map[string]any{
		"instructions_template":  codexClientFallbackInstructions,
		"instructions_variables": nil,
		"approvals":              nil,
		"collaboration_modes":    nil,
		"auto_review":            nil,
		"permissions":            nil,
		"multi_agent":            nil,
	}
}

func isPureCodexProvider(id string, providersForModel ProvidersForModelFunc) bool {
	if providersForModel == nil {
		return true
	}
	return allCodexClientProvidersAre(codexClientModelProviders(id, providersForModel), "codex")
}

func codexClientModelProviders(id string, providersForModel ProvidersForModelFunc) []string {
	providers := providersForModel(id)
	if len(providers) == 0 && strings.Contains(id, "/") {
		idx := strings.Index(id, "/")
		base := strings.TrimSpace(id[idx+1:])
		providers = providersForModel(base)
	}
	return providers
}

func allCodexClientProvidersAre(providers []string, name string) bool {
	if len(providers) == 0 {
		return false
	}
	for _, provider := range providers {
		if !strings.EqualFold(strings.TrimSpace(provider), name) {
			return false
		}
	}
	return true
}

func applyCodexClientSearchToolSupport(entry map[string]any, id string, templateModel bool, providersForModel ProvidersForModelFunc, toolSearchCapabilityForModel ToolSearchCapabilityForModelFunc) {
	supportsSearch, _ := entry["supports_search_tool"].(bool)
	if !supportsSearch {
		return
	}

	if providersForModel == nil {
		if !templateModel {
			entry["supports_search_tool"] = false
		}
		return
	}

	providers := codexClientModelProviders(id, providersForModel)
	if allCodexClientProvidersAre(providers, "claude") && toolSearchCapabilityForModel != nil && toolSearchCapabilityForModel(id) {
		return
	}
	if !templateModel || !allCodexClientProvidersAre(providers, "codex") {
		entry["supports_search_tool"] = false
	}
}
