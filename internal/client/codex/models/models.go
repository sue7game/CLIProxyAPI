// Package models builds model catalogs for official Codex clients.
package models

import (
	"bytes"
	"encoding/json"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
)

// ProvidersForModelFunc returns the providers registered for a model.
type ProvidersForModelFunc func(string) []string

// WebSearchCapabilityForModelFunc returns explicit conservative capability
// metadata for an exact public model ID. nil means unknown.
type WebSearchCapabilityForModelFunc func(string) *bool

// ToolSearchCapabilityForModelFunc reports whether every authorized credential
// serving a public model can receive Codex tool_search as Anthropic native search.
type ToolSearchCapabilityForModelFunc func(string) bool

type modelInfoLookupFunc func(string, ...string) *registry.ModelInfo

// BuildResponse builds a Codex client model response from available models.
func BuildResponse(availableModels []map[string]any, providersForModel ProvidersForModelFunc, optimizeMultiAgentV2 bool) map[string]any {
	return BuildResponseForClient(availableModels, providersForModel, optimizeMultiAgentV2, "")
}

// BuildResponseForClient builds a model response tailored for a client version.
func BuildResponseForClient(availableModels []map[string]any, providersForModel ProvidersForModelFunc, optimizeMultiAgentV2 bool, clientVersion string) map[string]any {
	return BuildResponseForClientWithCPACapabilities(availableModels, providersForModel, registry.GetGlobalRegistry().GetResponsesWebSearchCapability, optimizeMultiAgentV2, clientVersion)
}

// BuildResponseForClientWithCPACapabilities accepts capability metadata independent of the local registry.
func BuildResponseForClientWithCPACapabilities(availableModels []map[string]any, providersForModel ProvidersForModelFunc, webSearchCapabilityForModel WebSearchCapabilityForModelFunc, optimizeMultiAgentV2 bool, clientVersion string) map[string]any {
	return BuildResponseForClientWithToolCapabilities(availableModels, providersForModel, webSearchCapabilityForModel, nil, nil, optimizeMultiAgentV2, clientVersion)
}

// BuildResponseForClientWithToolCapabilities adds executor-backed tool support.
func BuildResponseForClientWithToolCapabilities(availableModels []map[string]any, providersForModel ProvidersForModelFunc, webSearchCapabilityForModel WebSearchCapabilityForModelFunc, applyPatchCapabilityForModel ApplyPatchCapabilityForModelFunc, toolSearchCapabilityForModel ToolSearchCapabilityForModelFunc, optimizeMultiAgentV2 bool, clientVersion string) map[string]any {
	return BuildResponseForClientWithSearchToolRoutes(availableModels, providersForModel, nil, webSearchCapabilityForModel, applyPatchCapabilityForModel, toolSearchCapabilityForModel, optimizeMultiAgentV2, clientVersion)
}

// BuildResponseForClientWithSearchToolRoutes lets Home supply routing evidence
// for search without the other provider-dependent metadata. A nil search route
// callback uses providersForModel; a nil tool callback disables Claude search.
func BuildResponseForClientWithSearchToolRoutes(availableModels []map[string]any, providersForModel, searchToolProvidersForModel ProvidersForModelFunc, webSearchCapabilityForModel WebSearchCapabilityForModelFunc, applyPatchCapabilityForModel ApplyPatchCapabilityForModelFunc, toolSearchCapabilityForModel ToolSearchCapabilityForModelFunc, optimizeMultiAgentV2 bool, clientVersion string) map[string]any {
	return map[string]any{
		"models": buildCodexClientModelsWithToolCapabilities(availableModels, providersForModel, searchToolProvidersForModel, webSearchCapabilityForModel, applyPatchCapabilityForModel, toolSearchCapabilityForModel, optimizeMultiAgentV2, clientVersion, registry.LookupModelInfo),
	}
}

// BuildResponseForCredentialCatalog uses only authorized route metadata.
// Shared public templates never add model IDs or other clients' metadata.
func BuildResponseForCredentialCatalog(catalog registry.CredentialModelCatalog, optimizeMultiAgentV2 bool, clientVersion string) map[string]any {
	return BuildResponseForCredentialCatalogWithToolCapabilities(catalog, nil, nil, optimizeMultiAgentV2, clientVersion)
}

// BuildResponseForCredentialCatalogWithToolCapabilities combines scoped metadata
// with executor capabilities evaluated only for authorized catalog providers.
func BuildResponseForCredentialCatalogWithToolCapabilities(catalog registry.CredentialModelCatalog, applyPatchCapabilityForModel ApplyPatchCapabilityForModelFunc, toolSearchCapabilityForModel ToolSearchCapabilityForModelFunc, optimizeMultiAgentV2 bool, clientVersion string) map[string]any {
	return map[string]any{
		"models": buildCodexClientModelsWithToolCapabilities(catalog.Models,
			func(id string) []string { return catalog.Providers[id] }, nil,
			func(id string) *bool { return catalog.WebSearch[id] },
			applyPatchCapabilityForModel, toolSearchCapabilityForModel, optimizeMultiAgentV2, clientVersion, catalog.LookupModelInfo),
	}
}

// MarshalCompact serializes a catalog as a single JSON line without HTML escaping.
func MarshalCompact(payload any) ([]byte, error) {
	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	encoder.SetEscapeHTML(false)
	if errEncode := encoder.Encode(payload); errEncode != nil {
		return nil, errEncode
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}
