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

type modelInfoLookupFunc func(string, ...string) *registry.ModelInfo

// BuildResponse builds a Codex client model response from available models.
func BuildResponse(availableModels []map[string]any, providersForModel ProvidersForModelFunc, optimizeMultiAgentV2 bool) map[string]any {
	return BuildResponseForClient(availableModels, providersForModel, optimizeMultiAgentV2, "")
}

// BuildResponseForClient builds a Codex client model response from available models
// tailored for a specific client version.
func BuildResponseForClient(availableModels []map[string]any, providersForModel ProvidersForModelFunc, optimizeMultiAgentV2 bool, clientVersion string) map[string]any {
	return BuildResponseForClientWithCPACapabilities(availableModels, providersForModel, registry.GetGlobalRegistry().GetResponsesWebSearchCapability, optimizeMultiAgentV2, clientVersion)
}

// BuildResponseForClientWithCPACapabilities builds a client response while
// allowing Home to supply capability metadata independent of the local registry.
func BuildResponseForClientWithCPACapabilities(availableModels []map[string]any, providersForModel ProvidersForModelFunc, webSearchCapabilityForModel WebSearchCapabilityForModelFunc, optimizeMultiAgentV2 bool, clientVersion string) map[string]any {
	return BuildResponseForClientWithToolCapabilities(availableModels, providersForModel, webSearchCapabilityForModel, nil, optimizeMultiAgentV2, clientVersion)
}

// BuildResponseForClientWithToolCapabilities adds executor-backed tool support
// independently of template metadata and legacy provider restrictions.
func BuildResponseForClientWithToolCapabilities(availableModels []map[string]any, providersForModel ProvidersForModelFunc, webSearchCapabilityForModel WebSearchCapabilityForModelFunc, applyPatchCapabilityForModel ApplyPatchCapabilityForModelFunc, optimizeMultiAgentV2 bool, clientVersion string) map[string]any {
	return map[string]any{
		"models": buildCodexClientModelsWithToolCapabilities(availableModels, providersForModel, webSearchCapabilityForModel, applyPatchCapabilityForModel, optimizeMultiAgentV2, clientVersion, registry.LookupModelInfo),
	}
}

// BuildResponseForCredentialCatalog uses only authorized route metadata.
// Public client templates remain shared, but never add model IDs or other clients' metadata.
func BuildResponseForCredentialCatalog(catalog registry.CredentialModelCatalog, optimizeMultiAgentV2 bool, clientVersion string) map[string]any {
	return BuildResponseForCredentialCatalogWithToolCapabilities(catalog, nil, optimizeMultiAgentV2, clientVersion)
}

// BuildResponseForCredentialCatalogWithToolCapabilities combines scoped route metadata
// with executor capabilities evaluated only for authorized catalog providers.
func BuildResponseForCredentialCatalogWithToolCapabilities(catalog registry.CredentialModelCatalog, applyPatchCapabilityForModel ApplyPatchCapabilityForModelFunc, optimizeMultiAgentV2 bool, clientVersion string) map[string]any {
	return map[string]any{
		"models": buildCodexClientModelsWithToolCapabilities(catalog.Models,
			func(id string) []string { return catalog.Providers[id] },
			func(id string) *bool { return catalog.WebSearch[id] },
			applyPatchCapabilityForModel, optimizeMultiAgentV2, clientVersion, catalog.LookupModelInfo),
	}
}

// MarshalCompact serializes a Codex client catalog as a single JSON line.
// HTML escaping is disabled so instruction text is not expanded into \u003c sequences.
func MarshalCompact(payload any) ([]byte, error) {
	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	encoder.SetEscapeHTML(false)
	if errEncode := encoder.Encode(payload); errEncode != nil {
		return nil, errEncode
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}
