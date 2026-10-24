package openai

import (
	"context"

	codexmodels "github.com/router-for-me/CLIProxyAPI/v8/internal/client/codex/models"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	responsesclaude "github.com/router-for-me/CLIProxyAPI/v8/internal/translator/claude/openai/responses"
)

func (h *OpenAIAPIHandler) codexClientModelsForRequest(ctx context.Context, models []map[string]any, version string) (map[string]any, error) {
	cfg := h.CurrentConfig()
	optimize := cfg != nil && cfg.Client.Codex.OptimizeMultiAgentV2
	applyPatchEnabled := cfg != nil && cfg.Client.Codex.EnableApplyPatch
	var toolSearch codexmodels.ToolSearchCapabilityForModelFunc
	if responsesclaude.ClientToolSearchEnabled() {
		toolSearch = h.SupportsNativeToolSearchModel
	}
	if !h.CredentialGroupingEnabled() {
		var applyPatch codexmodels.ApplyPatchCapabilityForModelFunc
		if applyPatchEnabled {
			applyPatch = h.SupportsApplyPatchModel
		}
		r := registry.GetGlobalRegistry()
		return codexmodels.BuildResponseForClientWithToolCapabilities(models, r.GetModelProviders, r.GetResponsesWebSearchCapability, applyPatch, toolSearch, optimize, version), nil
	}
	catalog, err := h.RequestModelCatalog(ctx, "openai")
	if err != nil {
		return nil, err
	}
	var applyPatch codexmodels.ApplyPatchCapabilityForModelFunc
	if applyPatchEnabled {
		applyPatch = func(id string) bool {
			return h.AuthManager.SupportsApplyPatchForProviders(catalog.Providers[id])
		}
	}
	if toolSearch != nil {
		auths, errAccess := h.AuthManager.AccessibleAuths(ctx)
		if errAccess != nil {
			return nil, errAccess
		}
		for _, auth := range auths {
			if errAccess = h.AuthManager.AuthorizeCredentialUse(ctx, auth); errAccess != nil {
				return nil, errAccess
			}
		}
		toolSearch = func(model string) bool {
			return h.AuthManager.SupportsNativeToolSearchForAuths(model, auths)
		}
	}
	return codexmodels.BuildResponseForCredentialCatalogWithToolCapabilities(catalog, applyPatch, toolSearch, optimize, version), nil
}

func (h *OpenAIAPIHandler) codexClientModelsResponse(clientVersion ...string) map[string]any {
	version := ""
	if len(clientVersion) > 0 {
		version = clientVersion[0]
	}
	optimizeMultiAgentV2 := false
	var applyPatchCapabilityForModel codexmodels.ApplyPatchCapabilityForModelFunc
	if h != nil {
		if cfg := h.CurrentConfig(); cfg != nil {
			optimizeMultiAgentV2 = cfg.Client.Codex.OptimizeMultiAgentV2
			if cfg.Client.Codex.EnableApplyPatch {
				applyPatchCapabilityForModel = h.SupportsApplyPatchModel
			}
		}
	}
	var toolSearchCapabilityForModel codexmodels.ToolSearchCapabilityForModelFunc
	if h != nil && responsesclaude.ClientToolSearchEnabled() {
		toolSearchCapabilityForModel = h.SupportsNativeToolSearchModel
	}
	modelRegistry := registry.GetGlobalRegistry()
	return codexmodels.BuildResponseForClientWithToolCapabilities(h.Models(), modelRegistry.GetModelProviders, modelRegistry.GetResponsesWebSearchCapability, applyPatchCapabilityForModel, toolSearchCapabilityForModel, optimizeMultiAgentV2, version)
}

// CodexClientModelsResponse builds a Codex client model response.
func CodexClientModelsResponse(models []map[string]any) map[string]any {
	return codexmodels.BuildResponse(models, nil, false)
}

// CodexClientModelsResponseWithMultiAgentV2 builds a Codex client model response
// and advertises multi-agent v2 for synthesized models when enabled.
func CodexClientModelsResponseWithMultiAgentV2(models []map[string]any, enabled bool) map[string]any {
	return codexmodels.BuildResponse(models, nil, enabled)
}

// CodexClientModelsResponseForClient builds a Codex client model response
// tailored for a specific client version.
func CodexClientModelsResponseForClient(models []map[string]any, clientVersion string, enabled bool) map[string]any {
	return codexmodels.BuildResponseForClient(models, nil, enabled, clientVersion)
}
