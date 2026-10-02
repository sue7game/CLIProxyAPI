package registry

import "sort"

// CredentialModelCatalog is a detached catalog derived only from selected clients.
type CredentialModelCatalog struct {
	Models        []map[string]any
	Providers     map[string][]string
	WebSearch     map[string]*bool
	Infos         map[string]*ModelInfo
	ProviderInfos map[string]map[string]*ModelInfo
}

// ModelsForClients returns the registered model union without transient cooldowns.
// It never falls back to another client's metadata or the global availability cache.
func (r *ModelRegistry) ModelsForClients(handlerType string, clientIDs []string) CredentialModelCatalog {
	catalog := CredentialModelCatalog{
		Models: make([]map[string]any, 0), Providers: make(map[string][]string), WebSearch: make(map[string]*bool),
		Infos: make(map[string]*ModelInfo), ProviderInfos: make(map[string]map[string]*ModelInfo),
	}
	ids := append([]string(nil), clientIDs...)
	sort.Strings(ids)
	r.mutex.RLock()
	defer r.mutex.RUnlock()
	models := make(map[string]map[string]any)
	routes := make(map[string][]NativeCapabilityRoute)
	seenClients := make(map[string]bool)
	for _, clientID := range ids {
		if seenClients[clientID] {
			continue
		}
		seenClients[clientID] = true
		for _, modelID := range r.clientModels[clientID] {
			info := r.clientModelInfos[clientID][modelID]
			if info == nil {
				continue
			}
			if _, exists := models[modelID]; !exists {
				models[modelID] = r.convertModelToMap(cloneModelInfo(info), handlerType)
				catalog.Infos[modelID] = cloneModelInfo(info)
			}
			provider := r.clientProviders[clientID]
			if catalog.ProviderInfos[modelID] == nil {
				catalog.ProviderInfos[modelID] = make(map[string]*ModelInfo)
			}
			if catalog.ProviderInfos[modelID][provider] == nil {
				catalog.ProviderInfos[modelID][provider] = cloneModelInfo(info)
			}
			routes[modelID] = append(routes[modelID], NativeCapabilityRoute{Provider: provider, NativeCapabilities: info.NativeCapabilities})
			catalog.Providers[modelID] = appendUniqueProvider(catalog.Providers[modelID], provider)
		}
	}
	modelIDs := make([]string, 0, len(models))
	for id := range models {
		modelIDs = append(modelIDs, id)
	}
	sort.Strings(modelIDs)
	for _, id := range modelIDs {
		catalog.Models = append(catalog.Models, models[id])
		catalog.WebSearch[id] = ResolveResponsesWebSearchCapability(routes[id])
	}
	return catalog
}

// ModelInfos returns the scoped model metadata in deterministic order.
func (c CredentialModelCatalog) ModelInfos() []*ModelInfo {
	ids := make([]string, 0, len(c.Infos))
	for id := range c.Infos {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	infos := make([]*ModelInfo, 0, len(ids))
	for _, id := range ids {
		infos = append(infos, cloneModelInfo(c.Infos[id]))
	}
	return infos
}

// LookupModelInfo returns only metadata registered by this catalog's clients.
// Missing entries must not fall back to the process-wide registry or built-in models.
func (c CredentialModelCatalog) LookupModelInfo(id string, provider ...string) *ModelInfo {
	if len(provider) != 0 {
		return cloneModelInfo(c.ProviderInfos[id][provider[0]])
	}
	return cloneModelInfo(c.Infos[id])
}

func appendUniqueProvider(providers []string, provider string) []string {
	for _, existing := range providers {
		if existing == provider {
			return providers
		}
	}
	return append(providers, provider)
}
