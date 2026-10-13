package pluginhost

type pluginRuntimeState struct {
	managementRoutes  map[string]managementRouteRecord
	resourceRoutes    map[string]resourceRouteRecord
	commandLineFlags  map[string]commandLineFlagRecord
	commandLineHits   map[string]struct{}
	modelProvider     string
	modelProviderSet  bool
	modelRegistration *pluginModelRegistration
	providerModels    []*registryModelInfo
	providerModelsSet bool
}

func (h *Host) capturePluginRuntimeStateLocked(id string) *pluginRuntimeState {
	state := &pluginRuntimeState{
		managementRoutes: make(map[string]managementRouteRecord),
		resourceRoutes:   make(map[string]resourceRouteRecord),
		commandLineFlags: make(map[string]commandLineFlagRecord),
		commandLineHits:  make(map[string]struct{}),
	}
	for key, record := range h.managementRoutes {
		if record.pluginID == id {
			state.managementRoutes[key] = record
		}
	}
	for key, record := range h.resourceRoutes {
		if record.pluginID == id {
			state.resourceRoutes[key] = record
		}
	}
	for name, record := range h.commandLineFlags {
		if record.pluginID == id {
			state.commandLineFlags[name] = record
			if _, hit := h.commandLineHits[name]; hit {
				state.commandLineHits[name] = struct{}{}
			}
		}
	}
	state.modelProvider, state.modelProviderSet = h.modelProviders[id]
	if registration, ok := h.modelRegistrations[id]; ok {
		state.modelRegistration = &registration
		state.providerModels, state.providerModelsSet = h.providerModels[registration.provider]
	}
	return state
}

func (h *Host) restorePluginRuntimeStateLocked(id string, state *pluginRuntimeState) {
	if state == nil {
		return
	}
	for key, record := range state.managementRoutes {
		h.managementRoutes[key] = record
	}
	for key, record := range state.resourceRoutes {
		h.resourceRoutes[key] = record
	}
	for name, record := range state.commandLineFlags {
		h.commandLineFlags[name] = record
	}
	for name := range state.commandLineHits {
		h.commandLineHits[name] = struct{}{}
	}
	if state.modelProviderSet {
		h.modelProviders[id] = state.modelProvider
	}
	if state.modelRegistration != nil {
		h.modelRegistrations[id] = *state.modelRegistration
		if state.providerModelsSet {
			h.providerModels[state.modelRegistration.provider] = state.providerModels
		}
	}
}

func (h *Host) restoreReplacementRuntime(lp *loadedPlugin, record capabilityRecord, runtime *pluginRuntimeState) {
	if runtime == nil {
		return
	}
	h.mu.Lock()
	if h.loaded[lp.id] != lp {
		h.mu.Unlock()
		return
	}
	records, enabled := h.snapshotWithoutPluginLocked(lp.id)
	records = append(records, record)
	sortRecords(records)
	h.restorePluginRuntimeStateLocked(lp.id, runtime)
	h.rebuildActivePluginMapsLocked(records)
	h.snapshot.Store(&Snapshot{enabled: enabled, records: records, quotaSupportedProviders: make(map[string][]string)})
	h.mu.Unlock()
	h.refreshThinkingProviders(records)
}
