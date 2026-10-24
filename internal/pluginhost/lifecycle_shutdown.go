package pluginhost

import (
	"context"
	"sort"

	log "github.com/sirupsen/logrus"
)

type pluginShutdownState struct {
	targets          []pluginUnloadTarget
	loading          map[string]*pluginLoadRequest
	loadingInstances map[string][]*hostCallbackInstance
	cleanupPending   bool
}

// ShutdownAll removes active plugin capabilities and detaches cleaned plugins.
// Plugin images stay mapped for the lifetime of the process.
func (h *Host) ShutdownAll() {
	h.ShutdownAllContext(context.Background())
}

// ShutdownAllContext clears owned runtime overrides before closing callbacks.
// Failed or canceled cleanup retains inactive clients for a later retry. Other
// clients detach without waiting beyond ctx for their active calls to complete.
func (h *Host) ShutdownAllContext(ctx context.Context) {
	if h == nil || !h.lockApply(ctx) {
		return
	}
	defer h.unlockApply()
	failed := h.shutdownRuntimeOverrideFailures(ctx)
	state := h.preparePluginShutdown(failed)
	for id, instances := range state.loadingInstances {
		h.closeHostHTTPCallbackInstances(id, instances)
	}
	h.closeShutdownHTTPResources(state)
	h.refreshThinkingProviders(nil)
	h.RegisterFrontendAuthProviders()
	for id, request := range state.loading {
		h.cleanupCanceledPluginLoad(id, request)
	}
	for _, target := range state.targets {
		shutdownPluginClient(ctx, target.client)
		log.WithFields(pluginLogFields(target.id, target.name, target.version, target.path)).Info("pluginhost: plugin unloaded")
	}
	h.closeShutdownHTTPResources(state)
}

func (h *Host) shutdownRuntimeOverrideFailures(ctx context.Context) map[string]struct{} {
	h.mu.Lock()
	ids := make([]string, 0, len(h.loaded))
	for id := range h.loaded {
		ids = append(ids, id)
	}
	h.mu.Unlock()
	sort.Strings(ids)
	failed := make(map[string]struct{})
	for _, id := range ids {
		if !h.cleanupRuntimeOverridesBeforeUnload(ctx, id) {
			failed[id] = struct{}{}
		}
	}
	return failed
}

func (h *Host) preparePluginShutdown(failed map[string]struct{}) pluginShutdownState {
	h.mu.Lock()
	defer h.mu.Unlock()
	state := pluginShutdownState{
		targets: h.collectShutdownTargetsLocked(failed), cleanupPending: len(failed) > 0,
		loading: make(map[string]*pluginLoadRequest), loadingInstances: make(map[string][]*hostCallbackInstance),
	}
	for id, request := range h.loading {
		if _, pending := failed[id]; pending {
			continue
		}
		state.loading[id] = request
		state.loadingInstances[id] = markPluginLoadClosedLocked(request)
	}
	h.retainShutdownFailuresLocked(failed)
	h.modelClientIDs = make(map[string]struct{})
	h.executorModelClientIDs = make(map[string]struct{})
	h.modelProviders = make(map[string]string)
	h.modelRegistrations = make(map[string]pluginModelRegistration)
	h.providerModels = make(map[string][]*registryModelInfo)
	h.executorProviders = make(map[string]struct{})
	h.commandLineFlags = make(map[string]commandLineFlagRecord)
	h.commandLineHits = make(map[string]struct{})
	h.managementRoutes = make(map[string]managementRouteRecord)
	h.resourceRoutes = make(map[string]resourceRouteRecord)
	h.pluginFileVersions = make(map[string]string)
	h.activePluginVersions = make(map[string]string)
	h.activePluginPaths = make(map[string]string)
	h.snapshot.Store(emptySnapshot())
	return state
}

func (h *Host) collectShutdownTargetsLocked(failed map[string]struct{}) []pluginUnloadTarget {
	targets := make([]pluginUnloadTarget, 0, len(h.loaded))
	appendTarget := func(lp *loadedPlugin) {
		if lp == nil || lp.client == nil {
			return
		}
		if _, pending := failed[lp.id]; pending {
			return
		}
		targets = append(targets, pluginUnloadTarget{
			id: lp.id, name: lp.name, path: lp.path, version: lp.version,
			client: lp.client, callbackInstance: lp.callbackInstance,
		})
	}
	for _, lp := range h.loaded {
		appendTarget(lp)
	}
	for _, retired := range h.retired {
		for _, lp := range retired {
			appendTarget(lp)
		}
	}
	return targets
}

func (h *Host) retainShutdownFailuresLocked(failed map[string]struct{}) {
	for id := range h.loaded {
		if _, pending := failed[id]; !pending {
			delete(h.loaded, id)
		}
	}
	for id := range h.retired {
		if _, pending := failed[id]; !pending {
			delete(h.retired, id)
		}
	}
	for id := range h.deactivationPending {
		if _, pending := failed[id]; !pending {
			delete(h.deactivationPending, id)
		}
	}
}

func (h *Host) closeShutdownHTTPResources(state pluginShutdownState) {
	for _, target := range state.targets {
		h.closeHostHTTPPluginResources(target.id, target.callbackInstance)
	}
	if state.cleanupPending {
		return
	}
	if h.httpOperations != nil {
		h.httpOperations.cancelAll()
	}
	if h.httpStreams != nil {
		h.httpStreams.closeAll()
	}
}
