package pluginhost

import (
	"context"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
)

const (
	runtimeOverrideUnused uint32 = iota
	runtimeOverrideOwned
	runtimeOverrideRetiring
)

func (instance *hostCallbackInstance) registerRuntimeOverrideUse() bool {
	instance.runtimeOverrideState.CompareAndSwap(runtimeOverrideUnused, runtimeOverrideOwned)
	return instance.runtimeOverrideState.Load() == runtimeOverrideOwned
}

func (instance *hostCallbackInstance) needsRuntimeOverrideCleanup() bool {
	// Freeze first-use writes atomically when retirement can skip cleanup.
	instance.runtimeOverrideState.CompareAndSwap(runtimeOverrideUnused, runtimeOverrideRetiring)
	return instance.runtimeOverrideState.Load() == runtimeOverrideOwned
}

func (h *Host) cleanupRuntimeOverrideOwner(ctx context.Context, lp *loadedPlugin) bool {
	if lp != nil && lp.callbackInstance != nil {
		lp.callbackInstance.revokeMaintenanceCallback()
	}
	if lp == nil || lp.callbackInstance == nil || !lp.callbackInstance.needsRuntimeOverrideCleanup() {
		return true
	}
	item := config.PluginInstanceConfig{}
	if cfg := h.currentRuntimeConfig(); cfg != nil {
		item = cfg.Plugins.Configs[lp.id]
	}
	target := pluginDeactivationTarget{
		id: lp.id, name: lp.name, path: lp.path, version: lp.version,
		loaded: lp, client: lp.client, configYAML: runtimeConfigYAML(item, false),
	}
	h.mu.Lock()
	if h.loaded[lp.id] != lp {
		h.mu.Unlock()
		return false
	}
	if pending, ok := h.deactivationPending[lp.id]; ok && pending.loaded == lp {
		target.runtime = pending.runtime
	}
	if target.runtime == nil {
		target.runtime = h.capturePluginRuntimeStateLocked(lp.id)
	}
	h.deactivationPending[lp.id] = target
	records, enabled := h.snapshotWithoutPluginLocked(lp.id)
	h.removePluginRuntimeStateLocked(lp.id)
	h.snapshot.Store(&Snapshot{enabled: enabled, records: records})
	h.mu.Unlock()
	h.refreshThinkingProviders(records)
	return h.deactivatePlugin(ctx, target)
}

func (h *Host) cleanupRuntimeOverridesBeforeUnload(ctx context.Context, id string) bool {
	h.mu.Lock()
	loaded := h.loaded[id]
	h.mu.Unlock()
	return h.cleanupRuntimeOverrideOwner(ctx, loaded)
}
