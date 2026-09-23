package pluginhost

import (
	"bytes"
	"context"
	"sort"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
	log "github.com/sirupsen/logrus"
)

type pluginDeactivationTarget struct {
	id         string
	name       string
	path       string
	version    string
	loaded     *loadedPlugin
	client     pluginClient
	configYAML []byte
}

func (h *Host) activePluginDeactivationTargets(items map[string]runtimeItemConfig) map[string]pluginDeactivationTarget {
	if h == nil {
		return nil
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	raw := h.snapshot.Load()
	snapshot, _ := raw.(*Snapshot)
	targets := make(map[string]pluginDeactivationTarget, len(h.deactivationPending))
	for id, pending := range h.deactivationPending {
		if loaded := h.loaded[id]; loaded == nil || loaded != pending.loaded {
			delete(h.deactivationPending, id)
			continue
		}
		pending.configYAML = disabledPluginConfigYAML(items, id)
		h.deactivationPending[id] = pending
		targets[id] = pending
	}
	if snapshot == nil || len(snapshot.records) == 0 {
		return targets
	}
	for _, record := range snapshot.records {
		loaded := h.loaded[record.id]
		if loaded == nil || !loaded.registered || loaded.client == nil {
			continue
		}
		target := pluginDeactivationTarget{
			id:         record.id,
			name:       loaded.name,
			path:       loaded.path,
			version:    loaded.version,
			loaded:     loaded,
			client:     loaded.client,
			configYAML: disabledPluginConfigYAML(items, record.id),
		}
		targets[record.id] = target
		h.deactivationPending[record.id] = target
	}
	return targets
}

func disabledPluginConfigYAML(items map[string]runtimeItemConfig, id string) []byte {
	item, ok := items[id]
	if !ok {
		item = defaultRuntimeItemConfig(id)
	}
	configYAML := item.DisabledConfigYAML
	if len(configYAML) == 0 {
		configYAML = defaultRuntimeConfigYAML
	}
	return bytes.Clone(configYAML)
}

func (h *Host) deactivatePlugins(ctx context.Context, targets map[string]pluginDeactivationTarget) {
	if h == nil || len(targets) == 0 {
		return
	}
	ids := make([]string, 0, len(targets))
	for id := range targets {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		target := targets[id]
		if !h.deactivatePlugin(ctx, target) {
			continue
		}
		h.mu.Lock()
		if pending, ok := h.deactivationPending[id]; ok && pending.loaded == target.loaded {
			delete(h.deactivationPending, id)
		}
		h.mu.Unlock()
	}
}

func (h *Host) cancelPluginDeactivation(targets map[string]pluginDeactivationTarget, id string) {
	delete(targets, id)
	h.mu.Lock()
	delete(h.deactivationPending, id)
	h.mu.Unlock()
}

func (h *Host) deactivatePlugin(ctx context.Context, target pluginDeactivationTarget) bool {
	if target.client == nil {
		return false
	}
	h.mu.Lock()
	pending, pendingOK := h.deactivationPending[target.id]
	if !pendingOK || pending.loaded != target.loaded {
		h.mu.Unlock()
		return false
	}
	_, fused := h.fused[target.id]
	h.mu.Unlock()
	if fused {
		return false
	}
	var errReconfigure error
	_, okCall := h.safePluginCall(ctx, target.id, pluginabi.MethodPluginReconfigure, func() pluginapi.Plugin {
		_, errReconfigure = registerRPCPlugin(
			ctx,
			h,
			target.id,
			target.client,
			pluginabi.MethodPluginReconfigure,
			target.configYAML,
		)
		return pluginapi.Plugin{}
	})
	if !okCall {
		return false
	}
	if errReconfigure != nil {
		log.Warnf("pluginhost: plugin %s deactivation failed: %v", target.id, errReconfigure)
		return false
	}
	log.WithFields(pluginLogFields(target.id, target.name, target.version, target.path)).Info("pluginhost: plugin deactivated")
	return true
}
