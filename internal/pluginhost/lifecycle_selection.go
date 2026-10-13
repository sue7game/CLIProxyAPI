package pluginhost

import (
	"context"
	"sort"
	"strings"
)

// detachUnselectedPlugins stops unselected plugins without pending cleanup.
// Active plugins must first clear their runtime overrides in deactivatePlugins.
// Caller must hold the apply lock; nil selects no plugins.
func (h *Host) detachUnselectedPlugins(ctx context.Context, selected map[string]struct{}) {
	if h == nil {
		return
	}
	h.mu.Lock()
	ids := make([]string, 0, len(h.loaded)+len(h.retired)+len(h.loading))
	for id := range h.loaded {
		ids = append(ids, id)
	}
	for id := range h.retired {
		ids = append(ids, id)
	}
	for id := range h.loading {
		ids = append(ids, id)
	}
	h.mu.Unlock()
	sort.Strings(ids)

	seen := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		if _, ok := selected[id]; ok {
			continue
		}
		if h.pluginDeactivationPending(id) {
			continue
		}
		h.detachPlugin(ctx, id)
	}
}

func enabledPluginIDs(files []pluginFile, items map[string]runtimeItemConfig) map[string]struct{} {
	ids := make(map[string]struct{}, len(files))
	for _, file := range files {
		id := strings.TrimSpace(file.ID)
		if id == "" {
			continue
		}
		item, ok := items[id]
		if !ok {
			item = defaultRuntimeItemConfig(id)
		}
		if !item.Enabled {
			continue
		}
		ids[id] = struct{}{}
	}
	return ids
}
