package management

import (
	"reflect"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"gopkg.in/yaml.v3"
)

// Operational v8 routes edit only their owned YAML fields. Serializing a whole
// runtime snapshot here would erase unrelated nulls and provider inheritance.
func (h *Handler) applyConfigV8RuntimeMutation(c *gin.Context, mutate func(*config.Config) error, project func(*configV8Document, *config.Config, *config.Config) error) bool {
	h.configApplyMu.Lock()
	defer h.configApplyMu.Unlock()
	snapshot := h.configV8Snapshot(c)
	if snapshot == nil {
		return false
	}
	candidate := snapshot.current.CloneForRuntime()
	if err := mutate(candidate); err != nil {
		writeConfigApplyError(c, err)
		return false
	}
	doc := readConfigV8Document(c, snapshot.source)
	if doc == nil {
		return false
	}
	if err := project(doc, snapshot.current, candidate); err != nil {
		writeConfigApplyError(c, err)
		return false
	}
	data, next := doc.prepare(c, snapshot.hook != nil || candidate.Grouping.Enabled)
	if next == nil {
		return false
	}
	next.Home = snapshot.current.Home
	return h.commitConfigV8(c, snapshot, data, next, nil)
}

func projectV8PluginMutation(doc *configV8Document, before, after *config.Config) error {
	for id := range before.Plugins.Configs {
		if _, exists := after.Plugins.Configs[id]; !exists {
			deleteConfigV8Path(doc.root, []string{"plugins", "configs", id})
		}
	}
	for id, item := range after.Plugins.Configs {
		if old, exists := before.Plugins.Configs[id]; exists && reflect.DeepEqual(old, item) {
			continue
		}
		value := new(yaml.Node)
		if err := value.Encode(item); err != nil {
			return &ConfigApplyError{400, "invalid_plugin_config", "plugin configuration could not be encoded"}
		}
		dst := configV8Path(doc.root, []string{"plugins", "configs", id})
		if dst == nil {
			return &ConfigApplyError{409, "plugin_config_changed", "plugin configuration path changed"}
		}
		*dst = *value
	}
	return nil
}
