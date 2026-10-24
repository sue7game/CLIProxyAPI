package management

import (
	"reflect"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/pluginstore"
)

const pluginConfigSideEffectsKey = "management.plugin-config-side-effects"

type pluginConfigExpectation struct {
	directory  string
	original   config.PluginInstanceConfig
	configured bool
}

func (expected pluginConfigExpectation) validate(candidate *config.Config, id string) error {
	item, present := candidate.Plugins.Configs[id]
	directory, err := config.ResolvePluginsDir(normalizedPluginsDir(candidate.Plugins.Dir))
	if err != nil || directory != expected.directory || present != expected.configured || !reflect.DeepEqual(item, expected.original) {
		return &ConfigApplyError{409, "plugin_config_changed", "plugin configuration changed during the file operation; refresh before retrying"}
	}
	return nil
}

func (h *Handler) commitInstalledPluginConfig(c *gin.Context, id string, manifest pluginstore.Manifest, path string, overwritten bool, expected pluginConfigExpectation) bool {
	c.Set(pluginConfigSideEffectsKey, gin.H{"file_installed": true, "file_overwritten": overwritten, "path": path})
	defer c.Set(pluginConfigSideEffectsKey, nil)
	return h.commitPluginConfig(c, "plugin.install", func(candidate *config.Config) error {
		if err := expected.validate(candidate, id); err != nil {
			return err
		}
		draft := &Handler{cfg: candidate}
		return draft.enablePluginConfigLocked(id, manifest)
	})
}

func (h *Handler) commitDeletedPluginConfig(c *gin.Context, id, path string, deleted bool, expected pluginConfigExpectation) bool {
	c.Set(pluginConfigSideEffectsKey, gin.H{"file_deleted": deleted, "path": path})
	defer c.Set(pluginConfigSideEffectsKey, nil)
	return h.commitPluginConfig(c, "plugin.delete", func(candidate *config.Config) error {
		if err := expected.validate(candidate, id); err != nil {
			return err
		}
		delete(candidate.Plugins.Configs, id)
		return nil
	})
}

func (h *Handler) commitPluginConfig(c *gin.Context, operation string, mutate func(*config.Config) error) bool {
	if c.GetBool(ConfigV8ContextKey) {
		return h.applyConfigV8RuntimeMutation(c, mutate, projectV8PluginMutation)
	}
	if h.requiresConfigApplyRequest(c) {
		return h.applyConfigMutation(c, operation, func(candidate *config.Config) (*APIKeyRotation, error) {
			return nil, mutate(candidate)
		})
	}
	// Legacy saves also use an isolated candidate so failed disk writes cannot
	// corrupt the shared service configuration.
	h.configApplyMu.Lock()
	defer h.configApplyMu.Unlock()
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.cfg == nil {
		writeConfigApplyError(c, &ConfigApplyError{503, "config_unavailable", "configuration is unavailable"})
		return false
	}
	candidate := h.cfg.CloneForRuntime()
	if err := mutate(candidate); err != nil {
		writeConfigApplyError(c, err)
		return false
	}
	if err := config.SaveConfigPreserveComments(h.configFilePath, candidate); err != nil {
		writeConfigApplyError(c, &ConfigApplyError{500, "config_save_failed", "plugin file operation completed but saving configuration failed"})
		return false
	}
	h.cfg = candidate
	h.reloadConfigAfterManagementSaveAsync(c.Request.Context(), h.reloadSnapshotConfigLocked())
	return true
}
