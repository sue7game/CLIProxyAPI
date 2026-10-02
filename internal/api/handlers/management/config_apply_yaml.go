package management

import (
	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/util"
)

func (h *Handler) putConfigYAMLWithApply(c *gin.Context, raw []byte, enabled bool) bool {
	if !h.requiresConfigApply() && !enabled {
		return false
	}
	proposed, err := config.ParseConfigBytes(raw)
	if err != nil {
		c.JSON(422, gin.H{"error": "invalid_config", "message": "configuration validation failed"})
		return true
	}
	proposed.AuthDir, err = util.ResolveAuthDir(proposed.AuthDir)
	if err != nil {
		c.JSON(422, gin.H{"error": "invalid_auth_dir", "message": "credential directory could not be resolved"})
		return true
	}
	if h.applyConfigMutation(c, "config.yaml.put", func(candidate *config.Config) (*APIKeyRotation, error) {
		currentAuthDir, err := util.ResolveAuthDir(candidate.AuthDir)
		if err != nil {
			return nil, &ConfigApplyError{503, "auth_dir_unavailable", "current credential directory could not be resolved"}
		}
		if currentAuthDir != proposed.AuthDir {
			return nil, &ConfigApplyError{409, "auth_dir_change_requires_restart", "changing the credential directory requires a restart"}
		}
		// Home is runtime-only and cannot be erased by an uploaded YAML document.
		proposed.Home = candidate.Home
		*candidate = *proposed.CloneForRuntime()
		return nil, nil
	}) {
		c.JSON(200, gin.H{"ok": true, "changed": []string{"config"}})
	}
	return true
}
