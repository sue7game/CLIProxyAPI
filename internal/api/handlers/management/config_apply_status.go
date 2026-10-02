package management

import (
	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

func (h *Handler) applyConfigAuthStatus(c *gin.Context, auth *coreauth.Auth, disabled bool) bool {
	if c.GetBool(ConfigV8ContextKey) {
		return h.applyConfigAuthStatusV8(c, auth, disabled)
	}
	if !h.requiresConfigApply() {
		return false
	}
	if h.applyConfigMutation(c, "config-credential.status", func(candidate *config.Config) (*APIKeyRotation, error) {
		handled, err := toggleConfigAPIKeyExcludedAll(candidate, auth, disabled)
		if err != nil {
			return nil, &ConfigApplyError{409, "credential_status_failed", "configuration credential status could not be changed"}
		}
		if !handled {
			return nil, &ConfigApplyError{404, "credential_not_found", "configuration credential was not found"}
		}
		return nil, nil
	}) {
		c.JSON(200, gin.H{"status": "ok", "disabled": disabled, "via": "config:excluded-models", "excluded_pattern": configAPIKeyDisablePattern})
	}
	return true
}
