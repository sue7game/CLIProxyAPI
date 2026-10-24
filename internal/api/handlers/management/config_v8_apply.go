package management

import (
	"bytes"
	"net/http"
	"os"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/util"
)

type configV8ApplySnapshot struct {
	base    *config.Config
	current *config.Config
	hook    ConfigApplyHook
	source  []byte
}

func (h *Handler) configV8Snapshot(c *gin.Context) *configV8ApplySnapshot {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.cfg == nil {
		writeConfigApplyError(c, &ConfigApplyError{503, "config_apply_unavailable", "configuration is unavailable"})
		return nil
	}
	source, err := os.ReadFile(h.configFilePath)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "read_failed"})
		return nil
	}
	if !checkConfigV8ETag(c, source, false) {
		return nil
	}
	return &configV8ApplySnapshot{base: h.cfg, current: h.cfg.CloneForRuntime(), hook: h.configApplyHook, source: source}
}

func (h *Handler) commitConfigV8(c *gin.Context, snapshot *configV8ApplySnapshot, canonical []byte, next *config.Config, rotation *APIKeyRotation) bool {
	if err := validateConfigApply(snapshot.current, next, rotation); err != nil {
		writeConfigApplyError(c, err)
		return false
	}
	managed := snapshot.hook != nil || snapshot.current.Grouping.Enabled || next.Grouping.Enabled
	if !managed {
		return h.commitUnmanagedConfigV8(c, snapshot, canonical, next)
	}
	if snapshot.hook == nil {
		writeConfigApplyError(c, &ConfigApplyError{503, "config_apply_unavailable", "synchronous configuration transaction is unavailable"})
		return false
	}
	if !checkConfigV8ETag(c, snapshot.source, rotation == nil && removedV8Identity(snapshot.current, next)) {
		return false
	}
	if err := validateConfigV8AuthDir(snapshot.current, next); err != nil {
		writeConfigApplyError(c, err)
		return false
	}
	req := ConfigApplyRequest{
		Current: snapshot.current, Proposed: next, Operation: "config.v8." + strings.ToLower(c.Request.Method),
		TokenRotation: rotation, SourceYAML: append([]byte(nil), snapshot.source...), CanonicalYAML: append([]byte(nil), canonical...),
	}
	if err := snapshot.hook(c.Request.Context(), req); err != nil {
		writeConfigApplyError(c, err)
		return false
	}
	h.mu.Lock()
	if h.cfg == snapshot.base {
		h.cfg = req.Proposed.CloneForRuntime()
	}
	h.mu.Unlock()
	return true
}

func (h *Handler) commitUnmanagedConfigV8(c *gin.Context, snapshot *configV8ApplySnapshot, canonical []byte, next *config.Config) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	current, err := os.ReadFile(h.configFilePath)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "read_failed"})
		return false
	}
	if h.cfg != snapshot.base || !bytes.Equal(current, snapshot.source) {
		c.JSON(http.StatusConflict, gin.H{"error": "config_changed", "message": "configuration changed; refresh before retrying"})
		return false
	}
	// Preserve the canonical tree and the inode of mounted configuration files.
	if err = WriteConfig(h.configFilePath, canonical); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "write_failed"})
		return false
	}
	h.cfg = next
	h.reloadConfigAfterManagementSaveAsync(c.Request.Context(), h.reloadSnapshotConfigLocked())
	return true
}

func validateConfigV8AuthDir(current, next *config.Config) error {
	before, err := util.ResolveAuthDir(current.AuthDir)
	if err != nil {
		return &ConfigApplyError{503, "auth_dir_unavailable", "current credential directory could not be resolved"}
	}
	after, err := util.ResolveAuthDir(next.AuthDir)
	if err != nil {
		return &ConfigApplyError{422, "invalid_auth_dir", "credential directory could not be resolved"}
	}
	if before != after {
		return &ConfigApplyError{409, "auth_dir_change_requires_restart", "changing the credential directory requires a restart"}
	}
	next.AuthDir = after
	return nil
}

func checkConfigV8ETag(c *gin.Context, source []byte, required bool) bool {
	values := c.Request.Header.Values("If-Match")
	hash := config.ComputeSourceHash(source)
	if required && len(values) == 0 {
		c.Header("ETag", configV8ETag(hash))
		c.JSON(http.StatusPreconditionRequired, gin.H{"error": "config_precondition_required", "message": "read the configuration and send its ETag in If-Match before removing identities"})
		return false
	}
	// Identity removal additionally needs a concrete version, not a wildcard.
	if !ifMatchSatisfied(values, hash) || required && strings.TrimSpace(strings.Join(values, ",")) == "*" {
		c.Header("ETag", configV8ETag(hash))
		c.JSON(http.StatusPreconditionFailed, gin.H{"error": "precondition_failed", "message": "configuration changed; refresh before retrying"})
		return false
	}
	return true
}

func removedV8Identity(before, after *config.Config) bool {
	afterTokens := make(map[string]bool, len(after.APIKeys))
	for _, token := range after.APIKeys {
		afterTokens[token] = true
	}
	for _, token := range before.APIKeys {
		if !afterTokens[token] {
			return true
		}
	}
	afterCredentials := config.GroupingCredentialSources(after)
	for id := range config.GroupingCredentialSources(before) {
		if _, exists := afterCredentials[id]; !exists {
			return true
		}
	}
	return false
}
