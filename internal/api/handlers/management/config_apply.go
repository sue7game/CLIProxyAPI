package management

import (
	"context"
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
)

// APIKeyRotation identifies an explicit replacement of one existing API token.
// These fields contain secrets and must not be logged or included in responses.
type APIKeyRotation struct {
	Old string `json:"-" yaml:"-"`
	New string `json:"-" yaml:"-"`
}

// ConfigApplyRequest contains isolated snapshots for a synchronous configuration
// transaction. The controller must reject stale Current snapshots, validate all
// identities and deployment modes, persist atomically, and publish runtime state
// before returning nil. It must not modify shared state on rejection.
type ConfigApplyRequest struct {
	Current       *config.Config
	Proposed      *config.Config
	Operation     string
	TokenRotation *APIKeyRotation
	// SourceYAML is the exact persisted document read before a v8 mutation.
	// CanonicalYAML retains explicit nulls, empty maps, and opaque plugin fields.
	// The controller must compare SourceYAML before committing CanonicalYAML,
	// filling only generated grouping identities via PrepareGroupingConfigDocument.
	// Both contain secrets and must never be logged or exposed in responses.
	SourceYAML    []byte `json:"-" yaml:"-"`
	CanonicalYAML []byte `json:"-" yaml:"-"`
}

// ConfigApplyHook commits a managed configuration mutation synchronously.
// It is invoked without Handler.mu held and may call Handler.SetConfig.
// It must not synchronously re-enter a management configuration mutation.
type ConfigApplyHook func(context.Context, ConfigApplyRequest) error

// ConfigApplyError provides a safe client-facing failure from a config transaction.
// Message must not include API keys, credentials, or raw configuration values.
type ConfigApplyError struct {
	StatusCode int
	Code       string
	Message    string
}

// Error returns the safe client-facing explanation.
func (e *ConfigApplyError) Error() string { return e.Message }

// SetConfigApplyHook installs the synchronous transaction owner. Installing it
// does not enable grouping and does not intercept unadapted legacy write handlers.
func (h *Handler) SetConfigApplyHook(hook ConfigApplyHook) {
	if h == nil {
		return
	}
	h.mu.Lock()
	h.configApplyHook = hook
	h.mu.Unlock()
}

func (h *Handler) requiresConfigApply() bool {
	if h == nil {
		return false
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.configApplyHook != nil || h.cfg != nil && h.cfg.Grouping.Enabled
}

func (h *Handler) applyConfigMutation(c *gin.Context, operation string, mutate func(*config.Config) (*APIKeyRotation, error)) bool {
	h.configApplyMu.Lock()
	defer h.configApplyMu.Unlock()
	h.mu.Lock()
	base, hook := h.cfg, h.configApplyHook
	current := base.CloneForRuntime()
	h.mu.Unlock()
	if current == nil || hook == nil {
		writeConfigApplyError(c, &ConfigApplyError{503, "config_apply_unavailable", "synchronous configuration transaction is unavailable"})
		return false
	}
	proposed := current.CloneForRuntime()
	rotation, err := mutate(proposed)
	if err == nil {
		err = validateConfigApply(current, proposed, rotation)
	}
	if err != nil {
		writeConfigApplyError(c, err)
		return false
	}
	req := ConfigApplyRequest{Current: current, Proposed: proposed, Operation: operation, TokenRotation: rotation}
	if err = hook(c.Request.Context(), req); err != nil {
		writeConfigApplyError(c, err)
		return false
	}
	h.mu.Lock()
	// A controller callback may already have published an authoritative snapshot.
	if h.cfg == base {
		h.cfg = proposed.CloneForRuntime()
	}
	h.mu.Unlock()
	return true
}

func validateConfigApply(current, proposed *config.Config, rotation *APIKeyRotation) error {
	if err := config.ValidateGroupingMode(proposed); err != nil {
		return &ConfigApplyError{409, "unsupported_grouping_mode", err.Error()}
	}
	// The transaction owner distinguishes controlled additions from lost identities,
	// allocates UUIDs for new sources, and validates before any persistent mutation.
	if current.Grouping.Enabled || proposed.Grouping.Enabled {
		return validateAPIKeyTransition(current.APIKeys, proposed.APIKeys, rotation)
	}
	return nil
}

func writeConfigApplyError(c *gin.Context, err error) {
	var failure *ConfigApplyError
	if errors.As(err, &failure) {
		status := failure.StatusCode
		if status < 400 || status > 599 {
			status = http.StatusInternalServerError
		}
		writeConfigApplyFailure(c, status, gin.H{"error": failure.Code, "message": failure.Message})
		return
	}
	writeConfigApplyFailure(c, http.StatusInternalServerError, gin.H{"error": "config_apply_failed", "message": "configuration transaction failed; no success has been reported"})
}

func writeConfigApplyFailure(c *gin.Context, status int, body gin.H) {
	if effects, ok := c.Get(pluginConfigSideEffectsKey); ok && effects != nil {
		body["side_effects"] = effects
		body["recovery_required"] = true
	}
	c.JSON(status, body)
}
