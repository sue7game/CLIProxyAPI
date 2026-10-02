package management

import (
	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
)

type configMutationDraft struct {
	owner     *Handler
	base      *config.Config
	current   *config.Config
	hook      ConfigApplyHook
	operation string
	committed bool
}

// withConfigDraft runs only configuration mutations on a request-local handler.
// Its mutexes and config are not shared with the live handler or the service.
// File writes, auth manager updates, and plugin side effects need separate adapters.
func (h *Handler) withConfigDraft(c *gin.Context, operation string, mutate func(*Handler, *gin.Context)) bool {
	if h.configDraft != nil || !h.requiresConfigApply() {
		return false
	}
	h.configApplyMu.Lock()
	defer h.configApplyMu.Unlock()
	h.mu.Lock()
	base, hook := h.cfg, h.configApplyHook
	current := base.CloneForRuntime()
	h.mu.Unlock()
	if current == nil || hook == nil {
		writeConfigApplyError(c, &ConfigApplyError{503, "config_apply_unavailable", "synchronous configuration transaction is unavailable"})
		return true
	}
	draft := &Handler{
		cfg: current.CloneForRuntime(), configFilePath: h.configFilePath,
		configDraft: &configMutationDraft{owner: h, base: base, current: current, hook: hook, operation: operation},
	}
	mutate(draft, c)
	return true
}

func (h *Handler) commitConfigDraft(c *gin.Context) bool {
	draft := h.configDraft
	if draft.committed {
		writeConfigApplyError(c, &ConfigApplyError{500, "duplicate_config_commit", "configuration mutation already committed"})
		return false
	}
	if err := validateConfigApply(draft.current, h.cfg, nil); err != nil {
		writeConfigApplyError(c, err)
		return false
	}
	req := ConfigApplyRequest{Current: draft.current, Proposed: h.cfg, Operation: draft.operation}
	if err := draft.hook(c.Request.Context(), req); err != nil {
		writeConfigApplyError(c, err)
		return false
	}
	draft.owner.mu.Lock()
	if draft.owner.cfg == draft.base {
		draft.owner.cfg = req.Proposed.CloneForRuntime()
	}
	draft.owner.mu.Unlock()
	draft.committed = true
	return true
}
