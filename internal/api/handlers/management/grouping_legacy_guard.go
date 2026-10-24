package management

import (
	"context"
	"net/http"
	"strings"
	"sync"

	"github.com/gin-gonic/gin"
)

type legacyManagementContextKey struct{}

func isLegacyManagementRequest(c *gin.Context) bool {
	return c != nil && c.Request != nil && c.Request.URL != nil &&
		strings.HasPrefix(c.Request.URL.Path, "/v0/management/")
}

func (h *Handler) requiresConfigApplyRequest(c *gin.Context) bool {
	return !isLegacyManagementRequest(c) && h.requiresConfigApply()
}

func (h *Handler) groupingEnabled() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.cfg != nil && h.cfg.Grouping.Enabled
}

func rejectLegacyGroupingWrite(c *gin.Context) {
	c.AbortWithStatusJSON(http.StatusConflict, gin.H{
		"error":   "grouping_requires_v8",
		"message": "grouping configuration and credential mutations require /v8/management",
	})
}

// BeginConfigMutationFence excludes legacy writes until a managed transaction
// has persisted and published. Call it before taking the service transaction lock.
func (h *Handler) BeginConfigMutationFence() func() {
	h.legacyMutationMu.Lock()
	return sync.OnceFunc(h.legacyMutationMu.Unlock)
}

func (h *Handler) guardLegacyGroupingRequest(c *gin.Context) (func(), bool) {
	release := func() {}
	if !isLegacyManagementRequest(c) {
		return release, false
	}
	c.Request = c.Request.WithContext(context.WithValue(c.Request.Context(), legacyManagementContextKey{}, true))
	readOnly := c.Request.Method == http.MethodGet || c.Request.Method == http.MethodHead || c.Request.Method == http.MethodOptions
	if strings.HasSuffix(c.Request.URL.Path, "-auth-url") {
		readOnly = false
	}
	if !readOnly {
		h.legacyMutationMu.RLock()
		release = h.legacyMutationMu.RUnlock
	}
	if !readOnly && h.groupingEnabled() {
		rejectLegacyGroupingWrite(c)
		return release, true
	}
	return release, false
}
