package handlers

import (
	"context"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/clienterror"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/interfaces"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
)

// CredentialGroupingEnabled reports whether mandatory credential policy is installed.
func (h *BaseAPIHandler) CredentialGroupingEnabled() bool {
	return h != nil && h.AuthManager != nil && h.AuthManager.CredentialAccessPolicyEnabled()
}

// RequestModelCatalog derives a fresh catalog from trusted request authorization.
// A policy error is returned, never replaced with the global catalog.
func (h *BaseAPIHandler) RequestModelCatalog(ctx context.Context, format string) (registry.CredentialModelCatalog, error) {
	r := registry.GetGlobalRegistry()
	if !h.CredentialGroupingEnabled() {
		return registry.CredentialModelCatalog{Models: r.GetAvailableModels(format)}, nil
	}
	auths, err := h.AuthManager.AccessibleAuths(ctx)
	if err != nil {
		return registry.CredentialModelCatalog{}, err
	}
	ids := make([]string, 0, len(auths))
	for _, auth := range auths {
		ids = append(ids, auth.ID)
	}
	catalog := r.ModelsForClients(format, ids)
	for _, auth := range auths {
		if _, err = AuthorizeRetainedCredential(ctx, h.AuthManager, auth); err != nil {
			return registry.CredentialModelCatalog{}, err
		}
	}
	return catalog, nil
}

// ModelsForRequest writes authorization failures and otherwise returns scoped models.
func (h *BaseAPIHandler) ModelsForRequest(c *gin.Context, format string) ([]map[string]any, bool) {
	ctx := context.Background()
	if c.Request != nil {
		ctx = c.Request.Context()
	}
	catalog, err := h.RequestModelCatalog(ctx, format)
	if err != nil {
		h.WriteCredentialAccessError(c, err)
		return nil, false
	}
	if h.CredentialGroupingEnabled() {
		c.Header("Cache-Control", "no-store")
	}
	return catalog.Models, true
}

// WriteCredentialAccessError emits a bounded error without credential details.
func (h *BaseAPIHandler) WriteCredentialAccessError(c *gin.Context, err error) {
	h.WriteErrorResponse(c, &interfaces.ErrorMessage{
		StatusCode: clienterror.HTTPStatusFromErrorOr(err, http.StatusForbidden), Error: err,
	})
}
