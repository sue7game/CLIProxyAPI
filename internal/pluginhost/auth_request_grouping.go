package pluginhost

import (
	"context"
	"net/http"
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/access"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

func groupingCallbackDenied() error {
	return coreauth.NewCredentialAccessError(&coreauth.Error{Code: "credential_access_denied", Message: "credential callback is unavailable for this request", HTTPStatus: http.StatusForbidden})
}

func (h *Host) groupingAccessManager() (*coreauth.Manager, error) {
	manager := h.currentAuthManager()
	cfg := h.currentRuntimeConfig()
	if cfg != nil && cfg.Grouping.Enabled && (manager == nil || !manager.CredentialAccessPolicyEnabled()) {
		return nil, coreauth.NewCredentialAccessError(&coreauth.Error{Code: "credential_policy_unavailable", Message: "credential access policy is unavailable", HTTPStatus: http.StatusServiceUnavailable})
	}
	return manager, nil
}

func (h *Host) resolveGroupingCallbackContext(ctx context.Context, callbackID string) (context.Context, error) {
	manager, err := h.groupingAccessManager()
	if err != nil {
		return nil, err
	}
	if manager == nil || !manager.CredentialAccessPolicyEnabled() {
		return h.resolveCallbackContext(callbackID, ctx), nil
	}
	callbackID = strings.TrimSpace(callbackID)
	caller := hostCallbackPluginIDFromContext(ctx)
	if callbackID == "" || caller == "" || h.callbackContexts == nil {
		return nil, groupingCallbackDenied()
	}
	registry := h.callbackContexts
	registry.mu.RLock()
	entry, exists := registry.contexts[callbackID]
	registry.mu.RUnlock()
	if !exists || entry.ctx == nil || entry.pluginID == "" || entry.pluginID != caller {
		return nil, groupingCallbackDenied()
	}
	if instance := hostCallbackInstanceFromContext(ctx); entry.instance != instance || (instance != nil && instance.closed.Load()) {
		return nil, groupingCallbackDenied()
	}
	if err := entry.ctx.Err(); err != nil {
		return nil, err
	}
	return entry.ctx, nil
}

func (h *Host) authorizeHostCredential(ctx context.Context, auth *coreauth.Auth) error {
	manager, err := h.groupingAccessManager()
	if err != nil {
		return err
	}
	if manager == nil {
		return nil
	}
	return manager.AuthorizeCredentialUse(ctx, auth)
}

func (h *Host) authorizeHostHTTP(ctx context.Context, auth *coreauth.Auth) error {
	manager, err := h.groupingAccessManager()
	if err != nil {
		return err
	}
	if manager == nil || !manager.CredentialAccessPolicyEnabled() {
		return nil
	}
	if auth == nil {
		if _, trusted := access.InternalOperationFromContext(ctx); trusted {
			return nil
		}
		return groupingCallbackDenied()
	}
	return manager.AuthorizeCredentialUse(ctx, auth)
}
