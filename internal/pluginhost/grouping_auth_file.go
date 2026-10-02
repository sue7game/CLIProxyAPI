package pluginhost

import (
	"bytes"
	"context"
	"net/http"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/access"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

// GroupingAuthFileApplier atomically persists file identity, policy and runtime state.
// Success must mean the grouping-aware host transaction has already been applied.
type GroupingAuthFileApplier func(context.Context, string, []byte) (string, error)

// SetGroupingAuthFileApplier installs the trusted host's credential write transaction.
// A nil applier refuses plugin file writes while credential grouping is enabled.
func (h *Host) SetGroupingAuthFileApplier(applier GroupingAuthFileApplier) {
	if h == nil {
		return
	}
	h.mu.Lock()
	h.groupingAuthFileApplier = applier
	h.mu.Unlock()
}

func (h *Host) applyGroupingAuthFile(ctx context.Context, name string, data []byte) (string, bool, error) {
	manager, err := h.groupingAccessManager()
	if err != nil {
		return "", true, err
	}
	if manager == nil || !manager.CredentialAccessPolicyEnabled() {
		return "", false, nil
	}
	if _, trusted := access.InternalOperationFromContext(ctx); !trusted {
		return "", true, groupingCallbackDenied()
	}
	h.mu.Lock()
	applier := h.groupingAuthFileApplier
	h.mu.Unlock()
	if applier == nil {
		return "", true, coreauth.NewCredentialAccessError(&coreauth.Error{Code: "credential_write_unavailable", Message: "grouping-aware credential writes are unavailable", HTTPStatus: http.StatusServiceUnavailable})
	}
	path, err := applier(ctx, name, bytes.Clone(data))
	return path, true, coreauth.NewCredentialAccessError(err)
}
