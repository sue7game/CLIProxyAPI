package pluginhost

import (
	"context"
	"encoding/json"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/access"
)

func (h *Host) authorizeGroupingMutation(ctx context.Context, request []byte) (context.Context, error) {
	manager, err := h.groupingAccessManager()
	if err != nil {
		return nil, err
	}
	if manager == nil || !manager.CredentialAccessPolicyEnabled() {
		return ctx, nil
	}
	var req struct {
		HostCallbackID string `json:"host_callback_id,omitempty"`
	}
	if err := json.Unmarshal(request, &req); err != nil {
		return nil, groupingCallbackDenied()
	}
	resolved, err := h.resolveGroupingCallbackContext(ctx, req.HostCallbackID)
	if err != nil {
		return nil, err
	}
	if _, trusted := access.InternalOperationFromContext(resolved); !trusted {
		return nil, groupingCallbackDenied()
	}
	return resolved, nil
}
