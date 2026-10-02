package pluginhost

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/access"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

func (h *Host) authorizePluginCredential(ctx context.Context, auth *coreauth.Auth) error {
	if err := h.authorizeHostCredential(ctx, auth); err != nil {
		return err
	}
	manager := h.currentAuthManager()
	if manager == nil || !manager.CredentialAccessPolicyEnabled() {
		return nil
	}
	if auth == nil {
		return groupingCallbackDenied()
	}
	if _, trusted := access.InternalOperationFromContext(ctx); trusted {
		return nil
	}
	return validateGroupingCredentialPayload(auth)
}

func validateGroupingCredentialPayload(auth *coreauth.Auth) error {
	raw, ok := auth.Storage.(interface{ RawJSON() []byte })
	if !ok {
		return nil
	}
	var metadata map[string]any
	data := raw.RawJSON()
	if len(data) == 0 {
		return nil
	}
	if err := json.Unmarshal(data, &metadata); err != nil || metadata == nil {
		return groupingCallbackDenied()
	}
	if metadata["type"] == nil {
		metadata["type"] = auth.Provider
	}
	coreauth.NormalizeCredentialMetadata(metadata)
	if !reflect.DeepEqual(metadata, auth.Metadata) {
		return groupingCallbackDenied()
	}
	// A virtual credential may serialize only its independently identified record.
	if coreauth.IsPluginVirtualAuth(auth) {
		id := strings.TrimSpace(auth.Attributes["grouping_id"])
		if id == "" || metadata["grouping_id"] != id {
			return groupingCallbackDenied()
		}
	}
	return nil
}
