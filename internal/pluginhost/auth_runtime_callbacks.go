package pluginhost

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

func (h *Host) callHostAuthSetRuntimeOverride(_ context.Context, request []byte) ([]byte, error) {
	var req pluginapi.HostAuthSetRuntimeOverrideRequest
	if errUnmarshal := json.Unmarshal(request, &req); errUnmarshal != nil {
		return nil, fmt.Errorf("decode host auth runtime override request: %w", errUnmarshal)
	}
	authIndex := strings.TrimSpace(req.AuthIndex)
	if authIndex == "" {
		return nil, fmt.Errorf("auth_index is required")
	}
	if errValidate := validateHostAuthRuntimeOverrideRequest(req); errValidate != nil {
		return nil, errValidate
	}

	manager := h.currentAuthManager()
	if manager == nil {
		return nil, fmt.Errorf("core auth manager unavailable")
	}

	auth, revisions, applied, errApply := applyHostAuthRuntimeOverrideRequest(manager, authIndex, req)
	if errApply != nil {
		return nil, fmt.Errorf("patch auth runtime override: %w", errApply)
	}

	entry := h.buildHostAuthFileEntry(auth)
	if entry == nil {
		return nil, fmt.Errorf("auth runtime info not found for auth_index %s", authIndex)
	}
	responseRevisionField := requestRuntimeOverrideRevisionField(req)
	return marshalRPCResult(pluginapi.HostAuthSetRuntimeOverrideResponse{
		Applied:         applied,
		Revision:        revisions.Revision(coreauth.RuntimeAuthOverrideField(responseRevisionField)),
		Revisions:       pluginRuntimeAuthOverrideRevisions(revisions),
		Auth:            *entry,
		RuntimeOverride: pluginRuntimeAuthOverride(auth.RuntimeAuthOverride()),
	})
}

func applyHostAuthRuntimeOverrideRequest(
	manager *coreauth.Manager,
	authIndex string,
	req pluginapi.HostAuthSetRuntimeOverrideRequest,
) (*coreauth.Auth, coreauth.RuntimeAuthOverrideRevisions, bool, error) {
	clearFields := coreRuntimeOverrideFields(req.Clear)
	override := coreauth.RuntimeAuthOverride{
		Disabled: req.Disabled,
		Priority: req.Priority,
		ProxyURL: req.ProxyURL,
	}
	if req.IfRevisions != nil {
		return manager.PatchRuntimeAuthOverrideIfRevisions(
			authIndex,
			clearFields,
			override,
			coreRuntimeAuthOverrideRevisions(*req.IfRevisions),
		)
	}
	return manager.PatchRuntimeAuthOverrideIfRevision(
		authIndex,
		clearFields,
		override,
		coreauth.RuntimeAuthOverrideField(req.IfRevisionField),
		req.IfRevision,
	)
}

func requestRuntimeOverrideRevisionField(req pluginapi.HostAuthSetRuntimeOverrideRequest) pluginapi.HostAuthRuntimeOverrideField {
	if req.IfRevisionField != "" {
		return req.IfRevisionField
	}
	fields := make(map[pluginapi.HostAuthRuntimeOverrideField]struct{}, 3)
	for _, field := range req.Clear {
		fields[field] = struct{}{}
	}
	if req.Disabled != nil {
		fields[pluginapi.HostAuthRuntimeOverrideDisabled] = struct{}{}
	}
	if req.Priority != nil {
		fields[pluginapi.HostAuthRuntimeOverridePriority] = struct{}{}
	}
	if req.ProxyURL != nil {
		fields[pluginapi.HostAuthRuntimeOverrideProxyURL] = struct{}{}
	}
	if len(fields) != 1 {
		return ""
	}
	for field := range fields {
		return field
	}
	return ""
}

func validateHostAuthRuntimeOverrideRequest(req pluginapi.HostAuthSetRuntimeOverrideRequest) error {
	if !hasHostAuthRuntimeOverride(req) && len(req.Clear) == 0 {
		return fmt.Errorf("at least one runtime override or clear field is required")
	}
	if req.Disabled != nil && !*req.Disabled {
		return fmt.Errorf("clear the disabled override instead of setting it to false")
	}
	if req.ProxyURL != nil && strings.TrimSpace(*req.ProxyURL) == "" {
		return fmt.Errorf("proxy_url cannot be empty; clear it to restore the configured proxy")
	}
	for _, field := range req.Clear {
		switch field {
		case pluginapi.HostAuthRuntimeOverrideDisabled,
			pluginapi.HostAuthRuntimeOverridePriority,
			pluginapi.HostAuthRuntimeOverrideProxyURL:
		default:
			return fmt.Errorf("unknown runtime override field: %s", field)
		}
	}
	if req.IfRevisions != nil && (req.IfRevision != nil || req.IfRevisionField != "") {
		return fmt.Errorf("if_revisions is mutually exclusive with if_revision and if_revision_field")
	}
	if req.IfRevision == nil && req.IfRevisionField != "" {
		return fmt.Errorf("if_revision_field requires if_revision")
	}
	if req.IfRevision != nil {
		switch req.IfRevisionField {
		case pluginapi.HostAuthRuntimeOverrideDisabled,
			pluginapi.HostAuthRuntimeOverridePriority,
			pluginapi.HostAuthRuntimeOverrideProxyURL:
		default:
			return fmt.Errorf("if_revision_field must identify disabled, priority, or proxy_url")
		}
	}
	return nil
}

func hasHostAuthRuntimeOverride(req pluginapi.HostAuthSetRuntimeOverrideRequest) bool {
	return req.Disabled != nil || req.Priority != nil || req.ProxyURL != nil
}

func coreRuntimeOverrideFields(fields []pluginapi.HostAuthRuntimeOverrideField) []coreauth.RuntimeAuthOverrideField {
	if len(fields) == 0 {
		return nil
	}
	out := make([]coreauth.RuntimeAuthOverrideField, 0, len(fields))
	for _, field := range fields {
		out = append(out, coreauth.RuntimeAuthOverrideField(field))
	}
	return out
}

func pluginRuntimeAuthOverride(override coreauth.RuntimeAuthOverride) pluginapi.HostAuthRuntimeOverride {
	return pluginapi.HostAuthRuntimeOverride{
		Disabled: override.Disabled,
		Priority: override.Priority,
		ProxyURL: override.ProxyURL,
	}
}

func pluginRuntimeAuthOverrideRevisions(revisions coreauth.RuntimeAuthOverrideRevisions) pluginapi.HostAuthRuntimeOverrideRevisions {
	return pluginapi.HostAuthRuntimeOverrideRevisions{
		Disabled: revisions.Disabled,
		Priority: revisions.Priority,
		ProxyURL: revisions.ProxyURL,
	}
}

func coreRuntimeAuthOverrideRevisions(revisions pluginapi.HostAuthRuntimeOverrideRevisions) coreauth.RuntimeAuthOverrideRevisions {
	return coreauth.RuntimeAuthOverrideRevisions{
		Disabled: revisions.Disabled,
		Priority: revisions.Priority,
		ProxyURL: revisions.ProxyURL,
	}
}
