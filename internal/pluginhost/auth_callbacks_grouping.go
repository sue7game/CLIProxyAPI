package pluginhost

import (
	"context"
	"encoding/json"
	"os"
	"reflect"
	"sort"
	"strings"

	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

func (h *Host) listAuthorizedAuthFiles(ctx context.Context) ([]pluginapi.HostAuthFileEntry, error) {
	manager := h.currentAuthManager()
	if manager == nil || !manager.CredentialAccessPolicyEnabled() {
		return h.listAuthFiles()
	}
	auths, err := manager.AccessibleAuths(ctx)
	if err != nil {
		return nil, err
	}
	entries := make([]pluginapi.HostAuthFileEntry, 0, len(auths))
	for _, auth := range auths {
		if errAccess := manager.AuthorizeCredentialUse(ctx, auth); errAccess != nil {
			return nil, errAccess
		}
		if entry := h.buildHostAuthFileEntry(auth); entry != nil {
			entries = append(entries, *entry)
		}
	}
	sort.Slice(entries, func(i, j int) bool { return strings.ToLower(entries[i].Name) < strings.ToLower(entries[j].Name) })
	return entries, nil
}

func (h *Host) authorizedAuthByIndex(ctx context.Context, index string) (*coreauth.Auth, error) {
	auth, err := h.authByIndex(index)
	if err != nil {
		return nil, err
	}
	if errAccess := h.authorizeHostCredential(ctx, auth); errAccess != nil {
		return nil, errAccess
	}
	return auth, nil
}

func (h *Host) authorizedAuthPhysicalJSONByIndex(ctx context.Context, index string) (*coreauth.Auth, []byte, error) {
	manager := h.currentAuthManager()
	if manager == nil || !manager.CredentialAccessPolicyEnabled() {
		return h.authPhysicalJSONByIndex(index)
	}
	auth, err := h.authorizedAuthByIndex(ctx, index)
	if err != nil {
		return nil, nil, err
	}
	if errSource := h.authorizeSingleCredentialSource(auth); errSource != nil {
		return nil, nil, errSource
	}
	current, data, errRead := h.authPhysicalJSONByIndex(index)
	if errRead != nil {
		return nil, nil, errRead
	}
	if errAccess := h.authorizeHostCredential(ctx, current); errAccess != nil {
		return nil, nil, errAccess
	}
	if errSource := h.authorizeSingleCredentialSource(current); errSource != nil {
		return nil, nil, errSource
	}
	var metadata map[string]any
	if errJSON := json.Unmarshal(data, &metadata); errJSON != nil {
		return nil, nil, errJSON
	}
	coreauth.NormalizeCredentialMetadata(metadata)
	// A replaced file must not expose credentials that are not the authorized snapshot.
	if !reflect.DeepEqual(metadata, current.Metadata) {
		return nil, nil, groupingCallbackDenied()
	}
	return current, data, nil
}

func (h *Host) authorizeSingleCredentialSource(auth *coreauth.Auth) error {
	if auth == nil || coreauth.IsPluginVirtualAuth(auth) {
		return groupingCallbackDenied()
	}
	path := strings.TrimSpace(authAttribute(auth, coreauth.AttributePath))
	if path == "" {
		return groupingCallbackDenied()
	}
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	for _, candidate := range h.currentAuthManager().List() {
		if candidate == nil || candidate.ID == auth.ID {
			continue
		}
		otherPath := strings.TrimSpace(authAttribute(candidate, coreauth.AttributePath))
		if otherPath == "" {
			continue
		}
		if otherPath == path {
			return groupingCallbackDenied()
		}
		other, errStat := os.Stat(otherPath)
		if errStat != nil && !os.IsNotExist(errStat) {
			return errStat
		}
		if errStat == nil && os.SameFile(info, other) {
			return groupingCallbackDenied()
		}
	}
	return nil
}
