package pluginhost

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

func (h *Host) callHostAuthModels(ctx context.Context, request []byte) ([]byte, error) {
	var req pluginapi.HostAuthModelsRequest
	if len(bytesTrimSpace(request)) > 0 {
		if errUnmarshal := json.Unmarshal(request, &req); errUnmarshal != nil {
			return nil, fmt.Errorf("decode host auth models request: %w", errUnmarshal)
		}
	}
	ctx, errContext := h.resolveGroupingCallbackContext(ctx, req.HostCallbackID)
	if errContext != nil {
		return nil, errContext
	}
	auths, errList := h.authModelQueryCredentials(ctx, strings.TrimSpace(req.AuthIndex))
	if errList != nil {
		return nil, errList
	}
	credentials := make([]pluginapi.HostAuthModels, 0, len(auths))
	for _, auth := range auths {
		if auth == nil {
			continue
		}
		if errAccess := h.authorizeHostCredential(ctx, auth); errAccess != nil {
			return nil, errAccess
		}
		credentials = append(credentials, buildHostAuthModels(auth, registry.GetGlobalRegistry()))
	}
	sort.Slice(credentials, func(i, j int) bool {
		leftID := strings.ToLower(credentials[i].ID)
		rightID := strings.ToLower(credentials[j].ID)
		if leftID != rightID {
			return leftID < rightID
		}
		if credentials[i].ID != credentials[j].ID {
			return credentials[i].ID < credentials[j].ID
		}
		return credentials[i].AuthIndex < credentials[j].AuthIndex
	})
	return marshalRPCResult(pluginapi.HostAuthModelsResponse{Credentials: credentials})
}

func (h *Host) authModelQueryCredentials(ctx context.Context, authIndex string) ([]*coreauth.Auth, error) {
	if authIndex != "" {
		auth, errGet := h.authorizedAuthByIndex(ctx, authIndex)
		if errGet != nil {
			return nil, errGet
		}
		return []*coreauth.Auth{auth}, nil
	}
	manager, errPolicy := h.groupingAccessManager()
	if errPolicy != nil || manager == nil {
		return nil, errPolicy
	}
	if manager.CredentialAccessPolicyEnabled() {
		return manager.AccessibleAuths(ctx)
	}
	return manager.List(), nil
}

func buildHostAuthModels(auth *coreauth.Auth, reg *registry.ModelRegistry) pluginapi.HostAuthModels {
	auth.EnsureIndex()
	var regModels []*registry.ModelInfo
	if reg != nil && strings.TrimSpace(auth.ID) != "" {
		regModels = reg.GetModelsForClient(auth.ID)
	}
	models := make([]string, 0, len(regModels))
	for _, model := range regModels {
		if model != nil {
			if id := strings.TrimSpace(model.ID); id != "" {
				models = append(models, id)
			}
		}
	}
	return pluginapi.HostAuthModels{
		ID: auth.ID, AuthIndex: auth.Index, Provider: strings.TrimSpace(auth.Provider), Models: models,
	}
}
