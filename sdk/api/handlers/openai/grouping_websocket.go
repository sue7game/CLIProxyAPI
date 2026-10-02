package openai

import (
	"context"
	"net/http"
	"sync"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/api/handlers"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

type websocketCredentialBindings struct {
	mu          sync.Mutex
	credentials map[string]*coreauth.Auth
}

func (b *websocketCredentialBindings) remember(credential *coreauth.Auth) {
	if credential == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.credentials == nil {
		b.credentials = make(map[string]*coreauth.Auth)
	}
	if b.credentials[credential.ID] == nil {
		b.credentials[credential.ID] = credential.Clone()
	}
}

func (b *websocketCredentialBindings) authorize(ctx context.Context, h *OpenAIResponsesAPIHandler, authID string) error {
	if !h.CredentialGroupingEnabled() {
		return nil
	}
	b.mu.Lock()
	credential := b.credentials[authID]
	b.mu.Unlock()
	_, err := handlers.AuthorizeRetainedCredential(ctx, h.AuthManager, credential)
	return err
}

func (h *OpenAIResponsesAPIHandler) authorizeWebsocketTurn(ctx context.Context, pinnedID string) error {
	if !h.CredentialGroupingEnabled() {
		return nil
	}
	auths, err := h.AuthManager.AccessibleAuths(ctx)
	if err != nil {
		return err
	}
	if pinnedID != "" {
		current, ok := h.AuthManager.GetByID(pinnedID)
		if !ok || current == nil || current.EffectiveDisabled() {
			return websocketCredentialUnavailable()
		}
		return h.AuthManager.AuthorizeCredentialUse(ctx, current)
	}
	if len(auths) == 0 {
		return websocketCredentialUnavailable()
	}
	for _, auth := range auths {
		if err = h.AuthManager.AuthorizeCredentialUse(ctx, auth); err != nil {
			return err
		}
	}
	return nil
}

func websocketCredentialUnavailable() error {
	return &coreauth.Error{
		Code: "credential_access_denied", Message: "websocket credential is unavailable", HTTPStatus: http.StatusForbidden,
	}
}
