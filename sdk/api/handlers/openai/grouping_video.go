package openai

import (
	"context"
	"net/http"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/api/handlers"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

func (h *OpenAIAPIHandler) authorizeVideoBinding(ctx context.Context, videoID string) error {
	if !h.CredentialGroupingEnabled() {
		return nil
	}
	_, err := h.groupedVideoCredential(ctx, videoID)
	return err
}

func (h *OpenAIAPIHandler) groupedVideoCredential(ctx context.Context, videoID string) (*coreauth.Auth, error) {
	binding, exists := videoAuthBindings.getBinding(videoID)
	if !exists {
		return nil, videoBindingUnavailable()
	}
	if binding.credential == nil || binding.credential.ID != binding.authID {
		return nil, videoBindingUnavailable()
	}
	return handlers.AuthorizeRetainedCredential(ctx, h.AuthManager, binding.credential)
}

func (h *OpenAIAPIHandler) authorizedVideoContext(ctx context.Context, videoID string) (context.Context, error) {
	if !h.CredentialGroupingEnabled() {
		return h.contextWithVideoAuthBinding(ctx, videoID), nil
	}
	credential, err := h.groupedVideoCredential(ctx, videoID)
	if err != nil {
		return ctx, err
	}
	return handlers.WithPinnedAuthID(ctx, credential.ID), nil
}

func videoBindingUnavailable() error {
	return &coreauth.Error{
		Code: "video_credential_unavailable", Message: "video credential binding is unavailable", HTTPStatus: http.StatusForbidden,
	}
}
