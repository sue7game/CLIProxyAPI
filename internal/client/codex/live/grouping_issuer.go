package live

import (
	"context"
	"net/http"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/access"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

func (h *Handler) groupingClientSecretIssuer(ctx context.Context) (access.AuthenticatedPrincipal, error) {
	principal, exists := access.AuthenticatedPrincipalFromContext(ctx)
	if !exists {
		return principal, &auth.Error{Code: "credential_access_denied", Message: "trusted Realtime issuer is required", HTTPStatus: http.StatusForbidden}
	}
	_, err := h.authManager.AccessibleAuths(ctx)
	return principal, err
}
