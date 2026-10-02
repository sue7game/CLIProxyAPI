package auth

import (
	"context"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/access"
)

type credentialAccessIdentity struct {
	principal access.AuthenticatedPrincipal
	internal  access.InternalOperation
}

func credentialAccessIdentityFromContext(ctx context.Context) credentialAccessIdentity {
	principal, _ := access.AuthenticatedPrincipalFromContext(ctx)
	internal, _ := access.InternalOperationFromContext(ctx)
	return credentialAccessIdentity{principal: principal, internal: internal}
}
