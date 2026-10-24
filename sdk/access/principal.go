package access

import "context"

type authenticatedPrincipalKey struct{}

// AuthenticatedPrincipal identifies a subject verified by a server-side provider.
// Subject may contain credential material and must not be logged or serialized.
type AuthenticatedPrincipal struct {
	Provider string
	Subject  string
}

// WithAuthenticatedPrincipal records the result of successful authentication.
// Callers must never populate it from unverified headers, bodies, or metadata.
// An incomplete identity clears any principal inherited from the parent.
func WithAuthenticatedPrincipal(ctx context.Context, provider, subject string) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	ctx = context.WithValue(ctx, internalOperationKey{}, InternalOperation(""))
	return context.WithValue(ctx, authenticatedPrincipalKey{}, AuthenticatedPrincipal{
		Provider: provider,
		Subject:  subject,
	})
}

// AuthenticatedPrincipalFromContext returns only a complete typed identity.
func AuthenticatedPrincipalFromContext(ctx context.Context) (AuthenticatedPrincipal, bool) {
	if ctx == nil {
		return AuthenticatedPrincipal{}, false
	}
	principal, ok := ctx.Value(authenticatedPrincipalKey{}).(AuthenticatedPrincipal)
	return principal, ok && principal.Provider != "" && principal.Subject != ""
}

// CopyAuthenticatedPrincipal preserves parent cancellation but takes identity
// exclusively from the authenticated request, including its missing state.
func CopyAuthenticatedPrincipal(parent, request context.Context) context.Context {
	principal, _ := AuthenticatedPrincipalFromContext(request)
	ctx := WithAuthenticatedPrincipal(parent, principal.Provider, principal.Subject)
	if operation, ok := InternalOperationFromContext(request); ok {
		ctx = WithInternalOperation(ctx, operation)
	}
	return ctx
}
