package cliproxy

import (
	"context"
	"errors"
	"net/http"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/grouping"
	sdkaccess "github.com/router-for-me/CLIProxyAPI/v8/sdk/access"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

type groupingAccessPolicy struct {
	store            *grouping.Store
	principalCurrent func(sdkaccess.AuthenticatedPrincipal) bool
	ready            func() bool
}

type groupingAccessScope struct {
	policy    *groupingAccessPolicy
	scope     *grouping.AccessScope
	hash      groupingHasher
	principal sdkaccess.AuthenticatedPrincipal
}

// BeginAttempt acquires a revision-bound scope from an authenticated issuer.
func (p *groupingAccessPolicy) BeginAttempt(ctx context.Context) (coreauth.CredentialAccessScope, error) {
	if _, internal := sdkaccess.InternalOperationFromContext(ctx); internal {
		return groupingInternalScope{}, nil
	}
	if p.ready != nil && !p.ready() {
		return nil, groupingPolicyUnavailable()
	}
	principal, ok := sdkaccess.AuthenticatedPrincipalFromContext(ctx)
	if !ok || p.principalCurrent == nil || !p.principalCurrent(principal) {
		return nil, grouping.ErrUnauthenticated
	}
	hash, err := p.store.IdentityHasher()
	if err != nil {
		return nil, groupingPolicyUnavailable()
	}
	fingerprint, err := hash("token:"+principal.Provider, principal.Subject)
	if err != nil {
		return nil, groupingPolicyUnavailable()
	}
	scope, err := p.store.BeginAccess(principal.Provider, fingerprint)
	if errors.Is(err, grouping.ErrUnavailable) {
		return nil, groupingPolicyUnavailable()
	}
	if err != nil {
		return nil, err
	}
	return &groupingAccessScope{p, scope, hash, principal}, nil
}

type groupingInternalScope struct{}

func (groupingInternalScope) Allows(auth *coreauth.Auth) bool { return auth != nil }

func (groupingInternalScope) AuthorizeUse(ctx context.Context, auth *coreauth.Auth) error {
	if _, internal := sdkaccess.InternalOperationFromContext(ctx); !internal || auth == nil {
		return grouping.ErrDenied
	}
	return nil
}

// Allows performs only pure identity computation and immutable snapshot reads.
func (s *groupingAccessScope) Allows(auth *coreauth.Auth) bool {
	identity, err := groupingCredentialIdentity(auth, s.hash)
	return err == nil && s.scope.Allows(identity.ID, identity.Provider, identity.Fingerprint)
}

// AuthorizeUse rechecks issuer validity and rejects policy changes before dispatch.
func (s *groupingAccessScope) AuthorizeUse(ctx context.Context, auth *coreauth.Auth) error {
	if s.policy.ready != nil && !s.policy.ready() {
		return groupingPolicyUnavailable()
	}
	if ctx != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	if !s.policy.principalCurrent(s.principal) {
		return grouping.ErrUnauthenticated
	}
	identity, err := groupingCredentialIdentity(auth, s.hash)
	if errors.Is(err, grouping.ErrUnavailable) {
		return groupingPolicyUnavailable()
	}
	if err != nil {
		return grouping.ErrPolicyChanged
	}
	err = s.policy.store.AuthorizeUse(s.scope, identity.ID, identity.Provider, identity.Fingerprint)
	if errors.Is(err, grouping.ErrUnavailable) {
		return groupingPolicyUnavailable()
	}
	return err
}

func groupingPolicyUnavailable() error {
	return &coreauth.Error{Code: "grouping_unavailable", Message: "grouping policy is unavailable", HTTPStatus: http.StatusServiceUnavailable}
}
