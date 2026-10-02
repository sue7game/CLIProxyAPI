package auth

import (
	"context"
	"errors"
	"net/http"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
)

// CredentialAccessPolicy resolves a trusted request identity to a policy snapshot.
// Implementations must be concurrency-safe and must not trust request metadata.
type CredentialAccessPolicy interface {
	BeginAttempt(context.Context) (CredentialAccessScope, error)
}

// CredentialAccessScope limits selection and checks permission before each use.
// Allows must be immutable, non-blocking, and free of I/O: scheduler locks may be held.
// AuthorizeUse must reject stale policy/identity state, not silently acquire broader rights.
type CredentialAccessScope interface {
	Allows(*Auth) bool
	AuthorizeUse(context.Context, *Auth) error
}

type credentialAccessPolicyHolder struct {
	policy CredentialAccessPolicy
}

type credentialAccessContextKey struct{}

type credentialAccessAttempt struct {
	manager  *Manager
	holder   *credentialAccessPolicyHolder
	scope    CredentialAccessScope
	identity credentialAccessIdentity
}

// SetCredentialAccessPolicy installs mandatory authorization for this manager.
// Passing nil explicitly disables it and restores the existing selection behavior.
func (m *Manager) SetCredentialAccessPolicy(policy CredentialAccessPolicy) {
	if m == nil {
		return
	}
	if policy == nil {
		m.credentialAccessPolicy.Store(nil)
		m.NotifyCredentialAccessChanged()
		return
	}
	m.credentialAccessPolicy.Store(&credentialAccessPolicyHolder{policy: policy})
	m.NotifyCredentialAccessChanged()
}

// CredentialAccessPolicyEnabled reports whether mandatory authorization is installed.
// It is intended for compatibility decisions, not as a substitute for authorization.
func (m *Manager) CredentialAccessPolicyEnabled() bool {
	return m != nil && m.credentialAccessPolicy.Load() != nil
}

func credentialAccessAttemptFromContext(ctx context.Context) *credentialAccessAttempt {
	if ctx == nil {
		return nil
	}
	attempt, _ := ctx.Value(credentialAccessContextKey{}).(*credentialAccessAttempt)
	return attempt
}

func (m *Manager) beginCredentialAccess(ctx context.Context) (context.Context, error) {
	if m == nil || m.credentialAccessPolicy.Load() == nil {
		if credentialAccessAttemptFromContext(ctx) != nil {
			ctx = context.WithValue(ctx, credentialAccessContextKey{}, (*credentialAccessAttempt)(nil))
		}
		return ctx, nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if m.HomeEnabled() {
		return ctx, accessPolicyUnavailable("credential access policy is unavailable in Home mode")
	}
	holder := m.credentialAccessPolicy.Load()
	if holder == nil {
		return ctx, nil
	}
	if attempt := credentialAccessAttemptFromContext(ctx); attempt != nil && attempt.manager == m {
		if attempt.holder != holder || attempt.identity != credentialAccessIdentityFromContext(ctx) {
			return ctx, accessPolicyUnavailable("credential access policy changed; retry the request")
		}
		return ctx, nil
	}
	scope, err := holder.policy.BeginAttempt(ctx)
	if err != nil {
		return ctx, credentialAccessFailure(err)
	}
	if scope == nil {
		return ctx, accessPolicyUnavailable("credential access policy returned no scope")
	}
	return context.WithValue(ctx, credentialAccessContextKey{}, &credentialAccessAttempt{
		manager: m, holder: holder, scope: scope, identity: credentialAccessIdentityFromContext(ctx),
	}), nil
}

// AuthorizeCredentialUse rechecks the specific credential against current policy.
// A missing context is passed to the policy as an anonymous request, never exempted.
func (m *Manager) AuthorizeCredentialUse(ctx context.Context, auth *Auth) error {
	ctx, err := m.beginCredentialAccess(ctx)
	if err != nil {
		return err
	}
	if m == nil || m.credentialAccessPolicy.Load() == nil {
		return nil
	}
	attempt := credentialAccessAttemptFromContext(ctx)
	if attempt == nil || attempt.manager != m || attempt.holder != m.credentialAccessPolicy.Load() {
		return accessPolicyUnavailable("credential access policy changed; retry the request")
	}
	if auth == nil || auth.EffectiveDisabled() || !attempt.scope.Allows(auth) {
		return credentialAccessFailure(&Error{Code: "credential_access_denied", Message: "credential is unavailable for this request", HTTPStatus: http.StatusForbidden})
	}
	if errCurrent := m.authorizeCurrentCredential(attempt.scope, auth); errCurrent != nil {
		return errCurrent
	}
	return credentialAccessFailure(attempt.scope.AuthorizeUse(ctx, auth))
}

// AccessibleAuths returns isolated authorized snapshots, ignoring transient cooldowns.
// Disabled credentials remain excluded. Callers must still apply model capabilities.
func (m *Manager) AccessibleAuths(ctx context.Context) ([]*Auth, error) {
	ctx, err := m.beginCredentialAccess(ctx)
	if err != nil {
		return nil, err
	}
	if m == nil {
		return nil, nil
	}
	eligibility := authSelectionEligibilityForRequest(ctx, cliproxyexecutor.Options{})
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]*Auth, 0, len(m.auths))
	for _, auth := range m.auths {
		if auth != nil && !auth.EffectiveDisabled() && eligibility.allows(auth) {
			out = append(out, auth.Clone())
		}
	}
	return out, nil
}

type credentialAccessError struct{ cause error }

func (e *credentialAccessError) Error() string { return e.cause.Error() }
func (e *credentialAccessError) Unwrap() error { return e.cause }
func (e *credentialAccessError) StatusCode() int {
	if status := statusCodeFromError(e.cause); status != 0 {
		return status
	}
	return http.StatusForbidden
}

func credentialAccessFailure(err error) error {
	if err == nil || isCredentialAccessError(err) {
		return err
	}
	return &credentialAccessError{cause: err}
}

func isCredentialAccessError(err error) bool {
	var accessErr *credentialAccessError
	return errors.As(err, &accessErr)
}

// NewCredentialAccessError marks a host authorization failure, not an upstream fault.
// Callers must not derive this marker from untrusted response text or metadata.
func NewCredentialAccessError(cause error) error {
	return credentialAccessFailure(cause)
}

// IsCredentialAccessError identifies host authorization failures across adapters.
func IsCredentialAccessError(err error) bool {
	return isCredentialAccessError(err)
}

func accessPolicyUnavailable(message string) error {
	return credentialAccessFailure(&Error{Code: "credential_policy_unavailable", Message: message, HTTPStatus: http.StatusServiceUnavailable})
}
