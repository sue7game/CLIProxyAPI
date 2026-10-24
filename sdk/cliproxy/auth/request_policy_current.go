package auth

import "net/http"

func (m *Manager) authorizeCurrentCredential(scope CredentialAccessScope, auth *Auth) error {
	m.mu.RLock()
	current := m.auths[auth.ID].Clone()
	m.mu.RUnlock()
	stale := current == nil && auth.RegistrationEpoch != 0
	if current != nil {
		stale = current.EffectiveDisabled() ||
			(auth.RegistrationEpoch != 0 && current.RegistrationEpoch != auth.RegistrationEpoch) ||
			!scope.Allows(current)
	}
	if stale {
		return credentialAccessFailure(&Error{Code: "credential_access_denied", Message: "credential is unavailable for this request", HTTPStatus: http.StatusForbidden})
	}
	return nil
}
