package live

import (
	"net/http"
	"sync"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

// ValidateCredentialAccessActivation reports unsafe existing direct-media state.
// Callers that will publish a policy must use BeginCredentialAccessActivation instead.
func (h *Handler) ValidateCredentialAccessActivation() error {
	h.credentialActivationMu.Lock()
	defer h.credentialActivationMu.Unlock()
	return h.validateCredentialAccessActivationLocked()
}

// BeginCredentialAccessActivation serializes policy publication with direct SDP admission.
// The caller must release after publishing both the policy and enabled configuration,
// including failure paths. It never closes or deletes existing sessions.
func (h *Handler) BeginCredentialAccessActivation() (func(), error) {
	h.credentialActivationMu.Lock()
	if err := h.validateCredentialAccessActivationLocked(); err != nil {
		h.credentialActivationMu.Unlock()
		return nil, err
	}
	var once sync.Once
	return func() { once.Do(h.credentialActivationMu.Unlock) }, nil
}

func (h *Handler) validateCredentialAccessActivationLocked() error {
	if h.unconfirmedDirectMedia {
		return &auth.Error{Code: "unconfirmed_direct_media", HTTPStatus: http.StatusConflict,
			Message: "Cannot enable grouping: previously established direct Realtime media cannot be confirmed stopped. End external media sessions and restart CLIProxyAPI before enabling grouping."}
	}
	if h.sessions == nil {
		return nil
	}
	h.sessions.mu.Lock()
	defer h.sessions.mu.Unlock()
	for _, entry := range h.sessions.sessions {
		if entry != nil && entry.session.media == nil {
			return &auth.Error{Code: "active_direct_media", HTTPStatus: http.StatusConflict,
				Message: "Cannot enable grouping while direct Realtime sessions remain. Drain existing sessions or restart CLIProxyAPI; no sessions were removed."}
		}
	}
	return nil
}

func (h *Handler) beginDirectMediaRequest() (func(), error) {
	h.credentialActivationMu.Lock()
	if h.authManager.CredentialAccessPolicyEnabled() {
		h.credentialActivationMu.Unlock()
		return nil, &auth.Error{Code: "realtime_media_relay_required", HTTPStatus: http.StatusServiceUnavailable,
			Message: "Realtime SDP requires a revocable media relay while grouping is enabled"}
	}
	return h.credentialActivationMu.Unlock, nil
}
