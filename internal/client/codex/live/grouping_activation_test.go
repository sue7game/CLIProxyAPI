package live

import (
	"net/http"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/clienterror"
)

func TestGroupingActivationSerializesDirectMediaAdmission(t *testing.T) {
	t.Run("activation-first", func(t *testing.T) {
		h, policy := groupingLiveFixture(t)
		h.authManager.SetCredentialAccessPolicy(nil)
		release, err := h.BeginCredentialAccessActivation()
		if err != nil {
			t.Fatal(err)
		}
		defer release()
		result := make(chan error, 1)
		started := make(chan struct{})
		go func() {
			close(started)
			end, errAdmission := h.beginDirectMediaRequest()
			if end != nil {
				end()
			}
			result <- errAdmission
		}()
		<-started
		if h.credentialActivationMu.TryLock() {
			h.credentialActivationMu.Unlock()
			t.Fatal("activation did not retain admission lock")
		}
		select {
		case <-result:
			t.Fatal("direct admission bypassed activation lock")
		default:
		}
		h.authManager.SetCredentialAccessPolicy(policy)
		release()
		if err = <-result; clienterror.HTTPStatusFromErrorOr(err, 0) != http.StatusServiceUnavailable {
			t.Fatalf("post-activation admission = %v", err)
		}
	})
}

func TestGroupingActivationWaitsForInFlightDirectMedia(t *testing.T) {
	t.Run("direct-request-first", func(t *testing.T) {
		h, _ := groupingLiveFixture(t)
		h.authManager.SetCredentialAccessPolicy(nil)
		finish, err := h.beginDirectMediaRequest()
		if err != nil {
			t.Fatal(err)
		}
		defer func() { finish() }()
		result := make(chan error, 1)
		started := make(chan struct{})
		go func() {
			close(started)
			release, errBegin := h.BeginCredentialAccessActivation()
			if release != nil {
				release()
			}
			result <- errBegin
		}()
		<-started
		if h.credentialActivationMu.TryLock() {
			h.credentialActivationMu.Unlock()
			t.Fatal("direct request did not retain admission lock")
		}
		select {
		case <-result:
			t.Fatal("activation bypassed in-flight SDP")
		default:
		}
		h.unconfirmedDirectMedia = true
		finish()
		finish = func() {}
		if err = <-result; clienterror.HTTPStatusFromErrorOr(err, 0) != http.StatusConflict {
			t.Fatalf("activation after SDP = %v", err)
		}
	})
}

func TestGroupingActivationRetainsUncertaintyAfterResponseReadFailure(t *testing.T) {
	h, _ := groupingLiveFixture(t)
	h.authManager.SetCredentialAccessPolicy(nil)
	h.authManager.RegisterExecutor(&captureExecutor{responseBody: &errorResponseBody{payload: []byte("v=0")}})
	if response := groupingSDPRequest(h); response.Code != http.StatusBadGateway {
		t.Fatalf("SDP status = %d", response.Code)
	}
	if err := h.ValidateCredentialAccessActivation(); clienterror.HTTPStatusFromErrorOr(err, 0) != http.StatusConflict {
		t.Fatalf("uncertain successful SDP allowed activation: %v", err)
	}
}

func TestGroupingActivationDoesNotDeleteExistingSessions(t *testing.T) {
	h, _ := groupingLiveFixture(t)
	h.authManager.SetCredentialAccessPolicy(nil)
	session := h.sessions.put("existing-direct", liveSession{authID: "grouping-live-auth"})
	if release, err := h.BeginCredentialAccessActivation(); err == nil {
		release()
		t.Fatal("existing direct session allowed activation")
	}
	if _, exists := h.sessions.peek(session.callID); !exists {
		t.Fatal("activation deleted existing session")
	}
	h.credentialActivationMu.Lock()
	h.unconfirmedDirectMedia = true
	h.credentialActivationMu.Unlock()
	h.sessions.expire(session.callID, session.token)
	if err := h.ValidateCredentialAccessActivation(); err == nil {
		t.Fatal("local TTL expiration incorrectly proved P2P media stopped")
	}
}
