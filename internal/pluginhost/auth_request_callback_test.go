package pluginhost

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"
	"time"

	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

type callbackCancelRoundTripper func(*http.Request) (*http.Response, error)

func (f callbackCancelRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestHostAuthRequestUsesManagementCallbackContext(t *testing.T) {
	host := New()
	manager := coreauth.NewManager(nil, nil, nil)
	host.SetAuthManager(manager)
	registered, errRegister := manager.Register(context.Background(), &coreauth.Auth{
		ID:       "callback-context-auth",
		Provider: "demo",
		Attributes: map[string]string{
			"api_key":      "callback-token",
			"runtime_only": "true",
		},
	})
	if errRegister != nil {
		t.Fatalf("Register() error = %v", errRegister)
	}

	started := make(chan struct{})
	roundTripper := callbackCancelRoundTripper(func(req *http.Request) (*http.Response, error) {
		close(started)
		<-req.Context().Done()
		return nil, req.Context().Err()
	})
	callbackBase := context.WithValue(context.Background(), "cliproxy.roundtripper", http.RoundTripper(roundTripper))
	callbackCtx, cancelCallback := context.WithCancel(callbackBase)
	defer cancelCallback()
	callbackID, closeCallback := host.openCallbackContext(callbackCtx)
	defer closeCallback()

	rawRequest, errMarshal := json.Marshal(pluginapi.HostAuthRequest{
		AuthIndex:      registered.Index,
		HostCallbackID: callbackID,
		Method:         http.MethodGet,
		URL:            "https://quota.example.test/check",
		Headers:        http.Header{"Authorization": {"Bearer $TOKEN$"}},
	})
	if errMarshal != nil {
		t.Fatalf("Marshal() error = %v", errMarshal)
	}

	result := make(chan error, 1)
	go func() {
		_, errCall := host.callHostAuthRequest(context.Background(), rawRequest)
		result <- errCall
	}()

	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("host auth request did not reach callback RoundTripper")
	}
	cancelCallback()

	select {
	case errCall := <-result:
		if !errors.Is(errCall, context.Canceled) {
			t.Fatalf("callHostAuthRequest() error = %v, want context.Canceled", errCall)
		}
	case <-time.After(time.Second):
		t.Fatal("host auth request did not stop after callback context cancellation")
	}
}
