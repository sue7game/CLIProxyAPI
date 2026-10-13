package pluginhost

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

func TestHostAuthRequestRejectsStaleAndForeignCallbackContexts(t *testing.T) {
	for _, scenario := range []string{"closed scope", "foreign plugin", "foreign instance", "closed instance"} {
		t.Run(scenario, func(t *testing.T) {
			host := New()
			instance := &hostCallbackInstance{}
			ctx := withHostCallbackIdentity(context.Background(), "alpha", instance)
			callbackID, closeCallback := host.openCallbackContextForPluginInstance(ctx, "alpha", instance)
			defer closeCallback()
			wantError := "host callback ID does not belong"
			switch scenario {
			case "closed scope":
				closeCallback()
				wantError = "host callback ID is not open"
			case "foreign plugin":
				ctx = withHostCallbackIdentity(context.Background(), "bravo", instance)
			case "foreign instance":
				ctx = withHostCallbackIdentity(context.Background(), "alpha", &hostCallbackInstance{})
			case "closed instance":
				host.closeHostHTTPCallbackInstance("alpha", instance)
				wantError = "host plugin callback instance is closed"
			}
			request := authRequestLifecyclePayload(t, "unused-auth", callbackID)
			if _, errCall := host.callFromPlugin(ctx, pluginabi.MethodHostAuthRequest, request); errCall == nil || !strings.Contains(errCall.Error(), wantError) {
				t.Fatalf("host.auth.request error = %v, want %q", errCall, wantError)
			}
		})
	}
}

func TestHostAuthRequestCanceledWhenPluginInstanceCloses(t *testing.T) {
	host := New()
	manager := coreauth.NewManager(nil, nil, nil)
	host.SetAuthManager(manager)
	auth, errRegister := manager.Register(context.Background(), &coreauth.Auth{ID: "request-lifecycle", Provider: "demo"})
	if errRegister != nil {
		t.Fatalf("register auth: %v", errRegister)
	}
	started := make(chan struct{})
	roundTripper := callbackCancelRoundTripper(func(req *http.Request) (*http.Response, error) {
		close(started)
		<-req.Context().Done()
		return nil, req.Context().Err()
	})
	instance := &hostCallbackInstance{}
	base := context.WithValue(context.Background(), "cliproxy.roundtripper", http.RoundTripper(roundTripper))
	ctx := withHostCallbackIdentity(base, "alpha", instance)
	t.Cleanup(func() { host.closeHostHTTPCallbackInstance("alpha", instance) })
	callbackID, closeCallback := host.openCallbackContextForPluginInstance(ctx, "alpha", instance)
	defer closeCallback()
	request := authRequestLifecyclePayload(t, auth.Index, callbackID)
	result := make(chan error, 1)
	finished := make(chan struct{})
	go func() {
		_, errCall := host.callFromPlugin(ctx, pluginabi.MethodHostAuthRequest, request)
		result <- errCall
		close(finished)
	}()
	waitForHostTestSignal(t, started, "host auth HTTP request")
	host.closeHostHTTPCallbackInstance("alpha", instance)
	waitForHostTestSignal(t, finished, "host auth request cancellation")
	if errCall := <-result; !errors.Is(errCall, context.Canceled) {
		t.Fatalf("host.auth.request error = %v, want context.Canceled", errCall)
	}
}

func authRequestLifecyclePayload(t *testing.T, authIndex, callbackID string) []byte {
	t.Helper()
	request, errMarshal := json.Marshal(pluginapi.HostAuthRequest{
		AuthIndex: authIndex, HostCallbackID: callbackID,
		Method: http.MethodGet, URL: "https://quota.example.test/check",
	})
	if errMarshal != nil {
		t.Fatalf("marshal auth request: %v", errMarshal)
	}
	return request
}
