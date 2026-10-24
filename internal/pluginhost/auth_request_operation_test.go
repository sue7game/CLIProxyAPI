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

func TestHostAuthRequestSupportsExplicitHTTPOperationCancellation(t *testing.T) {
	host, auth := newHostAuthRequestTestHost(t, &coreauth.Auth{ID: "operation-auth", Provider: "demo"})
	started := make(chan struct{})
	transport := callbackCancelRoundTripper(func(req *http.Request) (*http.Response, error) {
		close(started)
		<-req.Context().Done()
		return nil, req.Context().Err()
	})
	base := context.WithValue(context.Background(), "cliproxy.roundtripper", http.RoundTripper(transport))
	instance := &hostCallbackInstance{}
	ctx := withHostCallbackIdentity(base, "alpha", instance)
	callbackID, closeCallback := host.openCallbackContextForPluginInstance(ctx, "alpha", instance)
	t.Cleanup(closeCallback)
	operationID := openAuthRequestOperation(t, host, ctx, callbackID)
	request := authRequestOperationPayload(t, auth.Index, callbackID, operationID)
	finished := make(chan struct{})
	var errRequest error
	go func() {
		_, errRequest = host.callFromPlugin(ctx, pluginabi.MethodHostAuthRequest, request)
		close(finished)
	}()
	waitForHostTestSignal(t, started, "explicit auth HTTP operation")
	cancelRequest, errMarshal := json.Marshal(rpcHostHTTPCancelRequest{HostCallbackID: callbackID, OperationID: operationID})
	if errMarshal != nil {
		t.Fatal(errMarshal)
	}
	if _, errCancel := host.callFromPlugin(ctx, pluginabi.MethodHostHTTPCancel, cancelRequest); errCancel != nil {
		t.Fatal(errCancel)
	}
	waitForHostTestSignal(t, finished, "explicit auth HTTP operation cancellation")
	if !errors.Is(errRequest, context.Canceled) {
		t.Fatalf("request error = %v, want context.Canceled", errRequest)
	}
	if _, errReuse := host.callFromPlugin(ctx, pluginabi.MethodHostAuthRequest, request); errReuse == nil {
		t.Fatal("canceled HTTP operation was reusable")
	}
}

func TestHostAuthRequestExplicitOperationRejectsForeignIdentity(t *testing.T) {
	for _, scenario := range []string{"plugin", "instance", "callback"} {
		t.Run(scenario, func(t *testing.T) {
			host := New()
			instance := &hostCallbackInstance{}
			ctx := withHostCallbackIdentity(context.Background(), "alpha", instance)
			callbackID, closeCallback := host.openCallbackContextForPluginInstance(ctx, "alpha", instance)
			t.Cleanup(closeCallback)
			operationID := openAuthRequestOperation(t, host, ctx, callbackID)
			switch scenario {
			case "plugin":
				ctx = withHostCallbackIdentity(context.Background(), "beta", instance)
			case "instance":
				ctx = withHostCallbackIdentity(context.Background(), "alpha", &hostCallbackInstance{})
			case "callback":
				otherID, closeOther := host.openCallbackContextForPluginInstance(ctx, "alpha", instance)
				t.Cleanup(closeOther)
				callbackID = otherID
			}
			request := authRequestOperationPayload(t, "unused-auth", callbackID, operationID)
			_, errCall := host.callFromPlugin(ctx, pluginabi.MethodHostAuthRequest, request)
			if errCall == nil || (!strings.Contains(errCall.Error(), "is not open") && !strings.Contains(errCall.Error(), "does not belong")) {
				t.Fatalf("foreign %s operation error = %v, want rejection", scenario, errCall)
			}
		})
	}
}

func openAuthRequestOperation(t *testing.T, host *Host, ctx context.Context, callbackID string) string {
	t.Helper()
	request, errMarshal := json.Marshal(rpcHostHTTPOperationOpenRequest{HostCallbackID: callbackID})
	if errMarshal != nil {
		t.Fatal(errMarshal)
	}
	raw, errOpen := host.callFromPlugin(ctx, pluginabi.MethodHostHTTPOperationOpen, request)
	if errOpen != nil {
		t.Fatal(errOpen)
	}
	response, errDecode := decodeRPCEnvelope[rpcHostHTTPOperationOpenResponse](raw)
	if errDecode != nil {
		t.Fatal(errDecode)
	}
	return response.OperationID
}

func authRequestOperationPayload(t *testing.T, authIndex, callbackID, operationID string) []byte {
	t.Helper()
	request, errMarshal := json.Marshal(pluginapi.HostAuthRequest{
		AuthIndex: authIndex, HostCallbackID: callbackID, OperationID: operationID,
		Method: http.MethodGet, URL: "https://quota.example.test/check",
	})
	if errMarshal != nil {
		t.Fatal(errMarshal)
	}
	return request
}
