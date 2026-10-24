package pluginhost

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/access"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

type groupingDeniedRPCClient struct {
	host  *Host
	index string
}

func (c groupingDeniedRPCClient) Call(_ context.Context, _ string, request []byte) ([]byte, error) {
	var req struct {
		HostCallbackID string `json:"host_callback_id"`
	}
	if err := json.Unmarshal(request, &req); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(map[string]string{"host_callback_id": req.HostCallbackID, "auth_index": c.index})
	if err != nil {
		return nil, err
	}
	caller := withHostCallbackPluginID(context.Background(), "plugin-a")
	if _, err := c.host.callFromPlugin(caller, pluginabi.MethodHostAuthGetRuntime, raw); err == nil {
		return marshalRPCError("unexpected", "callback should have been denied"), nil
	}
	// A plugin may lose the error type at the ABI boundary or ignore it entirely.
	return marshalRPCResult(rpcEmptyResponse{})
}

func (groupingDeniedRPCClient) Shutdown() {}

func TestGroupingRPCRetainsHostDenialWithoutTrustingPluginResponse(t *testing.T) {
	for _, method := range []string{"execute", "count", "http", "refresh", "stream"} {
		t.Run(method, func(t *testing.T) {
			host, auth, scope, _, _ := groupingCallbackFixture(t)
			scope.allowed[auth.ID] = false
			adapter := &rpcPluginAdapter{id: "plugin-a", host: host, client: groupingDeniedRPCClient{host: host, index: auth.Index}}
			ctx := access.WithAuthenticatedPrincipal(context.Background(), "config", "verified")
			var err error
			switch method {
			case "execute":
				_, err = adapter.Execute(ctx, pluginapi.ExecutorRequest{})
			case "count":
				_, err = adapter.CountTokens(ctx, pluginapi.ExecutorRequest{})
			case "http":
				_, err = adapter.HttpRequest(ctx, pluginapi.ExecutorHTTPRequest{})
			case "refresh":
				_, err = adapter.RefreshAuth(ctx, pluginapi.AuthRefreshRequest{})
			case "stream":
				_, err = adapter.ExecuteStream(ctx, pluginapi.ExecutorRequest{Stream: true})
			}
			if !coreauth.IsCredentialAccessError(err) {
				t.Fatalf("denial lost: %v", err)
			}
		})
	}
}

func TestGroupingAsyncRPCStreamStopsAfterHostDenial(t *testing.T) {
	host, auth, scope, _, caller := groupingCallbackFixture(t)
	scope.allowed[auth.ID] = false
	client := newStreamCallbackPluginClient()
	adapter := &rpcPluginAdapter{id: "plugin-a", host: host, client: client}
	ctx, cancel := context.WithCancel(access.WithAuthenticatedPrincipal(context.Background(), "config", "verified"))
	defer cancel()
	stream, err := adapter.ExecuteStream(ctx, pluginapi.ExecutorRequest{Stream: true})
	if err != nil {
		t.Fatal(err)
	}
	request := groupingCallbackRequest(t, auth, client.callbackID, "http://unused.invalid/")
	if _, err = host.callFromPlugin(caller, pluginabi.MethodHostAuthGetRuntime, request); !coreauth.IsCredentialAccessError(err) {
		t.Fatalf("expected callback denial: %v", err)
	}
	var observed error
	for chunk := range stream.Chunks {
		observed = chunk.Err
	}
	if !coreauth.IsCredentialAccessError(observed) {
		t.Fatalf("stream denial lost: %v", observed)
	}
	if callbackContextExists(host, client.callbackID) {
		t.Fatal("denied stream retained callback context")
	}
}

func TestGroupingCallbackDenialRecorderIsConcurrentAndFirstWins(t *testing.T) {
	denial := newCallbackAccessDenial()
	err := groupingCallbackDenied()
	denial.record(err)
	done := make(chan struct{}, 16)
	for range 16 {
		go func() {
			denial.record(groupingCallbackDenied())
			if denial.failure(nil) != err {
				t.Error("initial denial changed")
			}
			done <- struct{}{}
		}()
	}
	for range 16 {
		<-done
	}
}
