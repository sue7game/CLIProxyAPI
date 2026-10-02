package pluginhost

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/google/uuid"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/access"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginabi"
)

func groupingHTTPInstanceFixture(t *testing.T) (*Host, string, context.Context, *hostCallbackInstance) {
	t.Helper()
	host, _, _, _, _ := groupingCallbackFixture(t)
	instance := &hostCallbackInstance{}
	parent := access.WithAuthenticatedPrincipal(context.Background(), "config", "verified")
	id, cleanup := host.openCallbackContextForPluginInstance(parent, "plugin-a", instance)
	t.Cleanup(cleanup)
	return host, id, withHostCallbackIdentity(context.Background(), "plugin-a", instance), instance
}

func groupingHTTPPayload(t *testing.T, callbackID, operationID, url string) []byte {
	t.Helper()
	raw, errMarshal := json.Marshal(map[string]string{
		"host_callback_id": callbackID, "operation_id": operationID, "method": http.MethodGet, "url": url,
	})
	if errMarshal != nil {
		t.Fatal(errMarshal)
	}
	return raw
}

func TestGroupingHTTPOperationsRequireRegisteredInstance(t *testing.T) {
	for _, method := range []string{pluginabi.MethodHostHTTPOperationOpen, pluginabi.MethodHostHTTPDo, pluginabi.MethodHostHTTPDoStream, pluginabi.MethodHostHTTPCancel} {
		t.Run(method, func(t *testing.T) {
			host, id, owner, instance := groupingHTTPInstanceFixture(t)
			operationID := openHostHTTPOperation(t, host, owner, id)
			for _, caller := range []context.Context{
				context.Background(),
				withHostCallbackIdentity(context.Background(), "other", instance),
				withHostCallbackIdentity(context.Background(), "plugin-a", &hostCallbackInstance{}),
				withHostCallbackPluginID(context.Background(), "plugin-a"),
			} {
				raw := groupingHTTPPayload(t, id, operationID, "http://upstream.invalid")
				if _, errCall := host.callFromPlugin(caller, method, raw); !coreauth.IsCredentialAccessError(errCall) {
					t.Fatalf("foreign callback accepted: %v", errCall)
				}
				if errDenial := host.callbackAccessDenial(id).failure(nil); errDenial != nil {
					t.Fatalf("foreign instance poisoned callback owner: %v", errDenial)
				}
			}
			raw := groupingHTTPPayload(t, "", operationID, "http://upstream.invalid")
			if _, errCall := host.callFromPlugin(owner, method, raw); !coreauth.IsCredentialAccessError(errCall) {
				t.Fatalf("unbound callback accepted: %v", errCall)
			}
		})
	}
}

func TestGroupingHTTPOperationPreservesTrustedContextAndSingleClaim(t *testing.T) {
	host, id, caller, _ := groupingHTTPInstanceFixture(t)
	operationID := openHostHTTPOperation(t, host, caller, id)
	if parsed, errParse := uuid.Parse(operationID); errParse != nil || parsed.Version() != 4 {
		t.Fatalf("operation ID is not random: %q", operationID)
	}
	handle, errAcquire := host.acquireHostHTTPOperation(caller, id, operationID)
	if errAcquire != nil {
		t.Fatal(errAcquire)
	}
	defer handle.finish()
	principal, ok := access.AuthenticatedPrincipalFromContext(handle.ctx)
	if !ok || principal.Subject != "verified" {
		t.Fatal("HTTP operation discarded the trusted principal")
	}
	if _, errReplay := host.acquireHostHTTPOperation(caller, id, operationID); errReplay == nil {
		t.Fatal("HTTP operation was claimed twice")
	}
}

func TestGroupingHTTPOperationsFailClosedWithoutPolicy(t *testing.T) {
	host := New()
	host.runtimeConfig = &config.Config{Grouping: config.GroupingConfig{Enabled: true}}
	raw := groupingHTTPPayload(t, "", "operation", "http://upstream.invalid")
	for _, method := range []string{pluginabi.MethodHostHTTPOperationOpen, pluginabi.MethodHostHTTPDo, pluginabi.MethodHostHTTPDoStream, pluginabi.MethodHostHTTPCancel} {
		if _, errCall := host.callFromPlugin(context.Background(), method, raw); !coreauth.IsCredentialAccessError(errCall) {
			t.Fatalf("unavailable policy accepted %s: %v", method, errCall)
		}
	}
}

func TestGroupingHTTPOperationCannotBypassNewlyEnabledPolicy(t *testing.T) {
	for _, method := range []string{pluginabi.MethodHostHTTPDo, pluginabi.MethodHostHTTPDoStream} {
		t.Run(method, func(t *testing.T) {
			host, _, _, id, caller := groupingCallbackFixture(t)
			manager := host.currentAuthManager()
			host.SetAuthManager(nil)
			operationID := openHostHTTPOperation(t, host, caller, "")
			defer host.httpOperations.cancel("plugin-a", nil, operationID)
			host.SetAuthManager(manager)
			for _, callbackID := range []string{"", id} {
				raw := groupingHTTPPayload(t, callbackID, operationID, "http://upstream.invalid")
				if _, errCall := host.callFromPlugin(caller, method, raw); errCall == nil {
					t.Fatal("unbound operation bypassed the enabled policy")
				}
			}
		})
	}
}

func TestGroupingHTTPOperationStillRejectsUnboundCredentialBeforeHTTP(t *testing.T) {
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	for _, method := range []string{pluginabi.MethodHostHTTPDo, pluginabi.MethodHostHTTPDoStream} {
		t.Run(method, func(t *testing.T) {
			host, id, caller, _ := groupingHTTPInstanceFixture(t)
			operationID := openHostHTTPOperation(t, host, caller, id)
			raw := groupingHTTPPayload(t, id, operationID, server.URL)
			if _, errCall := host.callFromPlugin(caller, method, raw); !coreauth.IsCredentialAccessError(errCall) {
				t.Fatalf("unbound HTTP operation accepted: %v", errCall)
			}
			if !coreauth.IsCredentialAccessError(host.callbackAccessDenial(id).failure(nil)) {
				t.Fatal("HTTP access denial was not retained across the ABI")
			}
			host.httpOperations.mu.Lock()
			remaining := len(host.httpOperations.operations)
			host.httpOperations.mu.Unlock()
			if remaining != 0 {
				t.Fatal("denied HTTP operation leaked")
			}
		})
	}
	if hits.Load() != 0 {
		t.Fatalf("unauthorized upstream requests: %d", hits.Load())
	}
}

func TestGroupingHTTPCancelIsCallbackScopedAndIdempotent(t *testing.T) {
	host, id, caller, instance := groupingHTTPInstanceFixture(t)
	otherID, cleanup := host.openCallbackContextForPluginInstance(context.Background(), "plugin-a", instance)
	defer cleanup()
	operationID := openHostHTTPOperation(t, host, caller, id)
	host.httpOperations.mu.Lock()
	entry := host.httpOperations.operations[hostHTTPOperationKey{pluginID: "plugin-a", operationID: operationID}]
	host.httpOperations.mu.Unlock()
	_, errCancel := host.callFromPlugin(caller, pluginabi.MethodHostHTTPCancel, groupingHTTPPayload(t, otherID, operationID, ""))
	if errCancel != nil || entry.ctx.Err() != nil {
		t.Fatalf("another callback canceled the operation: %v; %v", errCancel, entry.ctx.Err())
	}
	for range 2 {
		_, errCancel = host.callFromPlugin(caller, pluginabi.MethodHostHTTPCancel, groupingHTTPPayload(t, id, operationID, ""))
		if errCancel != nil || entry.ctx.Err() != context.Canceled {
			t.Fatalf("owner cancellation failed: %v; %v", errCancel, entry.ctx.Err())
		}
	}
	if errDenial := host.callbackAccessDenial(id).failure(nil); errDenial != nil {
		t.Fatalf("idempotent cancellation poisoned owner: %v", errDenial)
	}
}

func TestGroupingHTTPInternalOperationStreamRetainsScopeCleanup(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("fixture"))
	}))
	defer server.Close()
	host, _, caller, instance := groupingHTTPInstanceFixture(t)
	internal := access.WithInternalOperation(context.Background(), access.InternalManagement)
	id, cleanup := host.openCallbackContextForPluginInstance(internal, "plugin-a", instance)
	defer cleanup()
	operationID := openHostHTTPOperation(t, host, caller, id)
	raw, errCall := host.callFromPlugin(caller, pluginabi.MethodHostHTTPDoStream, groupingHTTPPayload(t, id, operationID, server.URL))
	if errCall != nil {
		t.Fatal(errCall)
	}
	response, errDecode := decodeRPCEnvelope[rpcHostHTTPStreamResponse](raw)
	if errDecode != nil {
		t.Fatal(errDecode)
	}
	if errAccess := host.authorizeGroupedStream(caller, pluginabi.MethodHostHTTPStreamRead, response.StreamID); errAccess != nil {
		t.Fatal(errAccess)
	}
	cleanup()
	if errAccess := host.authorizeGroupedStream(caller, pluginabi.MethodHostHTTPStreamRead, response.StreamID); errAccess == nil {
		t.Fatal("closed callback retained stream access")
	}
	host.httpOperations.mu.Lock()
	operations := len(host.httpOperations.operations)
	host.httpOperations.mu.Unlock()
	host.httpStreams.mu.Lock()
	streams := len(host.httpStreams.streams)
	host.httpStreams.mu.Unlock()
	if operations != 0 || streams != 0 {
		t.Fatalf("scope leaked %d operations and %d streams", operations, streams)
	}
}
