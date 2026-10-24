package pluginhost

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/access"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

func TestGroupingHTTPBridgeRejectsUnboundUserRequests(t *testing.T) {
	host, _, _, id, caller := groupingCallbackFixture(t)
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1); w.WriteHeader(http.StatusOK) }))
	defer server.Close()
	request, _ := json.Marshal(rpcHostHTTPRequest{HostCallbackID: id, URL: server.URL})
	if _, err := host.callHostHTTPDo(caller, request); err == nil {
		t.Fatal("unbound HTTP callback allowed")
	}
	if _, err := host.callHostHTTPDoStream(caller, request); err == nil {
		t.Fatal("unbound HTTP stream callback allowed")
	}
	if hits.Load() != 0 {
		t.Fatal("unbound callback sent network traffic")
	}
	user := access.WithAuthenticatedPrincipal(context.Background(), "config", "verified")
	for _, ctx := range []context.Context{nil, context.Background(), user} {
		if _, err := host.newHTTPClient(nil).Do(ctx, pluginapi.HTTPRequest{URL: server.URL}); err == nil {
			t.Fatal("unbound native HTTP allowed")
		}
		if _, err := host.newHTTPClient(nil).DoStream(ctx, pluginapi.HTTPRequest{URL: server.URL}); err == nil {
			t.Fatal("unbound native stream allowed")
		}
	}
	if hits.Load() != 0 {
		t.Fatal("unbound client sent network traffic")
	}
}

func TestGroupingHTTPBridgeAllowsOnlyTypedInternalOperation(t *testing.T) {
	host, _, _, _, _ := groupingCallbackFixture(t)
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1); w.WriteHeader(http.StatusOK) }))
	defer server.Close()
	internal := access.WithInternalOperation(context.Background(), access.InternalMaintenance)
	id, cancel := host.openCallbackContextForPlugin(internal, "maintenance-plugin")
	defer cancel()
	request, _ := json.Marshal(rpcHostHTTPRequest{HostCallbackID: id, URL: server.URL})
	owner := withHostCallbackPluginID(context.Background(), "maintenance-plugin")
	if _, err := host.callHostHTTPDo(owner, request); err != nil {
		t.Fatal(err)
	}
	other := withHostCallbackPluginID(context.Background(), "user-plugin")
	if _, err := host.callHostHTTPDo(other, request); err == nil {
		t.Fatal("other plugin borrowed internal operation")
	}
	forged := context.WithValue(context.Background(), "internal_operation", string(access.InternalMaintenance))
	if _, err := host.newHTTPClient(nil).Do(forged, pluginapi.HTTPRequest{URL: server.URL}); err == nil {
		t.Fatal("serialized internal operation trusted")
	}
	user := access.WithAuthenticatedPrincipal(internal, "config", "verified")
	if _, err := host.newHTTPClient(nil).Do(user, pluginapi.HTTPRequest{URL: server.URL}); err == nil {
		t.Fatal("user inherited internal operation")
	}
	if hits.Load() != 1 {
		t.Fatalf("requests=%d", hits.Load())
	}
}

func TestGroupingHTTPBridgeChecksBoundAuth(t *testing.T) {
	host, a, scope, _, _ := groupingCallbackFixture(t)
	scope.allowed[a.ID] = false
	ctx := access.WithAuthenticatedPrincipal(context.Background(), "config", "verified")
	if _, err := host.newHTTPClient(a).Do(ctx, pluginapi.HTTPRequest{URL: "http://upstream.invalid/"}); err == nil {
		t.Fatal("blocked bound credential used")
	}
	if _, err := host.newHTTPClient(a).DoStream(ctx, pluginapi.HTTPRequest{URL: "http://upstream.invalid/"}); err == nil {
		t.Fatal("blocked bound credential streamed")
	}
	if _, err := host.currentAuthManager().Register(context.Background(), &coreauth.Auth{ID: "other", Provider: "demo"}); err != nil {
		t.Fatal(err)
	}
}
