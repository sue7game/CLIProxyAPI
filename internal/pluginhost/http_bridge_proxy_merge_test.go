package pluginhost

import (
	"context"
	"net/http"
	"net/url"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	sdkconfig "github.com/router-for-me/CLIProxyAPI/v7/sdk/config"
)

func TestResolveProxyForRequestPreservesRuntimeAndRequestPriority(t *testing.T) {
	configured := "http://configured.example:8080"
	runtime := "http://runtime.example:8080"
	request := "http://request.example:8080"
	auth := &coreauth.Auth{ProxyURL: configured}
	cfg := &config.Config{SDKConfig: sdkconfig.SDKConfig{ProxyURL: "http://global.example:8080"}}
	req := &http.Request{URL: &url.URL{Scheme: "https", Host: "upstream.example"}}

	checkProxy := func(want string, requestProxy string) {
		t.Helper()
		got, errResolve := resolveProxyForRequest(req, requestProxy, auth, cfg, nil)
		if errResolve != nil {
			t.Fatalf("resolveProxyForRequest() error = %v", errResolve)
		}
		if want == "" {
			if got != nil {
				t.Fatalf("proxy = %s, want direct", got)
			}
			return
		}
		if got == nil || got.String() != want {
			t.Fatalf("proxy = %v, want %s", got, want)
		}
	}

	checkProxy(configured, "")
	manager := coreauth.NewManager(nil, nil, nil)
	registered, errRegister := manager.Register(coreauth.WithSkipPersist(context.Background()), &coreauth.Auth{
		ID: "wire-profile-runtime-proxy", Provider: "antigravity", ProxyURL: configured,
	})
	if errRegister != nil {
		t.Fatalf("Register() error = %v", errRegister)
	}
	if _, errOverride := manager.SetRuntimeAuthOverride(registered.Index, coreauth.RuntimeAuthOverride{ProxyURL: &runtime}); errOverride != nil {
		t.Fatalf("SetRuntimeAuthOverride() error = %v", errOverride)
	}
	auth, _ = manager.GetByID(registered.ID)
	checkProxy(runtime, "")
	checkProxy(request, request)
	checkProxy("", "direct")
}
