package handlers

import (
	"context"
	"net/http"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	coreexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	sdkconfig "github.com/router-for-me/CLIProxyAPI/v8/sdk/config"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

type pluginGroupingPolicy struct{}

func (pluginGroupingPolicy) BeginAttempt(context.Context) (coreauth.CredentialAccessScope, error) {
	return pluginGroupingPolicy{}, nil
}

func (pluginGroupingPolicy) Allows(a *coreauth.Auth) bool { return a != nil }

func (pluginGroupingPolicy) AuthorizeUse(context.Context, *coreauth.Auth) error { return nil }

func groupingPluginFixture() (*BaseAPIHandler, *mockPluginUsageHost) {
	manager := coreauth.NewManager(nil, nil, nil)
	manager.SetCredentialAccessPolicy(pluginGroupingPolicy{})
	host := &mockPluginUsageHost{execResp: coreexecutor.Response{Payload: []byte(`{"ok":true}`)}}
	host.hasRouters = true
	host.route = func(context.Context, pluginapi.ModelRouteRequest) (pluginapi.ModelRouteResponse, bool) {
		return pluginapi.ModelRouteResponse{Handled: true, TargetKind: pluginapi.ModelRouteTargetExecutor, Target: "grouping-direct"}, true
	}
	h := NewBaseAPIHandlers(&sdkconfig.SDKConfig{}, manager)
	h.SetModelRouterHost(host)
	return h, host
}

func TestGroupingPluginDirectRoutesRejectOnlyWhenEnabled(t *testing.T) {
	h, host := groupingPluginFixture()
	ctx := context.Background()
	_, _, errMsg := h.ExecuteWithAuthManager(ctx, "openai", "test", []byte(`{"model":"test"}`), "")
	if errMsg == nil || errMsg.StatusCode != http.StatusForbidden || host.lastPluginID != "" {
		t.Fatalf("grouped direct execution = %#v plugin=%q", errMsg, host.lastPluginID)
	}
	_, _, errors := h.ExecuteStreamWithAuthManager(ctx, "openai", "test", []byte(`{"model":"test","stream":true}`), "")
	if errMsg = <-errors; errMsg == nil || errMsg.StatusCode != http.StatusForbidden || host.lastPluginID != "" {
		t.Fatalf("grouped direct streaming = %#v plugin=%q", errMsg, host.lastPluginID)
	}
	h.AuthManager.SetCredentialAccessPolicy(nil)
	_, _, errMsg = h.ExecuteWithAuthManager(ctx, "openai", "test", []byte(`{"model":"test"}`), "")
	if errMsg != nil || host.lastPluginID != "grouping-direct" {
		t.Fatalf("disabled direct execution = %#v plugin=%q", errMsg, host.lastPluginID)
	}
}

func TestGroupingBuiltinRouteRemainsUsable(t *testing.T) {
	const id, model = "grouping-builtin-auth", "grouping-builtin-model"
	h, host := groupingPluginFixture()
	host.route = func(context.Context, pluginapi.ModelRouteRequest) (pluginapi.ModelRouteResponse, bool) {
		return pluginapi.ModelRouteResponse{}, false
	}
	h.AuthManager.RegisterExecutor(&interceptorCaptureExecutor{})
	if _, err := h.AuthManager.Register(context.Background(), &coreauth.Auth{ID: id, Provider: "codex"}); err != nil {
		t.Fatal(err)
	}
	registry.GetGlobalRegistry().RegisterClient(id, "codex", []*registry.ModelInfo{{ID: model}})
	t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(id) })
	_, _, errMsg := h.ExecuteWithAuthManager(context.Background(), "openai", model, []byte(`{"model":"grouping-builtin-model"}`), "")
	if errMsg != nil {
		t.Fatalf("ordinary Manager execution rejected: %#v", errMsg)
	}
	if host.lastPluginID != "" {
		t.Fatal("ordinary route unexpectedly invoked direct plugin")
	}
}
