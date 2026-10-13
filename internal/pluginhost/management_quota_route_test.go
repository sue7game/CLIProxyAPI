package pluginhost

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

type quotaRouteContextKey struct{}

func TestManagementQuotaRefreshRouteAvoidsHostQuotaEndpoints(t *testing.T) {
	gin.SetMode(gin.TestMode)
	tests := []struct {
		name       string
		method     string
		suffix     string
		wantBody   string
		wantPlugin bool
	}{
		{"plugin refresh", http.MethodPost, "/quota/refresh", "plugin refresh", true},
		{"host quota read", http.MethodGet, "/quota", "host quota", false},
		{"host quota fetch", http.MethodPost, "/quota", "host quota", false},
		{"host quota delete", http.MethodDelete, "/quota", "host quota", false},
		{"host quota reset", http.MethodPost, "/quota/reset", "host reset", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pluginCalls, noRouteCalls := 0, 0
			host := quotaRouteTestHost(t, &pluginCalls)
			engine := quotaRouteTestEngine(host, &noRouteCalls)
			path := "/v0/management/plugins/antigravity-guard" + tt.suffix
			req := httptest.NewRequest(tt.method, path, strings.NewReader(`{"auth_index":"test-auth"}`))
			req = req.WithContext(context.WithValue(req.Context(), quotaRouteContextKey{}, "quota request"))
			recorder := httptest.NewRecorder()
			engine.ServeHTTP(recorder, req)
			if recorder.Code != http.StatusOK || recorder.Body.String() != tt.wantBody {
				t.Fatalf("response = %d %q, want 200 %q", recorder.Code, recorder.Body.String(), tt.wantBody)
			}
			wantCalls := 0
			if tt.wantPlugin {
				wantCalls = 1
			}
			if pluginCalls != wantCalls || noRouteCalls != wantCalls {
				t.Fatalf("plugin calls = %d, NoRoute calls = %d, want both %d", pluginCalls, noRouteCalls, wantCalls)
			}
		})
	}
}

func quotaRouteTestHost(t *testing.T, calls *int) *Host {
	t.Helper()
	var host *Host
	handler := managementHandlerFunc(func(ctx context.Context, req pluginapi.ManagementRequest) (pluginapi.ManagementResponse, error) {
		*calls++
		if req.Method != http.MethodPost || req.Path != "/v0/management/plugins/antigravity-guard/quota/refresh" {
			t.Errorf("plugin received unexpected request: %s %s", req.Method, req.Path)
		}
		if string(req.Body) != `{"auth_index":"test-auth"}` {
			t.Errorf("plugin request body = %q", req.Body)
		}
		callbackID, closeCallback := host.openCallbackContextForPlugin(ctx, "antigravity-guard")
		defer closeCallback()
		callbackContext := host.resolveCallbackContext(callbackID, context.Background())
		if callbackContext.Value(quotaRouteContextKey{}) != "quota request" {
			t.Error("plugin callback lost the management request context")
		}
		return pluginapi.ManagementResponse{Body: []byte("plugin refresh")}, nil
	})
	var routes []pluginapi.ManagementRoute
	for _, path := range []string{"/quota/refresh", "/quota", "/quota/reset"} {
		routes = append(routes, pluginapi.ManagementRoute{
			Method: http.MethodPost, Path: "/plugins/antigravity-guard" + path, Handler: handler,
		})
	}
	host = newHostWithRecords(capabilityRecord{
		id: "antigravity-guard",
		plugin: pluginapi.Plugin{Capabilities: pluginapi.Capabilities{
			ManagementAPI: &managementPluginDouble{routes: routes},
		}},
	})
	host.RegisterManagementRoutes(context.Background(), nil)
	return host
}

func quotaRouteTestEngine(host *Host, noRouteCalls *int) *gin.Engine {
	engine := gin.New()
	quotaPath := "/v0/management/plugins/:id/quota"
	for _, method := range []string{http.MethodGet, http.MethodPost, http.MethodDelete} {
		engine.Handle(method, quotaPath, func(c *gin.Context) {
			c.String(http.StatusOK, "host quota")
		})
	}
	engine.POST(quotaPath+"/reset", func(c *gin.Context) {
		c.String(http.StatusOK, "host reset")
	})
	engine.NoRoute(func(c *gin.Context) {
		*noRouteCalls++
		if host.ServeManagementHTTP(c.Writer, c.Request) {
			c.Abort()
			return
		}
		c.AbortWithStatus(http.StatusNotFound)
	})
	return engine
}
