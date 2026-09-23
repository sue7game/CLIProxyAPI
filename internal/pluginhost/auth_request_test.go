package pluginhost

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

func TestHostAuthRequestReplacesAndRedactsToken(t *testing.T) {
	const token = "demo-secret-token"
	gin.SetMode(gin.TestMode)
	ginCtx, _ := gin.CreateTestContext(httptest.NewRecorder())
	callbackContext := context.WithValue(context.Background(), "gin", ginCtx)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if got := req.Header.Get("Authorization"); got != "Bearer "+token {
			t.Errorf("Authorization = %q, want bearer token", got)
		}
		w.Header().Set("X-Echo-Token", token)
		_, _ = w.Write([]byte(`{"token":"` + token + `"}`))
	}))
	defer server.Close()

	host, auth := newHostAuthRequestTestHost(t, &coreauth.Auth{
		ID:       "demo-token",
		Provider: "demo",
		ProxyURL: "direct",
		Attributes: map[string]string{
			"api_key":      token,
			"runtime_only": "true",
		},
	})
	host.mu.Lock()
	host.runtimeConfig = &config.Config{SDKConfig: config.SDKConfig{RequestLog: true}}
	host.mu.Unlock()
	callbackID, closeCallback := host.openCallbackContext(callbackContext)
	defer closeCallback()
	rawRequest, errMarshal := json.Marshal(pluginapi.HostAuthRequest{
		AuthIndex:      auth.Index,
		HostCallbackID: callbackID,
		Method:         http.MethodGet,
		URL:            server.URL,
		Headers:        http.Header{"Authorization": {"Bearer $TOKEN$"}},
	})
	if errMarshal != nil {
		t.Fatalf("Marshal() error = %v", errMarshal)
	}

	rawResponse, errCall := host.callFromPlugin(context.Background(), pluginabi.MethodHostAuthRequest, rawRequest)
	if errCall != nil {
		t.Fatalf("callFromPlugin() error = %v", errCall)
	}
	response, errDecode := decodeRPCEnvelope[pluginapi.HostAuthRequestResponse](rawResponse)
	if errDecode != nil {
		t.Fatalf("decode response: %v", errDecode)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", response.StatusCode)
	}
	if strings.Contains(response.Headers.Get("X-Echo-Token"), token) || strings.Contains(string(response.Body), token) {
		t.Fatalf("response exposed token: headers=%v body=%s", response.Headers, response.Body)
	}
	if response.Headers.Get("X-Echo-Token") != "[REDACTED]" || !strings.Contains(string(response.Body), "[REDACTED]") {
		t.Fatalf("response = %#v, want redacted token", response)
	}
	rawAPIResponse, okResponse := ginCtx.Get("API_RESPONSE")
	if !okResponse {
		t.Fatal("API_RESPONSE was not captured on the original Gin context")
	}
	apiResponse, _ := rawAPIResponse.([]byte)
	if bytes.Contains(apiResponse, []byte(token)) || !bytes.Contains(apiResponse, []byte("[REDACTED]")) {
		t.Fatalf("API_RESPONSE = %q, want token redacted before logging", apiResponse)
	}
}

func TestHostAuthRequestUsesRuntimeProxyOverride(t *testing.T) {
	proxyHit := false
	proxyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		proxyHit = true
		if got := req.URL.String(); got != "http://upstream.invalid/quota" {
			t.Errorf("proxy request URL = %q", got)
		}
		_, _ = w.Write([]byte("proxied"))
	}))
	defer proxyServer.Close()

	host, auth := newHostAuthRequestTestHost(t, &coreauth.Auth{
		ID:         "antigravity-proxy",
		Provider:   "antigravity",
		Attributes: map[string]string{"runtime_only": "true"},
	})
	proxyURL := proxyServer.URL
	if _, errSet := host.currentAuthManager().SetRuntimeAuthOverride(auth.Index, coreauth.RuntimeAuthOverride{ProxyURL: &proxyURL}); errSet != nil {
		t.Fatalf("SetRuntimeAuthOverride() error = %v", errSet)
	}
	rawRequest, errMarshal := json.Marshal(pluginapi.HostAuthRequest{
		AuthIndex: auth.Index,
		Method:    http.MethodGet,
		URL:       "http://upstream.invalid/quota",
	})
	if errMarshal != nil {
		t.Fatalf("Marshal() error = %v", errMarshal)
	}

	rawResponse, errCall := host.callFromPlugin(context.Background(), pluginabi.MethodHostAuthRequest, rawRequest)
	if errCall != nil {
		t.Fatalf("callFromPlugin() error = %v", errCall)
	}
	response, errDecode := decodeRPCEnvelope[pluginapi.HostAuthRequestResponse](rawResponse)
	if errDecode != nil {
		t.Fatalf("decode response: %v", errDecode)
	}
	if !proxyHit || string(response.Body) != "proxied" {
		t.Fatalf("proxyHit=%v response=%#v, want runtime proxy", proxyHit, response)
	}
}

func newHostAuthRequestTestHost(t *testing.T, auth *coreauth.Auth) (*Host, *coreauth.Auth) {
	t.Helper()
	host := New()
	host.SetAuthManager(coreauth.NewManager(nil, nil, nil))
	registered, errRegister := host.currentAuthManager().Register(context.Background(), auth)
	if errRegister != nil {
		t.Fatalf("Register() error = %v", errRegister)
	}
	return host, registered
}
