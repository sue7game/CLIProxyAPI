package main

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"
)

func TestManagementRejectsNonAntigravityTarget(t *testing.T) {
	host := &fakeHost{auths: []hostAuthEntry{{AuthIndex: "codex-1", Provider: "codex", Name: "codex.json"}}}
	app := newApplication(host)
	defer app.shutdown()

	proxyBody, _ := json.Marshal(proxyActionRequest{AuthIndex: "codex-1", Mode: "direct"})
	proxyResponse := app.proxyResponse(proxyBody)
	if proxyResponse.StatusCode != http.StatusForbidden {
		t.Fatalf("proxy status = %d, want %d", proxyResponse.StatusCode, http.StatusForbidden)
	}
	quotaBody, _ := json.Marshal(authIndexRequest{AuthIndex: "codex-1"})
	quotaResponse := app.quotaResponse(quotaBody, "")
	if quotaResponse.StatusCode != http.StatusForbidden {
		t.Fatalf("quota status = %d, want %d", quotaResponse.StatusCode, http.StatusForbidden)
	}
	if len(host.overrides()) != 0 || len(host.authRequests) != 0 {
		t.Fatal("rejected target must not invoke side-effect host callbacks")
	}
}

func TestManagementManualRecoveryAllowsCodexTarget(t *testing.T) {
	host := &fakeHost{auths: []hostAuthEntry{{AuthIndex: "codex-1", Provider: "codex", Name: "codex.json"}}}
	app := newApplication(host)
	defer app.shutdown()

	body, _ := json.Marshal(authIndexRequest{AuthIndex: "codex-1"})
	response := app.dispatchManagement(managementRequest{Method: http.MethodPost, Path: managementAPIPath + "/recover", Body: body})
	if response.StatusCode != http.StatusOK {
		t.Fatalf("recovery status = %d, body=%s", response.StatusCode, response.Body)
	}
}

func TestProxyDirectAndClearHaveDistinctRuntimeRequests(t *testing.T) {
	host := &fakeHost{auths: []hostAuthEntry{{AuthIndex: "ag-1", Provider: "antigravity", Name: "ag.json"}}}
	app := newApplication(host)
	defer app.shutdown()

	directBody, _ := json.Marshal(proxyActionRequest{AuthIndex: "ag-1", Mode: "direct"})
	if response := app.proxyResponse(directBody); response.StatusCode != http.StatusOK {
		t.Fatalf("direct status = %d, body=%s", response.StatusCode, response.Body)
	}
	clearBody, _ := json.Marshal(proxyActionRequest{AuthIndex: "ag-1", Mode: "clear"})
	if response := app.proxyResponse(clearBody); response.StatusCode != http.StatusOK {
		t.Fatalf("clear status = %d, body=%s", response.StatusCode, response.Body)
	}

	requests := host.overrides()
	if len(requests) != 2 {
		t.Fatalf("override request count = %d", len(requests))
	}
	if requests[0].ProxyURL == nil || *requests[0].ProxyURL != "direct" {
		t.Fatalf("direct request = %#v", requests[0])
	}
	if len(requests[1].Clear) != 1 || requests[1].Clear[0] != "proxy_url" {
		t.Fatalf("clear request = %#v", requests[1])
	}
}

func TestManagedProxyCleanupDoesNotOverwriteManualSameValueWrite(t *testing.T) {
	host := &fakeHost{auths: []hostAuthEntry{{AuthIndex: "ag-proxy-cas", Provider: "antigravity", Name: "ag.json"}}}
	store := newStateStore()
	guard := newGuard(host, store, testConfig)
	proxyURL := "direct"
	if errSet := guard.setProxy("ag-proxy-cas", &proxyURL); errSet != nil {
		t.Fatalf("setProxy() error = %v", errSet)
	}

	host.setRuntimeOverride("ag-proxy-cas", &runtimeOverride{ProxyURL: &proxyURL})
	guard.clearManagedProxies()

	requests := host.overrides()
	if len(requests) != 2 || requests[1].IfRevision == nil || requests[1].IfRevisionField != "proxy_url" {
		t.Fatalf("proxy cleanup CAS request = %#v", requests)
	}
	entries, errList := host.ListAuths()
	if errList != nil {
		t.Fatal(errList)
	}
	if entries[0].RuntimeOverride == nil || entries[0].RuntimeOverride.ProxyURL == nil || *entries[0].RuntimeOverride.ProxyURL != proxyURL {
		t.Fatalf("manual proxy write was cleared: %#v", entries[0].RuntimeOverride)
	}
	if state := store.snapshot("ag-proxy-cas", time.Now()); state.ManagedProxy != nil {
		t.Fatalf("stale managed proxy tracking was retained: %#v", state.ManagedProxy)
	}
}

func TestProxyCopyUsesSourceEffectiveProxy(t *testing.T) {
	const sourceProxy = "socks5://proxy-user:proxy-secret@127.0.0.1:1080"
	host := &fakeHost{auths: []hostAuthEntry{
		{AuthIndex: "ag-target", Provider: "antigravity", Name: "target.json"},
		{
			AuthIndex:          "ag-source",
			Provider:           "antigravity",
			Name:               "source.json",
			ConfiguredProxyURL: sourceProxy,
			EffectiveProxyURL:  sourceProxy,
		},
	}}
	app := newApplication(host)
	defer app.shutdown()

	body, _ := json.Marshal(proxyActionRequest{
		AuthIndex:       "ag-target",
		Mode:            "copy",
		SourceAuthIndex: "ag-source",
	})
	response := app.proxyResponse(body)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("copy status = %d, body=%s", response.StatusCode, response.Body)
	}
	requests := host.overrides()
	if len(requests) != 1 || requests[0].ProxyURL == nil || *requests[0].ProxyURL != sourceProxy {
		t.Fatalf("copy request = %#v, want source proxy", requests)
	}
	if containsText(string(response.Body), "proxy-secret") {
		t.Fatalf("copy response leaked proxy password: %s", response.Body)
	}
}

func TestProxyCopyRejectsDirectSource(t *testing.T) {
	host := &fakeHost{auths: []hostAuthEntry{
		{AuthIndex: "ag-target", Provider: "antigravity", Name: "target.json"},
		{AuthIndex: "ag-source", Provider: "antigravity", Name: "source.json", EffectiveProxyURL: "direct"},
	}}
	app := newApplication(host)
	defer app.shutdown()

	body, _ := json.Marshal(proxyActionRequest{
		AuthIndex:       "ag-target",
		Mode:            "copy",
		SourceAuthIndex: "ag-source",
	})
	response := app.proxyResponse(body)
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("copy direct status = %d, body=%s", response.StatusCode, response.Body)
	}
	if len(host.overrides()) != 0 {
		t.Fatal("rejected copy must not update runtime proxy")
	}
}

func TestDashboardMarksReusableProxyWithoutExposingPassword(t *testing.T) {
	const sourceProxy = "socks5://proxy-user:proxy-secret@127.0.0.1:1080"
	host := &fakeHost{auths: []hostAuthEntry{{
		AuthIndex:          "ag-source",
		Provider:           "antigravity",
		Name:               "source.json",
		ConfiguredProxyURL: sourceProxy,
		EffectiveProxyURL:  sourceProxy,
	}}}
	app := newApplication(host)
	defer app.shutdown()

	state, errState := app.auth.dashboard()
	if errState != nil {
		t.Fatal(errState)
	}
	if len(state.Credentials) != 1 || !state.Credentials[0].ProxyReusable {
		t.Fatalf("credential state = %#v, want reusable proxy", state.Credentials)
	}
	raw, errMarshal := json.Marshal(state)
	if errMarshal != nil {
		t.Fatal(errMarshal)
	}
	if containsText(string(raw), "proxy-secret") {
		t.Fatalf("dashboard leaked proxy password: %s", raw)
	}
}

func TestManagementQuotaPropagatesHostCallbackID(t *testing.T) {
	now := time.Date(2026, time.July, 25, 12, 0, 0, 0, time.UTC)
	reset := now.Add(7 * 24 * time.Hour)
	host := &fakeHost{
		auths: []hostAuthEntry{{
			AuthIndex: "ag-1",
			Provider:  "antigravity",
			Name:      "ag.json",
			ProjectID: "project-123",
		}},
		requestResponse: hostAuthResponse{
			StatusCode: http.StatusOK,
			Body:       []byte(`{"groups":[{"displayName":"Gemini models","buckets":[{"window":"weekly","remainingFraction":0,"resetTime":"` + reset.Format(time.RFC3339) + `"}]}]}`),
		},
	}
	app := newApplication(host)
	defer app.shutdown()
	app.quota.now = func() time.Time { return now }

	body, errMarshal := json.Marshal(authIndexRequest{AuthIndex: "ag-1"})
	if errMarshal != nil {
		t.Fatal(errMarshal)
	}
	response := app.dispatchManagement(managementRequest{
		Method:         http.MethodPost,
		Path:           managementAPIPath + "/quota",
		Body:           body,
		HostCallbackID: "management-callback-123",
	})
	if response.StatusCode != http.StatusOK {
		t.Fatalf("quota status = %d, body=%s", response.StatusCode, response.Body)
	}
	if len(host.authRequests) != 1 {
		t.Fatalf("auth request count = %d, want 1", len(host.authRequests))
	}
	if got := host.authRequests[0].HostCallbackID; got != "management-callback-123" {
		t.Fatalf("host callback ID = %q, want management-callback-123", got)
	}
}

func TestResourceRouteIsStaticAndHasNoSideEffects(t *testing.T) {
	host := &fakeHost{}
	app := newApplication(host)
	defer app.shutdown()
	rawRequest, _ := json.Marshal(managementRequest{Method: http.MethodGet, Path: resourceBasePath + "/dashboard"})

	rawResponse, errHandle := app.handleManagement(rawRequest)
	if errHandle != nil {
		t.Fatal(errHandle)
	}
	if len(rawResponse) == 0 {
		t.Fatal("resource response is empty")
	}
	if len(host.overrides()) != 0 || len(host.authRequests) != 0 {
		t.Fatal("resource route must not invoke host side effects")
	}
}

func TestEmbeddedManagementAssetsAreServedWithSecurityHeaders(t *testing.T) {
	tests := map[string]string{
		"/dashboard":              "text/html; charset=utf-8",
		"/assets/styles.css":      "text/css; charset=utf-8",
		"/assets/settings.css":    "text/css; charset=utf-8",
		"/assets/credentials.css": "text/css; charset=utf-8",
		"/assets/api.js":          "text/javascript; charset=utf-8",
		"/assets/format.js":       "text/javascript; charset=utf-8",
		"/assets/search.js":       "text/javascript; charset=utf-8",
		"/assets/proxy.js":        "text/javascript; charset=utf-8",
		"/assets/settings.js":     "text/javascript; charset=utf-8",
		"/assets/codex.js":        "text/javascript; charset=utf-8",
		"/assets/app.js":          "text/javascript; charset=utf-8",
	}
	for path, contentType := range tests {
		response, errResource := resourceResponse(resourceBasePath + path)
		if errResource != nil {
			t.Fatalf("resourceResponse(%q) error = %v", path, errResource)
		}
		if response.StatusCode != http.StatusOK || len(response.Body) == 0 {
			t.Fatalf("resourceResponse(%q) = status %d, body length %d", path, response.StatusCode, len(response.Body))
		}
		if got := response.Headers.Get("Content-Type"); got != contentType {
			t.Fatalf("resourceResponse(%q) Content-Type = %q, want %q", path, got, contentType)
		}
		if response.Headers.Get("Content-Security-Policy") == "" {
			t.Fatalf("resourceResponse(%q) missing Content-Security-Policy", path)
		}
	}
}
