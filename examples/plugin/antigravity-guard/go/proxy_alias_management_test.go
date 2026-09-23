package main

import (
	"encoding/json"
	"net/http"
	"testing"
)

func TestDashboardGroupsCanonicalProxiesAndSeparatesPasswords(t *testing.T) {
	firstRuntimeProxy := "socks5://alice:first-secret@proxy.example:1080"
	host := &fakeHost{auths: []hostAuthEntry{
		{
			AuthIndex:          "ag-configured",
			Provider:           "antigravity",
			Name:               "configured.json",
			ConfiguredProxyURL: "SOCKS5://alice:first-secret@Proxy.Example:1080",
		},
		{
			AuthIndex:       "ag-runtime",
			Provider:        "antigravity",
			Name:            "runtime.json",
			RuntimeOverride: &runtimeOverride{ProxyURL: &firstRuntimeProxy},
		},
		{
			AuthIndex:          "ag-other-password",
			Provider:           "antigravity",
			Name:               "other.json",
			ConfiguredProxyURL: "socks5://alice:second-secret@proxy.example:1080",
		},
	}}
	app := newApplication(host)
	defer app.shutdown()

	state, errState := app.auth.dashboard()
	if errState != nil {
		t.Fatal(errState)
	}
	if len(state.Credentials) != 3 || len(state.ProxyGroups) != 2 {
		t.Fatalf("credentials=%d proxy groups=%d, want 3 and 2", len(state.Credentials), len(state.ProxyGroups))
	}
	credentials := credentialsByAuthIndex(state.Credentials)
	configured := credentials["ag-configured"]
	runtime := credentials["ag-runtime"]
	other := credentials["ag-other-password"]
	if configured.ProxyID == "" || configured.ProxyID != runtime.ProxyID {
		t.Fatalf("equivalent proxy IDs = %q and %q", configured.ProxyID, runtime.ProxyID)
	}
	if configured.ProxyID == other.ProxyID {
		t.Fatal("proxies with different passwords were merged")
	}
	group := proxyGroupByID(state.ProxyGroups, configured.ProxyID)
	if group == nil || group.Credentials != 2 || group.Source != "mixed" {
		t.Fatalf("merged proxy group = %#v", group)
	}
	raw, errMarshal := json.Marshal(state)
	if errMarshal != nil {
		t.Fatal(errMarshal)
	}
	for _, secret := range []string{"first-secret", "second-secret"} {
		if containsText(string(raw), secret) {
			t.Fatalf("dashboard leaked proxy password %q: %s", secret, raw)
		}
	}
}

func TestProxyAliasEndpointUpdatesDashboardAndClearsInMemoryAlias(t *testing.T) {
	const firstProxy = "socks5://alice:first-secret@proxy-one.example:1080"
	const secondProxy = "socks5://bob:second-secret@proxy-two.example:1080"
	host := &fakeHost{auths: []hostAuthEntry{
		{AuthIndex: "ag-1", Provider: "antigravity", Name: "one.json", ConfiguredProxyURL: firstProxy},
		{AuthIndex: "ag-2", Provider: "antigravity", Name: "two.json", ConfiguredProxyURL: secondProxy},
	}}
	app := newApplication(host)
	defer app.shutdown()

	initial, errState := app.auth.dashboard()
	if errState != nil {
		t.Fatal(errState)
	}
	firstID := credentialsByAuthIndex(initial.Credentials)["ag-1"].ProxyID
	secondID := credentialsByAuthIndex(initial.Credentials)["ag-2"].ProxyID

	response := postProxyAlias(app, firstID, "美国住宅 Proxy 01")
	if response.StatusCode != http.StatusOK {
		t.Fatalf("set alias status=%d body=%s", response.StatusCode, response.Body)
	}
	updated, errUpdated := app.auth.dashboard()
	if errUpdated != nil {
		t.Fatal(errUpdated)
	}
	credential := credentialsByAuthIndex(updated.Credentials)["ag-1"]
	group := proxyGroupByID(updated.ProxyGroups, firstID)
	if credential.ProxyAlias != "美国住宅 Proxy 01" || group == nil || group.ProxyAlias != "美国住宅 Proxy 01" {
		t.Fatalf("credential alias=%q group=%#v", credential.ProxyAlias, group)
	}

	if duplicate := postProxyAlias(app, secondID, "美国住宅 proxy 01"); duplicate.StatusCode != http.StatusBadRequest {
		t.Fatalf("duplicate alias status=%d body=%s", duplicate.StatusCode, duplicate.Body)
	}
	if cleared := postProxyAlias(app, firstID, ""); cleared.StatusCode != http.StatusOK {
		t.Fatalf("clear alias status=%d body=%s", cleared.StatusCode, cleared.Body)
	}
	clearedState, errCleared := app.auth.dashboard()
	if errCleared != nil {
		t.Fatal(errCleared)
	}
	if credentialsByAuthIndex(clearedState.Credentials)["ag-1"].ProxyAlias != "" {
		t.Fatal("cleared alias remains on credential")
	}

	raw, errMarshal := json.Marshal(clearedState)
	if errMarshal != nil {
		t.Fatal(errMarshal)
	}
	if containsText(string(raw), "first-secret") || containsText(string(response.Body), "first-secret") {
		t.Fatal("alias flow leaked a proxy password")
	}
}

func TestProxyAliasEndpointRejectsNonCurrentAntigravityProxy(t *testing.T) {
	const codexProxy = "socks5://codex:secret@proxy.example:1080"
	host := &fakeHost{auths: []hostAuthEntry{
		{AuthIndex: "codex-1", Provider: "codex", Name: "codex.json", ConfiguredProxyURL: codexProxy},
	}}
	app := newApplication(host)
	defer app.shutdown()

	descriptor, reusable := app.proxies.describe(codexProxy)
	if !reusable {
		t.Fatal("test proxy must be reusable")
	}
	response := postProxyAlias(app, descriptor.ID, "Codex proxy")
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("non-Antigravity alias status=%d body=%s", response.StatusCode, response.Body)
	}
	if containsText(string(response.Body), "secret") {
		t.Fatal("rejected alias response leaked proxy password")
	}
}

func TestManagementRegistrationIncludesProxyAliasRoute(t *testing.T) {
	wantPath := "/plugins/" + pluginID + "/proxy/alias"
	for _, route := range managementRoutes().Routes {
		if route.Method == http.MethodPost && route.Path == wantPath {
			return
		}
	}
	t.Fatalf("management route %q is not registered", wantPath)
}

func postProxyAlias(app *application, proxyID, alias string) managementResponse {
	body, _ := json.Marshal(proxyAliasRequest{ProxyID: proxyID, Alias: alias})
	return app.dispatchManagement(managementRequest{
		Method: http.MethodPost,
		Path:   managementAPIPath + "/proxy/alias",
		Body:   body,
	})
}

func credentialsByAuthIndex(credentials []credentialView) map[string]credentialView {
	result := make(map[string]credentialView, len(credentials))
	for _, credential := range credentials {
		result[credential.AuthIndex] = credential
	}
	return result
}

func proxyGroupByID(groups []proxyGroupView, proxyID string) *proxyGroupView {
	for index := range groups {
		if groups[index].ProxyID == proxyID {
			return &groups[index]
		}
	}
	return nil
}
