package cliproxy

import (
	"bytes"
	"net/http"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/api/handlers/groupingapi"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/grouping"
)

func TestGroupingHTTPAuthenticationAndPermissionMatrix(t *testing.T) {
	f := newGroupingHTTPFixture(t)
	response := f.request(t, http.MethodPost, "/v0/management/grouping/initialize", gin.H{}, 0, "")
	if response.Code < 400 || f.service.grouping.store != nil {
		t.Fatal("unauthenticated management initialized policy")
	}
	f.managed(t, http.MethodPost, "/grouping/initialize", gin.H{}, 0)
	a, b := f.createHTTPGroup(t, "HTTP Team A"), f.createHTTPGroup(t, "HTTP Team B")
	var tokenID string
	var credentials []string
	for id, identity := range f.snapshot(t).Identities {
		if identity.Kind == grouping.Token {
			tokenID = id
		} else {
			credentials = append(credentials, id)
		}
	}
	bind := func(request groupingapi.BindingRequest) {
		request.ConfirmPermissionExpansion = true
		f.managed(t, http.MethodPatch, "/grouping/bindings", request, f.snapshot(t).Revision)
	}
	bind(groupingapi.BindingRequest{TokenIDs: []string{tokenID}, GroupID: a})
	bind(groupingapi.BindingRequest{CredentialIDs: credentials, GroupID: b})
	f.managed(t, http.MethodPatch, "/grouping/activation", gin.H{"enabled": true}, f.snapshot(t).Revision)
	f.installTestExecutor(t)
	assertGroupingHTTPRequest(t, f, false)
	bind(groupingapi.BindingRequest{TokenIDs: []string{tokenID}, GroupID: b})
	assertGroupingHTTPRequest(t, f, true)
	bind(groupingapi.BindingRequest{TokenIDs: []string{tokenID}, GroupID: grouping.AllGroups})
	assertGroupingHTTPRequest(t, f, true)
	bind(groupingapi.BindingRequest{TokenIDs: []string{tokenID}, GroupID: a})
	bind(groupingapi.BindingRequest{CredentialIDs: credentials[:1], GroupID: grouping.AllGroups})
	assertGroupingHTTPRequest(t, f, true)
	for _, path := range []string{"/grouping/credentials", "/grouping/tokens"} {
		response := f.managed(t, http.MethodGet, path, nil, 0)
		for _, secret := range []string{"integration-upstream-only", "integration-downstream-only", "integration-oauth-only", "fingerprint", "access_token"} {
			if bytes.Contains(response.Body.Bytes(), []byte(secret)) {
				t.Fatal("grouping list exposed credential material")
			}
		}
	}
}

func assertGroupingHTTPRequest(t *testing.T, f *groupingHTTPFixture, allowed bool) {
	t.Helper()
	before := f.executor.calls.Load()
	response := f.request(t, http.MethodPost, "/v1/chat/completions", gin.H{"model": groupingHTTPModel, "messages": []gin.H{{"role": "user", "content": "local fixture"}}}, 0, "integration-downstream-only")
	if allowed && (response.Code != http.StatusOK || f.executor.calls.Load() != before+1) {
		t.Fatalf("allowed request failed: %d %s", response.Code, response.Body.String())
	}
	if !allowed && (response.Code < 400 || f.executor.calls.Load() != before) {
		t.Fatalf("cross-group request reached executor: %d", response.Code)
	}
	models := f.request(t, http.MethodGet, "/v1/models", nil, 0, "integration-downstream-only")
	if models.Code != http.StatusOK || bytes.Contains(models.Body.Bytes(), []byte(groupingHTTPModel)) != allowed {
		t.Fatalf("models union disagrees with authorization: %d %s", models.Code, models.Body.String())
	}
}

func TestGroupingHTTPConfigEditsPublishAuthoritativeUUIDs(t *testing.T) {
	f := newGroupingHTTPFixture(t)
	f.managed(t, http.MethodPost, "/grouping/initialize", gin.H{}, 0)
	keys := append(f.service.cfg.CloneForRuntime().CodexKey, f.service.cfg.CodexKey[0])
	keys[len(keys)-1].GroupingID = ""
	f.managed(t, http.MethodPut, "/codex-api-key", keys, 0)
	if len(f.service.cfg.CodexKey) != 3 || f.service.cfg.CodexKey[2].GroupingID == "" {
		t.Fatal("new source UUID was not published")
	}
	f.managed(t, http.MethodPatch, "/api-keys", gin.H{"index": 0, "value": "http-rotated-token-only"}, 0)
	if f.service.cfg.APIKeys[0] != "http-rotated-token-only" {
		t.Fatal("next edit saw a stale Handler snapshot")
	}
}
