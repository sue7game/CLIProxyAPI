package handlers_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/access"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/api/handlers"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/api/handlers/claude"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/api/handlers/gemini"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/api/handlers/openai"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

type catalogPolicy struct {
	allowed string
	failUse bool
}

func (p *catalogPolicy) BeginAttempt(ctx context.Context) (coreauth.CredentialAccessScope, error) {
	principal, ok := access.AuthenticatedPrincipalFromContext(ctx)
	if !ok || principal.Subject != "catalog-token" {
		return nil, &coreauth.Error{HTTPStatus: http.StatusForbidden, Message: "missing trusted principal"}
	}
	return p, nil
}

func (p *catalogPolicy) Allows(auth *coreauth.Auth) bool {
	return auth != nil && auth.ID == p.allowed
}

func (p *catalogPolicy) AuthorizeUse(context.Context, *coreauth.Auth) error {
	if p.failUse {
		return &coreauth.Error{HTTPStatus: http.StatusServiceUnavailable, Message: "policy changed"}
	}
	return nil
}

func groupingCatalogFixture(t *testing.T) (*handlers.BaseAPIHandler, *catalogPolicy) {
	t.Helper()
	m := coreauth.NewManager(nil, &coreauth.FillFirstSelector{}, nil)
	r := registry.GetGlobalRegistry()
	for _, suffix := range []string{"allowed", "denied"} {
		id := "grouping-catalog-" + suffix
		if _, err := m.Register(context.Background(), &coreauth.Auth{ID: id, Provider: "test", Attributes: map[string]string{"grouping_id": id}}); err != nil {
			t.Fatal(err)
		}
		r.RegisterClient(id, "test", []*registry.ModelInfo{{ID: "claude-grouping-" + suffix, DisplayName: suffix}})
		t.Cleanup(func() { r.UnregisterClient(id) })
	}
	p := &catalogPolicy{allowed: "grouping-catalog-allowed"}
	m.SetCredentialAccessPolicy(p)
	return &handlers.BaseAPIHandler{AuthManager: m}, p
}

func TestGroupingAllModelCatalogEndpoints(t *testing.T) {
	base, _ := groupingCatalogFixture(t)
	o, c := openai.NewOpenAIAPIHandler(base), claude.NewClaudeCodeAPIHandler(base)
	g, r := gemini.NewGeminiAPIHandler(base), openai.NewOpenAIResponsesAPIHandler(base)
	tests := []struct {
		name, url string
		handler   gin.HandlerFunc
	}{
		{"openai", "/v1/models", o.OpenAIModels},
		{"codex", "/v1/models?client_version=0.130.0", o.OpenAIModels},
		{"responses", "/v1/models", r.OpenAIResponsesModels},
		{"claude", "/v1/models", c.ClaudeModels},
		{"gemini", "/v1beta/models", g.GeminiModels},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, trusted := range []bool{true, false} {
				response := requestCatalog(tt.handler, tt.url, trusted)
				if !trusted {
					if response.Code != http.StatusForbidden {
						t.Fatalf("untrusted status = %d", response.Code)
					}
					continue
				}
				body := response.Body.String()
				if response.Code != http.StatusOK || !strings.Contains(body, "claude-grouping-allowed") || strings.Contains(body, "claude-grouping-denied") {
					t.Fatalf("scoped response = %d %s", response.Code, body)
				}
				if response.Header().Get("Cache-Control") != "no-store" {
					t.Fatal("scoped catalog must not be cached")
				}
			}
		})
	}
}

func requestCatalog(handler gin.HandlerFunc, url string, trusted bool) *httptest.ResponseRecorder {
	response := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(response)
	c.Request = httptest.NewRequest(http.MethodGet, url, nil)
	c.Request.Header.Set("X-Group", "all")
	c.Set("group_id", "all")
	if trusted {
		c.Request = c.Request.WithContext(access.WithAuthenticatedPrincipal(c.Request.Context(), "test", "catalog-token"))
	}
	handler(c)
	return response
}

func TestGroupingCatalogCurrentPolicyAndDisabledCompatibility(t *testing.T) {
	base, policy := groupingCatalogFixture(t)
	h := openai.NewOpenAIAPIHandler(base)
	policy.failUse = true
	response := requestCatalog(h.OpenAIModels, "/v1/models", true)
	if response.Code != http.StatusServiceUnavailable || strings.Contains(response.Body.String(), "claude-grouping-allowed") {
		t.Fatalf("stale policy response = %d %s", response.Code, response.Body.String())
	}
	base.AuthManager.SetCredentialAccessPolicy(nil)
	response = requestCatalog(h.OpenAIModels, "/v1/models", false)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "claude-grouping-denied") {
		t.Fatalf("disabled response = %d %s", response.Code, response.Body.String())
	}
}

func TestGroupingGeminiSingleModelDoesNotRevealDeniedModel(t *testing.T) {
	base, _ := groupingCatalogFixture(t)
	h := gemini.NewGeminiAPIHandler(base)
	for _, suffix := range []string{"allowed", "denied"} {
		handler := func(c *gin.Context) {
			c.Params = gin.Params{{Key: "action", Value: "/claude-grouping-" + suffix}}
			h.GeminiGetHandler(c)
		}
		response := requestCatalog(handler, "/v1beta/models/claude-grouping-"+suffix, true)
		want := http.StatusOK
		if suffix == "denied" {
			want = http.StatusNotFound
		}
		if response.Code != want {
			t.Fatalf("model %s: status = %d", suffix, response.Code)
		}
	}
}

func TestGroupingClaudeModelDetailRemainsScoped(t *testing.T) {
	base, _ := groupingCatalogFixture(t)
	h := claude.NewClaudeCodeAPIHandler(base)
	for _, suffix := range []string{"allowed", "denied"} {
		handler := func(c *gin.Context) {
			c.Set(handlers.ModelDetailIDContextKey, "claude-grouping-"+suffix)
			h.ClaudeModels(c)
		}
		response := requestCatalog(handler, "/v1/models/claude-grouping-"+suffix, true)
		want := http.StatusOK
		if suffix == "denied" {
			want = http.StatusNotFound
		}
		if response.Code != want || strings.Contains(response.Body.String(), "claude-grouping-denied") {
			t.Fatalf("model detail %s: status=%d body=%s", suffix, response.Code, response.Body.String())
		}
		if response.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("scoped model detail must not be cached")
		}
	}
}
