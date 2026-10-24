package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	sdkaccess "github.com/router-for-me/CLIProxyAPI/v8/sdk/access"
)

type principalProvider struct{}

func (principalProvider) Identifier() string { return "test-provider" }

func (principalProvider) Authenticate(context.Context, *http.Request) (*sdkaccess.Result, *sdkaccess.AuthError) {
	return &sdkaccess.Result{Provider: "test-provider", Principal: "verified-subject"}, nil
}

func TestAuthMiddlewarePublishesTypedPrincipal(t *testing.T) {
	manager := sdkaccess.NewManager()
	manager.SetProviders([]sdkaccess.Provider{principalProvider{}})
	engine := gin.New()
	engine.Use(AuthMiddleware(manager))
	engine.GET("/", func(c *gin.Context) {
		principal, ok := sdkaccess.AuthenticatedPrincipalFromContext(c.Request.Context())
		if !ok || principal.Provider != "test-provider" || principal.Subject != "verified-subject" {
			t.Error("successful authentication did not publish typed identity")
		}
		c.Status(http.StatusNoContent)
	})
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Group-ID", "all")
	response := httptest.NewRecorder()
	engine.ServeHTTP(response, req)
	if response.Code != http.StatusNoContent {
		t.Fatalf("status = %d", response.Code)
	}
}
