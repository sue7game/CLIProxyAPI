package handlers

import (
	"context"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	sdkaccess "github.com/router-for-me/CLIProxyAPI/v8/sdk/access"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/config"
)

func TestContextWithCancelBridgesAuthenticatedPrincipal(t *testing.T) {
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest("POST", "/v1/responses", nil)
	c.Request = c.Request.WithContext(sdkaccess.WithAuthenticatedPrincipal(c.Request.Context(), "config-inline", "verified-subject"))
	c.Set("userApiKey", "untrusted-override")
	c.Set("accessProvider", "untrusted-provider")
	h := &BaseAPIHandler{Cfg: &config.SDKConfig{}}
	ctx, cancel := h.GetContextWithCancel(nil, c, context.Background())
	defer cancel()
	principal, ok := sdkaccess.AuthenticatedPrincipalFromContext(ctx)
	if !ok || principal.Provider != "config-inline" || principal.Subject != "verified-subject" {
		t.Fatal("trusted request identity was dropped or replaced")
	}
}

func TestContextWithCancelRejectsMetadataPrincipal(t *testing.T) {
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest("POST", "/v1/responses", nil)
	c.Request.Header.Set("X-Group-ID", "all")
	c.Set("userApiKey", "forged-subject")
	c.Set("accessProvider", "config-inline")
	parent := sdkaccess.WithAuthenticatedPrincipal(context.Background(), "parent", "unrelated-subject")
	h := &BaseAPIHandler{Cfg: &config.SDKConfig{}}
	ctx, cancel := h.GetContextWithCancel(nil, c, parent)
	defer cancel()
	if _, ok := sdkaccess.AuthenticatedPrincipalFromContext(ctx); ok {
		t.Fatal("request inherited an unverified or unrelated identity")
	}
}
