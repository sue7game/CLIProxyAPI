package management

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	sdkaccess "github.com/router-for-me/CLIProxyAPI/v8/sdk/access"
)

func TestManagementMiddlewareInternalScopeRequiresSuccessfulAuthentication(t *testing.T) {
	for _, key := range []string{"management-secret", "wrong-secret", ""} {
		t.Run(key, func(t *testing.T) {
			h := &Handler{
				cfg: &config.Config{}, envSecret: "management-secret",
				failedAttempts: make(map[string]*attemptInfo),
			}
			response := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(response)
			c.Request = httptest.NewRequest(http.MethodGet, "/v0/management/api-call", nil)
			c.Request.RemoteAddr = "127.0.0.1:12345"
			c.Request.Header.Set("X-Management-Key", key)
			c.Request.Header.Set("X-Internal-Operation", "management")
			c.Set("internal_operation", "management")
			h.Middleware()(c)
			operation, present := sdkaccess.InternalOperationFromContext(c.Request.Context())
			if key == "management-secret" {
				if c.IsAborted() || !present || operation != sdkaccess.InternalManagement {
					t.Fatal("authenticated management request did not receive its typed scope")
				}
			} else if !c.IsAborted() || present {
				t.Fatal("unauthenticated request received a typed management scope")
			}
		})
	}
}

func TestManagementMiddlewareScopeReachesProtectedHandler(t *testing.T) {
	h := &Handler{cfg: &config.Config{}, envSecret: "management-secret", failedAttempts: make(map[string]*attemptInfo)}
	engine := gin.New()
	engine.Use(h.Middleware())
	called := false
	engine.GET("/probe", func(c *gin.Context) {
		called = true
		operation, ok := sdkaccess.InternalOperationFromContext(c.Request.Context())
		if !ok || operation != sdkaccess.InternalManagement {
			t.Fatal("scope was not set before c.Next")
		}
		c.Status(http.StatusNoContent)
	})
	req := httptest.NewRequest(http.MethodGet, "/probe", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	req.Header.Set("Authorization", "Bearer management-secret")
	response := httptest.NewRecorder()
	engine.ServeHTTP(response, req)
	if !called || response.Code != http.StatusNoContent {
		t.Fatal("protected handler did not execute")
	}
}
