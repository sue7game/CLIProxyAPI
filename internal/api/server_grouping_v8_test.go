package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestGroupingConfigETagAvailableToCrossOriginManagementUI(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(corsMiddleware())
	router.GET("/v8/management/config", func(c *gin.Context) {
		c.Header("ETag", `"revision"`)
		c.JSON(http.StatusOK, gin.H{})
	})
	request := httptest.NewRequest("OPTIONS", "/v8/management/config", nil)
	request.Header.Set("Origin", "http://127.0.0.1:3000")
	request.Header.Set("Access-Control-Request-Method", "PUT")
	request.Header.Set("Access-Control-Request-Headers", "Authorization, Content-Type, If-Match")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusNoContent || !strings.Contains(response.Header().Get("Access-Control-Allow-Headers"), "If-Match") {
		t.Fatal("cross-origin precondition header was not allowed")
	}
	response = httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest("GET", "/v8/management/config", nil))
	if !strings.Contains(response.Header().Get("Access-Control-Expose-Headers"), "ETag") || response.Header().Get("ETag") == "" {
		t.Fatal("cross-origin configuration ETag was not exposed")
	}
}

func TestGroupingRoutesAreV8Only(t *testing.T) {
	t.Setenv("MANAGEMENT_PASSWORD", "test-management-key")
	server := newTestServer(t)
	for _, version := range []string{"v0", "v8"} {
		request := httptest.NewRequest(http.MethodGet, "/"+version+"/management/grouping/status", nil)
		request.Header.Set("Authorization", "Bearer test-management-key")
		response := httptest.NewRecorder()
		server.engine.ServeHTTP(response, request)
		want := http.StatusNotFound
		if version == "v8" {
			want = http.StatusServiceUnavailable
		}
		if response.Code != want {
			t.Fatalf("%s grouping route status=%d, want %d; body=%s", version, response.Code, want, response.Body.String())
		}
	}
}
