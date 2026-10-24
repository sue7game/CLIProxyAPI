package management

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
)

func legacyGroupingRequest(router *gin.Engine, method, path, body string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	request.RemoteAddr = "127.0.0.1:12345"
	request.Header.Set("X-Management-Key", "management-secret")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	return response
}

func TestGroupingLegacyManagementMutationsRequireV8(t *testing.T) {
	h := &Handler{
		cfg:       &config.Config{Grouping: config.GroupingConfig{Enabled: true}},
		envSecret: "management-secret", failedAttempts: make(map[string]*attemptInfo),
	}
	router := gin.New()
	router.Use(h.Middleware())
	for _, path := range []string{"/v0/management/config", "/v0/management/codex-auth-url", "/v8/management/config"} {
		router.Any(path, func(c *gin.Context) { c.Status(http.StatusNoContent) })
	}
	for _, test := range []struct {
		method string
		path   string
		status int
	}{
		{http.MethodGet, "/v0/management/config", http.StatusNoContent},
		{http.MethodPut, "/v0/management/config", http.StatusConflict},
		{http.MethodPatch, "/v0/management/config", http.StatusConflict},
		{http.MethodDelete, "/v0/management/config", http.StatusConflict},
		{http.MethodGet, "/v0/management/codex-auth-url", http.StatusConflict},
		{http.MethodPut, "/v8/management/config", http.StatusNoContent},
	} {
		response := legacyGroupingRequest(router, test.method, test.path, "")
		if response.Code != test.status {
			t.Fatalf("%s %s: status=%d body=%s", test.method, test.path, response.Code, response.Body.String())
		}
		if test.status == http.StatusConflict && !strings.Contains(response.Body.String(), "/v8/management") {
			t.Fatal("legacy rejection did not identify the supported API")
		}
	}
}

func TestGroupingDisabledLegacyWritesBypassNewTransaction(t *testing.T) {
	h, path, _ := newIssue6631Handler(t, "request-retry: 3\n")
	h.envSecret, h.failedAttempts = "management-secret", make(map[string]*attemptInfo)
	h.SetConfigApplyHook(func(context.Context, ConfigApplyRequest) error {
		t.Fatal("legacy write invoked grouping transaction")
		return nil
	})
	router := gin.New()
	router.Use(h.Middleware())
	router.PUT("/v0/management/request-retry", h.PutRequestRetry)
	router.PUT("/v0/management/config.yaml", h.PutConfigYAML)
	response := legacyGroupingRequest(router, http.MethodPut, "/v0/management/request-retry", `{"value":5}`)
	if response.Code != http.StatusOK || readIssue6631Disk(t, path).RequestRetry != 5 {
		t.Fatalf("legacy update failed: %d %s", response.Code, response.Body.String())
	}
	before, errRead := os.ReadFile(path)
	if errRead != nil {
		t.Fatal(errRead)
	}
	response = legacyGroupingRequest(router, http.MethodPut, "/v0/management/config.yaml", "grouping: {enabled: true}\n")
	after, errRead := os.ReadFile(path)
	if response.Code != http.StatusConflict || errRead != nil || string(before) != string(after) {
		t.Fatalf("legacy endpoint enabled grouping: %d %s", response.Code, response.Body.String())
	}
}

func TestGroupingDisabledLegacyUploadBypassesNewHook(t *testing.T) {
	dir := t.TempDir()
	h := &Handler{cfg: &config.Config{AuthDir: dir}}
	h.SetAuthFileApplyHook(func(context.Context, string, []byte) error {
		t.Fatal("legacy upload invoked grouping transaction")
		return nil
	})
	ctx := context.WithValue(context.Background(), legacyManagementContextKey{}, true)
	if errWrite := h.writeAuthFile(ctx, "credential.json", []byte(`{"type":"codex","access_token":"fixture-token"}`)); errWrite != nil {
		t.Fatal(errWrite)
	}
	if _, errStat := os.Stat(filepath.Join(dir, "credential.json")); errStat != nil {
		t.Fatal(errStat)
	}
}
