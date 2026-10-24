package management

import (
	"bytes"
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

const v8GroupingIDFirst = "611fd047-6530-45a7-9ec1-1f5338e0d5fa"
const v8GroupingIDSecond = "7e424bfe-4044-42f7-bcff-0a4852604b45"
const v8GroupingSources = `[{"name":"pair","base-url":"https://codex.example.test","keys":[{"api-key":"same-key","grouping-id":"` + v8GroupingIDFirst + `"},{"api-key":"same-key","grouping-id":"` + v8GroupingIDSecond + `"}]}]`

const v8GroupingDocument = `config-version: 8
grouping: {enabled: true, store-path: ./groups.json}
access: {api-keys: [first-token, second-token]}
requests: {payload: {default: null}}
plugins:
  configs:
    sample: {enabled: false, custom: {empty: {}, nullable: null}}
api-keys:
  codex: ` + v8GroupingSources + `
oauth:
  providers:
    codex:
      live-media-relay:
        ice-servers:
          - urls: [turn:relay.example.test:3478]
            username: retained-user
            credential: retained-secret
`

type v8GroupingFixture struct {
	h      *Handler
	router *gin.Engine
	path   string
	calls  []ConfigApplyRequest
}

func newV8GroupingFixture(t *testing.T, raw string) *v8GroupingFixture {
	t.Helper()
	gin.SetMode(gin.TestMode)
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.ParseConfigBytesPreservingCredentials([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	f := &v8GroupingFixture{h: &Handler{cfg: cfg, configFilePath: path}, router: gin.New(), path: path}
	f.router.Use(func(c *gin.Context) { c.Set(ConfigV8ContextKey, true) })
	for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodPatch, http.MethodDelete} {
		f.router.Handle(method, "/v8/management/config", f.h.ConfigV8)
		f.router.Handle(method, "/v8/management/config/*path", f.h.ConfigV8)
	}
	f.router.PUT("/v8/management/config.yaml", f.h.ConfigV8)
	f.router.PATCH("/v8/management/access/api-keys", f.h.PatchAPIKeysV8)
	f.h.SetConfigApplyHook(func(_ context.Context, req ConfigApplyRequest) error {
		return f.commit(t, req)
	})
	return f
}

func (f *v8GroupingFixture) commit(t *testing.T, req ConfigApplyRequest) error {
	t.Helper()
	f.calls = append(f.calls, req)
	if !bytes.Equal(f.read(t), req.SourceYAML) {
		return &ConfigApplyError{409, "config_changed", "source changed"}
	}
	if _, err := config.EnsureGroupingCredentialIDs(req.Proposed); err != nil {
		return err
	}
	prepared, err := config.PrepareGroupingConfigDocument(req.CanonicalYAML, req.Proposed)
	if err != nil {
		return err
	}
	if err = WriteConfig(f.path, prepared); err != nil {
		return err
	}
	f.h.SetConfig(req.Proposed.CloneForRuntime())
	return nil
}

func (f *v8GroupingFixture) request(method, path, body, etag string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if etag != "" {
		req.Header.Set("If-Match", etag)
	}
	recorder := httptest.NewRecorder()
	f.router.ServeHTTP(recorder, req)
	return recorder
}

func (f *v8GroupingFixture) read(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile(f.path)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func (f *v8GroupingFixture) etag(t *testing.T) string {
	t.Helper()
	response := f.request("GET", "/v8/management/config", "", "")
	if response.Code != http.StatusOK || response.Header().Get("ETag") == "" {
		t.Fatal("configuration GET did not return its precondition")
	}
	return response.Header().Get("ETag")
}
