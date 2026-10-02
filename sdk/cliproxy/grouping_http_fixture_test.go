package cliproxy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/api"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/api/handlers/groupingapi"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/registry"
	sdkaccess "github.com/router-for-me/CLIProxyAPI/v7/sdk/access"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	executor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
)

const groupingHTTPManagementKey = "local-grouping-management-test-only"
const groupingHTTPModel = "grouping-integration-model"

type groupingHTTPFixture struct {
	*groupingIntegrationFixture
	engine   *gin.Engine
	executor *groupingHTTPExecutor
}

func newGroupingHTTPFixture(t *testing.T) *groupingHTTPFixture {
	t.Helper()
	t.Setenv("MANAGEMENT_PASSWORD", groupingHTTPManagementKey)
	f := &groupingHTTPFixture{groupingIntegrationFixture: newGroupingIntegrationFixture(t)}
	s := f.service
	s.accessManager = sdkaccess.NewManager()
	s.server = api.NewServer(s.cfg, s.coreManager, s.accessManager, f.path,
		api.WithEngineConfigurator(func(engine *gin.Engine) { f.engine = engine }),
		api.WithLocalManagementPassword(groupingHTTPManagementKey),
		api.WithGroupingBackend(f.backend), api.WithConfigApplyHook(s.applyGroupingConfigMutation),
		api.WithAuthFileApplyHook(s.grouping.applyAuthFile),
		api.WithPostAuthPersistHook(s.runtimeAuthSyncHook()),
		api.WithGroupingAuthHooks(s.grouping.prepareOAuthRecord, s.grouping.finalizeOAuthRecord),
	)
	return f
}

func (f *groupingHTTPFixture) request(t *testing.T, method, path string, body any, revision uint64, key string) *httptest.ResponseRecorder {
	t.Helper()
	var encoded []byte
	if body != nil {
		var err error
		encoded, err = json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
	}
	req := httptest.NewRequest(method, path, bytes.NewReader(encoded))
	req.RemoteAddr = "127.0.0.1:12345"
	req.Header.Set("Content-Type", "application/json")
	if key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}
	if revision != 0 {
		req.Header.Set("If-Match", fmt.Sprintf("\"%d\"", revision))
	}
	// Untrusted policy headers must not widen the authenticated token's scope.
	req.Header.Set("X-Group-ID", "all")
	req.Header.Set("X-Internal-Operation", "management")
	response := httptest.NewRecorder()
	f.engine.ServeHTTP(response, req)
	return response
}

func (f *groupingHTTPFixture) managed(t *testing.T, method, path string, body any, revision uint64) *httptest.ResponseRecorder {
	t.Helper()
	response := f.request(t, method, "/v0/management"+path, body, revision, groupingHTTPManagementKey)
	if response.Code != http.StatusOK {
		t.Fatalf("management %s %s: %d %s", method, path, response.Code, response.Body.String())
	}
	return response
}

func (f *groupingHTTPFixture) createHTTPGroup(t *testing.T, name string) string {
	t.Helper()
	response := f.managed(t, http.MethodPost, "/grouping/groups", gin.H{"name": name}, f.snapshot(t).Revision)
	var result groupingapi.ApplyResult
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil || result.Group == nil {
		t.Fatalf("invalid group response: %v", err)
	}
	return result.Group.ID
}

func (f *groupingHTTPFixture) installTestExecutor(t *testing.T) {
	t.Helper()
	f.executor = &groupingHTTPExecutor{}
	f.service.coreManager.RegisterExecutor(f.executor)
	for _, auth := range f.service.coreManager.List() {
		registry.GetGlobalRegistry().RegisterClient(auth.ID, "codex", []*registry.ModelInfo{{ID: groupingHTTPModel, Object: "model", OwnedBy: "codex"}})
		f.service.coreManager.RefreshSchedulerEntry(auth.ID)
	}
}

type groupingHTTPExecutor struct{ calls atomic.Int32 }

func (*groupingHTTPExecutor) Identifier() string { return "codex" }
func (e *groupingHTTPExecutor) Execute(context.Context, *coreauth.Auth, executor.Request, executor.Options) (executor.Response, error) {
	e.calls.Add(1)
	return executor.Response{Payload: []byte(`{"id":"grouping-test","object":"chat.completion","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}]}`)}, nil
}
func (*groupingHTTPExecutor) ExecuteStream(context.Context, *coreauth.Auth, executor.Request, executor.Options) (*executor.StreamResult, error) {
	return nil, errors.New("unexpected streaming test request")
}
func (*groupingHTTPExecutor) Refresh(_ context.Context, auth *coreauth.Auth) (*coreauth.Auth, error) {
	return auth, nil
}
func (e *groupingHTTPExecutor) CountTokens(ctx context.Context, auth *coreauth.Auth, request executor.Request, options executor.Options) (executor.Response, error) {
	return e.Execute(ctx, auth, request, options)
}
func (*groupingHTTPExecutor) HttpRequest(context.Context, *coreauth.Auth, *http.Request) (*http.Response, error) {
	return nil, errors.New("unexpected raw upstream request")
}
