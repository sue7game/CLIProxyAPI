package openai

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/access"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/api/handlers"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	sdkconfig "github.com/router-for-me/CLIProxyAPI/v8/sdk/config"
	"github.com/tidwall/gjson"
)

type sessionGroupingPolicy struct {
	authID  string
	revoked atomic.Bool
}

func (p *sessionGroupingPolicy) BeginAttempt(ctx context.Context) (coreauth.CredentialAccessScope, error) {
	principal, ok := access.AuthenticatedPrincipalFromContext(ctx)
	if !ok || principal.Subject != "session-token" || p.revoked.Load() {
		return nil, websocketCredentialUnavailable()
	}
	return p, nil
}

func (p *sessionGroupingPolicy) Allows(auth *coreauth.Auth) bool {
	return auth != nil && auth.ID == p.authID
}

func (p *sessionGroupingPolicy) AuthorizeUse(_ context.Context, a *coreauth.Auth) error {
	if p.revoked.Load() || !p.Allows(a) {
		return websocketCredentialUnavailable()
	}
	return nil
}

func newGroupingSessionManager(t *testing.T, provider, model string) (*coreauth.Manager, *sessionGroupingPolicy) {
	t.Helper()
	m := coreauth.NewManager(nil, &coreauth.FillFirstSelector{}, nil)
	p := &sessionGroupingPolicy{authID: "grouping-session-" + provider}
	if _, err := m.Register(context.Background(), &coreauth.Auth{ID: p.authID, Provider: provider, Status: coreauth.StatusActive,
		Attributes: map[string]string{"grouping_id": "2bc7d94f-e50c-42bd-b1f9-41d90e066b15"}}); err != nil {
		t.Fatal(err)
	}
	r := registry.GetGlobalRegistry()
	r.RegisterClient(p.authID, provider, []*registry.ModelInfo{{ID: model}})
	t.Cleanup(func() { r.UnregisterClient(p.authID) })
	m.SetCredentialAccessPolicy(p)
	return m, p
}

func trustedGroupingRequest(c *gin.Context) {
	c.Request = c.Request.WithContext(access.WithAuthenticatedPrincipal(c.Request.Context(), "test", "session-token"))
}

func TestGroupingResponsesWebsocketRechecksEveryTurn(t *testing.T) {
	manager, policy := newGroupingSessionManager(t, "test-provider", "grouping-ws-model")
	executor := &websocketAuthCaptureExecutor{}
	manager.RegisterExecutor(executor)
	h := NewOpenAIResponsesAPIHandler(handlers.NewBaseAPIHandlers(&sdkconfig.SDKConfig{}, manager))
	router := gin.New()
	router.GET("/v1/responses", trustedGroupingRequest, h.ResponsesWebsocket)
	server := httptest.NewServer(router)
	defer server.Close()
	conn, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(server.URL, "http")+"/v1/responses", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	request := []byte(`{"type":"response.create","model":"grouping-ws-model","input":[{"role":"user","content":"hello"}]}`)
	if err = conn.WriteMessage(websocket.TextMessage, request); err != nil {
		t.Fatal(err)
	}
	if _, first, errRead := conn.ReadMessage(); errRead != nil || !strings.Contains(string(first), "response.completed") {
		t.Fatalf("first response = %s, %v", first, errRead)
	}
	policy.revoked.Store(true)
	if err = conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"response.interrupt","response_id":"active"}`)); err != nil {
		t.Fatal(err)
	}
	if _, interrupted, errRead := conn.ReadMessage(); errRead != nil || gjson.GetBytes(interrupted, "status").Int() != http.StatusForbidden {
		t.Fatalf("revoked interrupt response = %s, %v", interrupted, errRead)
	}
	if err = conn.WriteMessage(websocket.TextMessage, request); err != nil {
		t.Fatal(err)
	}
	if err = conn.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	_, payload, err := conn.ReadMessage()
	if err != nil || !strings.Contains(string(payload), "error") {
		t.Fatalf("revoked turn response = %s, %v", payload, err)
	}
	if _, _, err = conn.ReadMessage(); err == nil {
		t.Fatal("revoked websocket remained open")
	}
	if calls := executor.AuthIDs(); len(calls) != 1 {
		t.Fatalf("upstream calls = %v, want one", calls)
	}
}

func TestGroupingWebsocketPrewarmCannotSkipPrincipalCheck(t *testing.T) {
	manager, policy := newGroupingSessionManager(t, "test-provider", "grouping-prewarm-model")
	h := NewOpenAIResponsesAPIHandler(&handlers.BaseAPIHandler{AuthManager: manager})
	ctx := access.WithAuthenticatedPrincipal(context.Background(), "test", "session-token")
	if err := h.authorizeWebsocketTurn(ctx, ""); err != nil {
		t.Fatal(err)
	}
	policy.revoked.Store(true)
	if err := h.authorizeWebsocketTurn(ctx, ""); err == nil {
		t.Fatal("revoked principal accepted before synthetic prewarm")
	}
	manager.SetCredentialAccessPolicy(nil)
	if err := h.authorizeWebsocketTurn(context.Background(), "unknown"); err != nil {
		t.Fatalf("disabled policy changed legacy behavior: %v", err)
	}
}

func TestGroupingVideoUnknownAndRevokedBindingNeverExecutes(t *testing.T) {
	manager, policy := newGroupingSessionManager(t, "xai", defaultXAIVideosModel)
	executor := &videoAuthCaptureExecutor{}
	manager.RegisterExecutor(executor)
	h := NewOpenAIAPIHandler(handlers.NewBaseAPIHandlers(&sdkconfig.SDKConfig{}, manager))
	router := gin.New()
	router.Use(trustedGroupingRequest)
	router.GET("/v1/videos/:video_id", h.VideosRetrieve)
	request := func(id string) *httptest.ResponseRecorder {
		response := httptest.NewRecorder()
		router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/v1/videos/"+id, nil))
		return response
	}
	if response := request("grouping-unknown-video"); response.Code != http.StatusForbidden {
		t.Fatalf("unknown binding = %d %s", response.Code, response.Body.String())
	}
	credential, _ := manager.GetByID(policy.authID)
	videoAuthBindings.setWithCredential("grouping-bound-video", policy.authID, "", time.Hour, credential)
	policy.revoked.Store(true)
	if response := request("grouping-bound-video"); response.Code != http.StatusForbidden {
		t.Fatalf("revoked binding = %d %s", response.Code, response.Body.String())
	}
	if len(executor.AuthIDs()) != 0 {
		t.Fatal("denied video reached upstream")
	}
	policy.revoked.Store(false)
	if response := request("grouping-bound-video"); response.Code != http.StatusOK {
		t.Fatalf("allowed binding = %d %s", response.Code, response.Body.String())
	}
	if calls := executor.AuthIDs(); len(calls) != 1 || calls[0] != policy.authID {
		t.Fatalf("video did not use fixed auth: %v", calls)
	}
}

func TestGroupingVideoDirectDownloadRechecksAuthorization(t *testing.T) {
	manager, policy := newGroupingSessionManager(t, "xai", defaultXAIVideosModel)
	h := NewOpenAIAPIHandler(&handlers.BaseAPIHandler{AuthManager: manager})
	policy.revoked.Store(true)
	credential, _ := manager.GetByID(policy.authID)
	videoAuthBindings.setWithCredential("grouping-download-video", policy.authID, "", time.Hour, credential)
	var upstreamCalls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { upstreamCalls.Add(1) }))
	defer server.Close()
	response := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(response)
	c.Request = httptest.NewRequest(http.MethodGet, "/v1/videos/grouping-download-video/content", nil)
	c.Params = gin.Params{{Key: "video_id", Value: "grouping-download-video"}}
	trustedGroupingRequest(c)
	if err := h.writeVideoContentFromURL(c, server.URL); err == nil || response.Code != http.StatusForbidden {
		t.Fatalf("download status = %d error = %v", response.Code, err)
	}
	if upstreamCalls.Load() != 0 {
		t.Fatal("revoked video made a download request")
	}
}
