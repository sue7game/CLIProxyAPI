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
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/access"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/api/handlers"
	sdkconfig "github.com/router-for-me/CLIProxyAPI/v8/sdk/config"
)

type groupingReauthProvider struct{ subject atomic.Value }

func (*groupingReauthProvider) Identifier() string { return "test" }

func (p *groupingReauthProvider) Authenticate(context.Context, *http.Request) (*access.Result, *access.AuthError) {
	subject, _ := p.subject.Load().(string)
	return &access.Result{Provider: p.Identifier(), Principal: subject}, nil
}

func TestGroupingWebsocketUsesFreshPrincipalBeforeSelection(t *testing.T) {
	conn, provider, executor := groupingReauthFixture(t)
	request := []byte(`{"type":"response.create","model":"grouping-reauth-model","input":[]}`)
	if errWrite := conn.WriteMessage(websocket.TextMessage, request); errWrite != nil {
		t.Fatal(errWrite)
	}
	if _, body, errRead := conn.ReadMessage(); errRead != nil || !strings.Contains(string(body), "response.completed") {
		t.Fatalf("first turn used stale handshake identity: body=%s error=%v", body, errRead)
	}
	provider.subject.Store("different-subject")
	if errWrite := conn.WriteMessage(websocket.TextMessage, request); errWrite != nil {
		t.Fatal(errWrite)
	}
	if _, body, errRead := conn.ReadMessage(); errRead != nil || !strings.Contains(string(body), "error") {
		t.Fatalf("changed principal was not rejected: body=%s error=%v", body, errRead)
	}
	if got := len(executor.AuthIDs()); got != 1 {
		t.Fatalf("upstream executions=%d, want 1", got)
	}
}

func groupingReauthFixture(t *testing.T) (*websocket.Conn, *groupingReauthProvider, *websocketAuthCaptureExecutor) {
	t.Helper()
	manager, _ := newGroupingSessionManager(t, "test-provider", "grouping-reauth-model")
	executor := &websocketAuthCaptureExecutor{}
	manager.RegisterExecutor(executor)
	provider := &groupingReauthProvider{}
	provider.subject.Store("session-token")
	h := NewOpenAIResponsesAPIHandler(handlers.NewBaseAPIHandlers(&sdkconfig.SDKConfig{}, manager))
	h.AccessManager = access.NewManager()
	h.AccessManager.SetProviders([]access.Provider{provider})
	router := gin.New()
	router.GET("/v1/responses", func(c *gin.Context) {
		c.Request = c.Request.WithContext(access.WithAuthenticatedPrincipal(c.Request.Context(), "test", "handshake-only"))
	}, h.ResponsesWebsocket)
	server := httptest.NewServer(router)
	t.Cleanup(server.Close)
	conn, _, errDial := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(server.URL, "http")+"/v1/responses", nil)
	if errDial != nil {
		t.Fatal(errDial)
	}
	t.Cleanup(func() {
		if errClose := conn.Close(); errClose != nil {
			t.Error(errClose)
		}
	})
	if errDeadline := conn.SetReadDeadline(time.Now().Add(3 * time.Second)); errDeadline != nil {
		t.Fatal(errDeadline)
	}
	return conn, provider, executor
}

func TestGroupingDuplexReauthReplacesTrustedPrincipalWithoutMutatingRequest(t *testing.T) {
	manager, policy := newGroupingSessionManager(t, "test-provider", "grouping-duplex-identity")
	h := NewOpenAIResponsesAPIHandler(handlers.NewBaseAPIHandlers(&sdkconfig.SDKConfig{}, manager))
	h.AccessManager = access.NewManager()
	provider := &groupingReauthProvider{}
	provider.subject.Store("different-subject")
	h.AccessManager.SetProviders([]access.Provider{provider})
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest(http.MethodGet, "/v1/responses", nil)
	trustedGroupingRequest(c)
	original := c.Request.Context()
	turnCtx, errAuth := h.authenticateResponsesWebsocketTurnContext(c, c.Request, []byte(`{"type":"response.create"}`), "grouping-duplex-identity", false)
	if errAuth != nil {
		t.Fatal(errAuth)
	}
	authorization := newWebsocketTurnAuthorization(original)
	authorization.updatePrincipal(turnCtx)
	credential, _ := manager.GetByID(policy.authID)
	bindings := &websocketCredentialBindings{}
	bindings.remember(credential)
	if errAccess := bindings.authorizeCurrent(authorization.context(), h); errAccess == nil {
		t.Fatal("duplex retained the previous principal's credential access")
	}
	if principal, _ := access.AuthenticatedPrincipalFromContext(c.Request.Context()); principal.Subject != "session-token" {
		t.Fatal("duplex reauthentication mutated the live request context")
	}
}

func TestWebsocketAnonymousReauthClearsHandshakeIdentity(t *testing.T) {
	h := &OpenAIResponsesAPIHandler{BaseAPIHandler: &handlers.BaseAPIHandler{}, AccessManager: access.NewManager()}
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest(http.MethodGet, "/v1/responses", nil)
	trustedGroupingRequest(c)
	if errAuth := h.authenticateResponsesWebsocketTurn(c, c.Request, []byte(`{}`), "", true); errAuth != nil {
		t.Fatal(errAuth)
	}
	if _, ok := access.AuthenticatedPrincipalFromContext(c.Request.Context()); ok {
		t.Fatal("anonymous reauthentication retained a trusted handshake principal")
	}
}
