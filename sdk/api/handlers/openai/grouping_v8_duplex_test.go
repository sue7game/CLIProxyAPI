package openai

import (
	"context"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/api/handlers"
	sdkconfig "github.com/router-for-me/CLIProxyAPI/v8/sdk/config"
)

type groupingCodexDuplexExecutor struct {
	groupingDuplexExecutor
	disconnect chan error
}

func (*groupingCodexDuplexExecutor) Identifier() string { return "codex" }

func (e *groupingCodexDuplexExecutor) UpstreamDisconnectChan(string) <-chan error {
	return e.disconnect
}

func groupingCodexDuplexFixture(t *testing.T) (*websocket.Conn, *sessionGroupingPolicy, *groupingCodexDuplexExecutor) {
	t.Helper()
	manager, policy := newGroupingSessionManager(t, "codex", "grouping-v8-duplex")
	credential, _ := manager.GetByID(policy.authID)
	credential.Attributes["websockets"] = "true"
	if _, err := manager.Update(context.Background(), credential); err != nil {
		t.Fatal(err)
	}
	executor := &groupingCodexDuplexExecutor{
		groupingDuplexExecutor: groupingDuplexExecutor{checked: make(chan bool, 1)},
		disconnect:             make(chan error),
	}
	manager.RegisterExecutor(executor)
	h := NewOpenAIResponsesAPIHandler(handlers.NewBaseAPIHandlers(&sdkconfig.SDKConfig{CodexResponseSteering: true}, manager))
	router := gin.New()
	router.GET("/v1/responses", trustedGroupingRequest, h.ResponsesWebsocket)
	server := httptest.NewServer(router)
	t.Cleanup(server.Close)
	conn, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(server.URL, "http")+"/v1/responses", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if errClose := conn.Close(); errClose != nil {
			t.Errorf("close downstream websocket: %v", errClose)
		}
	})
	return conn, policy, executor
}

func TestGroupingV8CodexDuplexDisconnectDoesNotBypassRevocation(t *testing.T) {
	conn, policy, executor := groupingCodexDuplexFixture(t)
	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	request := []byte(`{"type":"response.create","model":"grouping-v8-duplex","input":[]}`)
	if err := conn.WriteMessage(websocket.TextMessage, request); err != nil {
		t.Fatal(err)
	}
	if _, payload, err := conn.ReadMessage(); err != nil || !strings.Contains(string(payload), "response.created") {
		t.Fatalf("initial response = %s, %v", payload, err)
	}
	policy.revoked.Store(true)
	// The v8 out-of-band disconnect watcher must leave an active Codex duplex
	// stream in charge of ordered events, without disabling its credential check.
	select {
	case executor.disconnect <- errors.New("upstream disconnect during duplex"):
	case <-time.After(3 * time.Second):
		t.Fatal("upstream disconnect subscriber was not installed")
	}
	if err := conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"response.steer","previous_response_id":"grouping-duplex","input":[]}`)); err != nil {
		t.Fatal(err)
	}
	select {
	case allowed := <-executor.checked:
		if allowed || executor.forwarded.Load() != 0 {
			t.Fatal("duplex disconnect bypassed credential revocation")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("duplex closed without applying its credential check")
	}
	// v8 deliberately hides terminal credential failures on this transport.
	// Require a closed connection, not a timeout or another successful event.
	_, payload, err := conn.ReadMessage()
	var closeErr *websocket.CloseError
	if !errors.As(err, &closeErr) {
		t.Fatalf("revoked duplex remained open: payload=%s error=%v", payload, err)
	}
}
