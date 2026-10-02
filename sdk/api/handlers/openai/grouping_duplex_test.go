package openai

import (
	"context"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/api/handlers"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	coreexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	sdkconfig "github.com/router-for-me/CLIProxyAPI/v8/sdk/config"
)

type groupingDuplexExecutor struct {
	websocketAuthCaptureExecutor
	forwarded atomic.Int32
	checked   chan bool
}

func (e *groupingDuplexExecutor) ExecuteStream(ctx context.Context, credential *coreauth.Auth, _ coreexecutor.Request, _ coreexecutor.Options) (*coreexecutor.StreamResult, error) {
	chunks := make(chan coreexecutor.StreamChunk, 1)
	chunks <- coreexecutor.StreamChunk{Payload: []byte(`{"type":"response.created","response":{"id":"grouping-duplex"}}`)}
	go func() {
		defer close(chunks)
		select {
		case <-ctx.Done():
			return
		case <-coreexecutor.WebsocketInputFromContext(ctx):
			allowed := coreexecutor.WebsocketAuthEnabled(ctx, credential.ID)
			e.checked <- allowed
			if allowed {
				e.forwarded.Add(1)
			}
			chunks <- coreexecutor.StreamChunk{Err: websocketCredentialUnavailable()}
		}
	}()
	return &coreexecutor.StreamResult{Chunks: chunks}, nil
}

func TestGroupingDuplexCallbackRechecksIssuerAndPermanentCredential(t *testing.T) {
	for _, change := range []string{"issuer-revoked", "credential-replaced", "disabled-compatibility"} {
		t.Run(change, func(t *testing.T) { testGroupingDuplexChange(t, change) })
	}
}

func testGroupingDuplexChange(t *testing.T, change string) {
	t.Helper()
	manager, policy := newGroupingSessionManager(t, "test-provider", "grouping-duplex-model")
	executor := &groupingDuplexExecutor{checked: make(chan bool, 1)}
	manager.RegisterExecutor(executor)
	if change == "disabled-compatibility" {
		manager.SetCredentialAccessPolicy(nil)
	}
	h := NewOpenAIResponsesAPIHandler(handlers.NewBaseAPIHandlers(&sdkconfig.SDKConfig{CodexResponseSteering: true}, manager))
	router := gin.New()
	router.GET("/v1/responses", trustedGroupingRequest, h.ResponsesWebsocket)
	server := httptest.NewServer(router)
	defer server.Close()
	conn, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(server.URL, "http")+"/v1/responses", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	if err = conn.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if err = conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"response.create","model":"grouping-duplex-model","input":[]}`)); err != nil {
		t.Fatal(err)
	}
	if _, _, err = conn.ReadMessage(); err != nil {
		t.Fatal(err)
	}
	if change == "credential-replaced" {
		credential, _ := manager.GetByID(policy.authID)
		credential.Attributes["grouping_id"] = "new-source"
		if _, err = manager.Register(context.Background(), credential); err != nil {
			t.Fatal(err)
		}
	} else {
		policy.revoked.Store(true)
	}
	if err = conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"response.steer","previous_response_id":"grouping-duplex","input":[]}`)); err != nil {
		t.Fatal(err)
	}
	select {
	case allowed := <-executor.checked:
		if allowed != (change == "disabled-compatibility") {
			t.Fatalf("duplex authorization = %v", allowed)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("duplex executor did not receive its credential check")
	}
}
