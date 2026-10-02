package live

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
)

func TestGroupingRealtimeWebsocketAndSidebandCloseOnIdleRevocation(t *testing.T) {
	for _, sideband := range []bool{false, true} {
		name := "direct"
		if sideband {
			name = "sideband"
		}
		t.Run(name, func(t *testing.T) { testGroupingRealtimeSocketRevocation(t, sideband) })
	}
}

func testGroupingRealtimeSocketRevocation(t *testing.T, sideband bool) {
	t.Helper()
	h, policy := groupingLiveFixture(t)
	h.authManager.RegisterExecutor(&captureExecutor{})
	upstreamClosed := make(chan struct{})
	upstream := groupingRealtimeUpstream(upstreamClosed)
	defer upstream.Close()
	h.sidebandAPIBaseURL = "ws" + strings.TrimPrefix(upstream.URL, "http") + "/v1"
	router := gin.New()
	router.GET("/v1/realtime", groupingLiveMiddleware, h.HandleRealtimeWebsocket)
	server := httptest.NewServer(router)
	defer server.Close()
	query := "?model=gpt-realtime"
	if sideband {
		h.sessions.put("call-grouping", liveSession{authID: "grouping-live-auth", credential: groupingLiveCredential(h), model: "gpt-live-1-codex"})
		query = "?call_id=call-grouping"
	}
	conn, response, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(server.URL, "http")+"/v1/realtime"+query, nil)
	if err != nil {
		if response != nil {
			_ = response.Body.Close()
		}
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	if _, _, err = conn.ReadMessage(); err != nil {
		t.Fatal(err)
	}
	policy.revoked.Store(true)
	h.authManager.NotifyCredentialAccessChanged()
	if err = conn.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, _, err = conn.ReadMessage(); err == nil {
		t.Fatal("revoked idle socket remains open")
	}
	awaitGroupingClose(t, upstreamClosed)
	if sideband {
		if _, exists := h.sessions.peek("call-grouping"); exists {
			t.Fatal("revoked sideband remains retained")
		}
	}
}

func groupingRealtimeUpstream(closed chan struct{}) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer func() { _ = conn.Close(); close(closed) }()
		if err = conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"session.created"}`)); err != nil {
			return
		}
		for {
			if _, _, err = conn.ReadMessage(); err != nil {
				return
			}
		}
	}))
}
