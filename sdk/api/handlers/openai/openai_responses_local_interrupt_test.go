package openai

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/interfaces"
)

func TestLocalInterruptRequiresCurrentResponseIdentity(t *testing.T) {
	for _, terminal := range []string{"response.completed", "response.done", "response.incomplete", "response.failed"} {
		t.Run(terminal, func(t *testing.T) {
			local := newResponsesLocalInterrupt()
			local.begin()
			interrupt := []byte(`{"type":"response.interrupt","response_id":"r1"}`)
			if local.deliver(interrupt) {
				t.Fatal("local interrupt accepted before a response identity was known")
			}
			local.observe([]byte(`{"type":"response.created","response":{"id":"r1"}}`))
			if local.deliver([]byte(`{"type":"response.interrupt","response_id":"unknown"}`)) {
				t.Fatal("unknown response interrupted the active turn")
			}
			if !local.deliver(interrupt) {
				t.Fatal("active response rejected its own interrupt")
			}
			local.observe([]byte(fmt.Sprintf(`{"type":%q,"response":{"id":"r1"}}`, terminal)))
			if local.deliver(interrupt) {
				t.Fatal("terminal response retained its local interrupt window")
			}
			select {
			case <-local.framesChan():
				t.Fatal("terminal response left an interrupt queued for the next turn")
			default:
			}
			local.observe([]byte(`{"type":"response.created","response":{"id":"r2"}}`))
			if local.deliver(interrupt) {
				t.Fatal("previous response interrupted the next turn")
			}
			if !local.deliver([]byte(`{"type":"response.interrupt","response_id":"r2"}`)) {
				t.Fatal("next response could not be interrupted")
			}
		})
	}
}

func TestForwardTerminalClosesLocalInterruptBeforeStreamCleanup(t *testing.T) {
	local := newResponsesLocalInterrupt()
	data := make(chan []byte, 2)
	data <- []byte(`{"type":"response.created","response":{"id":"r1"}}`)
	data <- []byte(`{"type":"response.completed","response":{"id":"r1","output":[]}}`)
	done := make(chan error, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, errUpgrade := responsesWebsocketUpgrader.Upgrade(w, r, nil)
		if errUpgrade != nil {
			done <- errUpgrade
			return
		}
		defer func() { _ = conn.Close() }()
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		c.Request = r
		_, _, _, errMsg, errForward := (*OpenAIResponsesAPIHandler)(nil).forwardResponsesWebsocket(
			c, newResponsesWebsocketWriter(conn), func(...interface{}) {}, data, make(chan *interfaces.ErrorMessage), nil, "local-interrupt-terminal",
			responsesWebsocketForwardOptions{localInterrupt: local},
		)
		if errMsg != nil {
			done <- errMsg.Error
			return
		}
		done <- errForward
	}))
	t.Cleanup(server.Close)
	client, _, errDial := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(server.URL, "http"), nil)
	if errDial != nil {
		t.Fatal(errDial)
	}
	t.Cleanup(func() { _ = client.Close() })
	t.Cleanup(func() { close(data) })
	if errDeadline := client.SetReadDeadline(time.Now().Add(3 * time.Second)); errDeadline != nil {
		t.Fatal(errDeadline)
	}
	for range 2 {
		if _, _, errRead := client.ReadMessage(); errRead != nil {
			t.Fatal(errRead)
		}
	}
	// Keep the source open to hold the exact terminal-delivered/cleanup-pending window.
	if local.deliver([]byte(`{"type":"response.interrupt","response_id":"unknown"}`)) {
		t.Fatal("terminal delivery left a local interrupt window before stream cleanup")
	}
	select {
	case errForward := <-done:
		t.Fatalf("forwarder ended before source cleanup: %v", errForward)
	default:
	}
}
