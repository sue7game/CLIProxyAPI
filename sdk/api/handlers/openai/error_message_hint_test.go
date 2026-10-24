package openai

import (
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/gorilla/websocket"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/interfaces"
	"github.com/tidwall/gjson"
)

func TestResponsesWebsocketJSONErrorAppendsMessageHint(t *testing.T) {
	input := `{"error":{"message":"invalid request","type":"invalid_request_error","code":"invalid_value"}}`
	payload, errBuild := buildResponsesWebsocketErrorPayload(&interfaces.ErrorMessage{
		StatusCode: http.StatusBadRequest,
		Error:      errors.New(input),
	})
	if errBuild != nil {
		t.Fatalf("build error payload: %v", errBuild)
	}
	if got := gjson.GetBytes(payload, "status").Int(); got != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", got)
	}
	want := "invalid request\n请求格式、参数或上下文不符合要求，或请求内容包含敏感信息"
	if got := gjson.GetBytes(payload, "error.message").String(); got != want {
		t.Fatalf("message = %q, want %q", got, want)
	}
	if got := gjson.GetBytes(payload, "error.code").String(); got != "invalid_value" {
		t.Fatalf("code = %q, want invalid_value", got)
	}
}

func TestResponsesWebsocketRawTerminalErrorAppendsHintOnce(t *testing.T) {
	errMsg := &interfaces.ErrorMessage{StatusCode: http.StatusBadRequest, Error: errors.New("invalid request")}
	payload := []byte(`{"type":"error","status":400,"error":{"message":"invalid request","code":"invalid_value"}}`)
	for i := 0; i < 2; i++ {
		var errWrite error
		payload, _, errWrite = writeResponsesWebsocketTerminalError(nil, nil, errMsg, payload)
		if !errors.Is(errWrite, websocket.ErrCloseSent) {
			t.Fatalf("terminal error = %v, want ErrCloseSent", errWrite)
		}
		message := gjson.GetBytes(payload, "error.message").String()
		const hint = "请求格式、参数或上下文不符合要求，或请求内容包含敏感信息"
		if !strings.HasPrefix(message, "invalid request\n") || strings.Count(message, hint) != 1 {
			t.Fatalf("message after pass %d = %q", i, message)
		}
	}
}

func TestResponsesWebsocketRawTerminalErrorSkipsMissingMessage(t *testing.T) {
	errMsg := &interfaces.ErrorMessage{StatusCode: http.StatusBadRequest, Error: errors.New("invalid request")}
	input := []byte(`{"type":"error","status":400,"error":{"code":"invalid_value"}}`)
	payload, _, errWrite := writeResponsesWebsocketTerminalError(nil, nil, errMsg, input)
	if !errors.Is(errWrite, websocket.ErrCloseSent) {
		t.Fatalf("terminal error = %v, want ErrCloseSent", errWrite)
	}
	if string(payload) != string(input) {
		t.Fatalf("payload = %s, want unchanged %s", payload, input)
	}
}
