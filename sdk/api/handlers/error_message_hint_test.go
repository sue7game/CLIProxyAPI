package handlers

import (
	"bytes"
	"net/http"
	"testing"

	"github.com/tidwall/gjson"
)

func TestAppendErrorMessageHintPreservesStructuredError(t *testing.T) {
	input := []byte(`{"error":{"message":"network failed","code":"upstream_error","retryable":false},"request_id":"req-1"}`)
	got := AppendErrorMessageHint(http.StatusBadGateway, input)
	if message := gjson.GetBytes(got, "error.message").String(); message != "network failed\n网络错误，请重试" {
		t.Fatalf("error message = %q", message)
	}
	if gjson.GetBytes(got, "error.code").String() != "upstream_error" || gjson.GetBytes(got, "error.retryable").Bool() {
		t.Fatalf("structured error classification changed: %s", got)
	}
	if gjson.GetBytes(got, "request_id").String() != "req-1" {
		t.Fatalf("request metadata changed: %s", got)
	}
	if repeated := AppendErrorMessageHint(http.StatusBadGateway, got); !bytes.Equal(repeated, got) {
		t.Fatalf("hint duplicated: %s", repeated)
	}
}

func TestAppendErrorMessageHintLeavesNonMessagesUnchanged(t *testing.T) {
	for _, input := range []string{
		`not json`, `{"error":{"code":"no_message"}}`,
		`{"error":{"message":123}}`, `{"error":{"message":""}}`,
	} {
		got := AppendErrorMessageHint(http.StatusBadGateway, []byte(input))
		if string(got) != input {
			t.Errorf("body changed: got %s, want %s", got, input)
		}
	}
}
