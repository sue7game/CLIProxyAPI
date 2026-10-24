package claude

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/interfaces"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/api/handlers"
	"github.com/tidwall/gjson"
)

func TestWriteClaudeErrorAppendsHintToExistingMessage(t *testing.T) {
	gin.SetMode(gin.TestMode)
	const input = `{"type":"error","error":{"type":"rate_limit_error","message":"original error"},"request_id":9007199254740993}`
	for _, direct := range []bool{false, true} {
		t.Run(strconv.FormatBool(direct), func(t *testing.T) {
			recorder := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(recorder)
			handler := &ClaudeCodeAPIHandler{}
			handler.WriteErrorResponse(c, &interfaces.ErrorMessage{
				StatusCode: http.StatusTooManyRequests, Error: errors.New(input),
				DirectResponse: direct, Body: []byte(input),
			})
			if recorder.Code != http.StatusTooManyRequests {
				t.Fatalf("status = %d, want 429", recorder.Code)
			}
			body := recorder.Body.Bytes()
			want := "original error\n请求内容不符合要求或内容中敏感信息，请调整，不要一直重试"
			if got := gjson.GetBytes(body, "error.message").String(); got != want {
				t.Fatalf("message = %q, want %q", got, want)
			}
			if gjson.GetBytes(body, "type").String() != "error" || gjson.GetBytes(body, "error.type").String() != "rate_limit_error" {
				t.Fatalf("Claude error envelope changed: %s", body)
			}
			if direct && gjson.GetBytes(body, "request_id").Raw != "9007199254740993" {
				t.Fatalf("direct response metadata changed: %s", body)
			}
		})
	}
}

func TestWriteClaudeDirectErrorSkipsMissingAndNonStringMessages(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, input := range []string{
		`{"type":"error","error":{"code":"invalid_value"}}`,
		`{"error":{"message":null}}`,
		`{"error":{"message":123}}`,
		`{"error":{"message":""}}`,
	} {
		recorder := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(recorder)
		handler := &ClaudeCodeAPIHandler{}
		handler.WriteErrorResponse(c, &interfaces.ErrorMessage{
			StatusCode: http.StatusBadRequest, DirectResponse: true, Body: []byte(input),
		})
		if got := recorder.Body.String(); got != input {
			t.Errorf("body = %s, want unchanged %s", got, input)
		}
	}
}

func TestClaudeStreamErrorAppendsHintOnce(t *testing.T) {
	gin.SetMode(gin.TestMode)
	const hint = "账号暂时不可用，等我们处理好"
	for _, input := range []string{"original error", "original error\n" + hint} {
		recorder := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(recorder)
		c.Request = httptest.NewRequest(http.MethodPost, "/v1/messages", nil)
		handler := NewClaudeCodeAPIHandler(&handlers.BaseAPIHandler{})
		errs := make(chan *interfaces.ErrorMessage, 1)
		errs <- &interfaces.ErrorMessage{StatusCode: http.StatusServiceUnavailable, Error: errors.New(input)}
		close(errs)
		handler.forwardClaudeStream(c, c.Writer, func(error) {}, nil, errs)
		body := recorder.Body.String()
		if !strings.HasPrefix(body, "event: error\ndata: ") {
			t.Fatalf("missing Claude SSE error envelope: %s", body)
		}
		payload := strings.TrimSpace(strings.TrimPrefix(body, "event: error\ndata: "))
		if got := gjson.Get(payload, "error.message").String(); got != "original error\n"+hint {
			t.Fatalf("message = %q, want original error with one hint", got)
		}
	}
}
