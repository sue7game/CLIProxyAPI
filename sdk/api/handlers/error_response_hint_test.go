package handlers

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/interfaces"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	"github.com/tidwall/gjson"
)

func TestBuildErrorResponseBodyAppendsConfirmedHintsToJSON(t *testing.T) {
	tests := []struct {
		status int
		hint   string
	}{
		{400, "请求格式、参数或上下文不符合要求，或请求内容包含敏感信息"},
		{401, "账号被封了，等我们换号"},
		{402, "上游要求付费或账号额度不可用"},
		{403, "账号被封了，等我换号"},
		{404, "模型、接口或引用的历史响应不存在"},
		{408, "请求已中断或超时"},
		{409, "请求与当前资源状态冲突"},
		{413, "输入、上下文或上传内容超过限制"},
		{422, "请求字段或参数值无法处理"},
		{426, "当前连接需要协议升级"},
		{429, "请求内容不符合要求或内容中敏感信息，请调整，不要一直重试"},
		{499, "客户端已主动断开连接"},
		{500, "网络错误，请重试"},
		{501, "当前接口未实现或不支持"},
		{502, "网络错误，请重试"},
		{503, "账号暂时不可用，等我们处理好"},
		{504, "上游请求超时，请稍后重试"},
	}
	const input = `{"error":{"message":"original error","type":"original_type","code":"original_code","retryable":false},"request_id":9007199254740993}`
	for _, tt := range tests {
		t.Run(strconv.Itoa(tt.status), func(t *testing.T) {
			body := BuildErrorResponseBody(tt.status, input)
			want := "original error\n" + tt.hint
			if got := gjson.GetBytes(body, "error.message").String(); got != want {
				t.Fatalf("message = %q, want %q", got, want)
			}
			assertHintErrorFieldsPreserved(t, body)
			if again := BuildErrorResponseBody(tt.status, string(body)); string(again) != string(body) {
				t.Fatalf("hint appended more than once: %s", again)
			}
		})
	}
}

func assertHintErrorFieldsPreserved(t *testing.T, body []byte) {
	t.Helper()
	for path, want := range map[string]string{
		"error.type":      `"original_type"`,
		"error.code":      `"original_code"`,
		"error.retryable": `false`,
		"request_id":      `9007199254740993`,
	} {
		if got := gjson.GetBytes(body, path).Raw; got != want {
			t.Errorf("%s = %s, want %s", path, got, want)
		}
	}
}

func TestBuildErrorResponseBodyAppendsHintToExistingMessageShapes(t *testing.T) {
	for _, path := range []string{"message", "error.message", "response.error.message"} {
		t.Run(path, func(t *testing.T) {
			input := map[string]string{
				"message":                `{"message":"original error"}`,
				"error.message":          `{"error":{"message":"original error"}}`,
				"response.error.message": `{"response":{"error":{"message":"original error"}}}`,
			}[path]
			body := BuildErrorResponseBody(http.StatusBadRequest, input)
			want := "original error\n请求格式、参数或上下文不符合要求，或请求内容包含敏感信息"
			if got := gjson.GetBytes(body, path).String(); got != want {
				t.Fatalf("%s = %q, want %q", path, got, want)
			}
		})
	}
}

func TestBuildErrorResponseBodySkipsMissingAndNonStringMessages(t *testing.T) {
	for _, input := range []string{
		`{"error":{"code":"missing_message"}}`,
		`{"error":"upstream error"}`,
		`{"detail":"upstream error"}`,
		`{"error":{"message":null}}`,
		`{"error":{"message":123}}`,
		`{"error":{"message":false}}`,
		`{"error":{"message":""}}`,
		`{"error":{"message":"   "}}`,
		`{"error":{}}`, `null`, `[]`,
	} {
		body := BuildErrorResponseBody(http.StatusBadRequest, input)
		if string(body) != input {
			t.Errorf("body = %s, want unchanged %s", body, input)
		}
	}
	const input = `{"error":{"message":"original error"}}`
	for _, status := range []int{http.StatusOK, http.StatusTeapot} {
		if body := BuildErrorResponseBody(status, input); string(body) != input {
			t.Errorf("unmapped status %d changed body: %s", status, body)
		}
	}
}

func TestBuildErrorResponseBodyAppendsHintToTerminalAuthError(t *testing.T) {
	terminalErr := coreauth.NewTerminalAuthError(&coreauth.Error{
		Code: "auth_unavailable", Message: "no auth available", HTTPStatus: http.StatusServiceUnavailable,
	}, errors.New("token revoked"))
	for _, input := range []string{
		"token revoked",
		`{"error":{"message":"token revoked","type":"server_error"}}`,
		`{"message":"token revoked"}`,
	} {
		body := BuildErrorResponseBodyWithError(http.StatusServiceUnavailable, input, terminalErr)
		want := "token revoked\n账号暂时不可用，等我们处理好"
		if got := gjson.GetBytes(body, "error.message").String(); got != want {
			t.Errorf("message = %q, want %q", got, want)
		}
		if got := gjson.GetBytes(body, "error.type").String(); got != "authentication_error" {
			t.Errorf("type = %q, want authentication_error", got)
		}
		if got := gjson.GetBytes(body, "error.code").String(); got != "upstream_authentication_required" {
			t.Errorf("code = %q, want upstream_authentication_required", got)
		}
		if got := gjson.GetBytes(body, "error.retryable").Raw; got != "false" {
			t.Errorf("retryable = %s, want false", got)
		}
	}
}

func TestWriteErrorResponseAppendsHintToJSONWithOriginalStatus(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, direct := range []bool{false, true} {
		t.Run(strconv.FormatBool(direct), func(t *testing.T) {
			recorder := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(recorder)
			c.Request = httptest.NewRequest(http.MethodPost, "/v1/responses", nil)
			const input = `{"error":{"message":"invalid request","code":"invalid_value","type":"invalid_request_error"}}`
			NewBaseAPIHandlers(nil, nil).WriteErrorResponse(c, &interfaces.ErrorMessage{
				StatusCode: http.StatusBadRequest, Error: errors.New(input),
				DirectResponse: direct, Body: []byte(input),
			})
			if recorder.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400", recorder.Code)
			}
			body := recorder.Body.Bytes()
			want := "invalid request\n请求格式、参数或上下文不符合要求，或请求内容包含敏感信息"
			if got := gjson.GetBytes(body, "error.message").String(); got != want {
				t.Fatalf("message = %q, want %q", got, want)
			}
			if !json.Valid(body) || strings.Contains(string(body), "\n") {
				t.Fatalf("invalid or multiline JSON body: %s", body)
			}
		})
	}
}
