package handlers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

// BuildErrorResponseBody builds an OpenAI-compatible JSON error response body.
// Valid JSON is compacted for SSE compatibility and existing messages receive a status hint.
func BuildErrorResponseBody(status int, errText string) []byte {
	return BuildErrorResponseBodyWithError(status, errText, nil)
}

// BuildErrorResponseBodyWithError preserves structured error classifications and
// retryable flags, then appends a status hint to existing string message fields.
func BuildErrorResponseBodyWithError(status int, errText string, err error) []byte {
	if status <= 0 {
		status = http.StatusInternalServerError
	}
	if strings.TrimSpace(errText) == "" {
		errText = http.StatusText(status)
	}
	return AppendErrorMessageHint(status, buildErrorResponsePayload(status, errText, err))
}

func buildErrorResponsePayload(status int, errText string, err error) []byte {
	if coreauth.IsTerminalAuthError(err) {
		return buildTerminalAuthErrorBody(errText)
	}
	trimmed := strings.TrimSpace(errText)
	if json.Valid([]byte(trimmed)) {
		var compact bytes.Buffer
		if errCompact := json.Compact(&compact, []byte(trimmed)); errCompact == nil {
			return compact.Bytes()
		}
		return []byte(trimmed)
	}
	return buildPlainErrorResponseBody(status, errText)
}

func buildTerminalAuthErrorBody(errText string) []byte {
	message := errText
	var parsed map[string]any
	if errUnmarshal := json.Unmarshal([]byte(errText), &parsed); errUnmarshal == nil {
		if msg, ok := parsed["message"].(string); ok && msg != "" {
			message = msg
		} else if errMap, ok := parsed["error"].(map[string]any); ok {
			if msg, ok := errMap["message"].(string); ok && msg != "" {
				message = msg
			}
		}
	}
	retryable := false
	payload, errMarshal := json.Marshal(ErrorResponse{
		Error: ErrorDetail{
			Message:   message,
			Type:      "authentication_error",
			Code:      "upstream_authentication_required",
			Retryable: &retryable,
		},
	})
	if errMarshal != nil {
		return []byte(fmt.Sprintf(`{"error":{"message":%q,"type":"authentication_error","code":"upstream_authentication_required","retryable":false}}`, message))
	}
	return payload
}

func buildPlainErrorResponseBody(status int, errText string) []byte {
	errType := "invalid_request_error"
	var code string
	switch status {
	case http.StatusUnauthorized:
		errType = "authentication_error"
		code = "invalid_api_key"
	case http.StatusForbidden:
		errType = "permission_error"
		code = "insufficient_quota"
	case http.StatusTooManyRequests:
		errType = "rate_limit_error"
		code = "rate_limit_exceeded"
	case http.StatusNotFound:
		code = "model_not_found"
	case http.StatusRequestTimeout:
		errType = "server_error"
		code = "request_timeout"
	default:
		if status >= http.StatusInternalServerError {
			errType = "server_error"
			code = "internal_server_error"
		}
	}
	payload, errMarshal := json.Marshal(ErrorResponse{
		Error: ErrorDetail{
			Message: errText,
			Type:    errType,
			Code:    code,
		},
	})
	if errMarshal != nil {
		return []byte(fmt.Sprintf(`{"error":{"message":%q,"type":"server_error","code":"internal_server_error"}}`, errText))
	}
	return payload
}
