package pluginhost

import (
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/runtime/executor/helps"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

type redactedHostAuthError struct {
	err     error
	message string
}

// Error returns the credential-safe message.
func (e redactedHostAuthError) Error() string { return e.message }

// Unwrap preserves the original error identity for errors.Is and errors.As.
func (e redactedHostAuthError) Unwrap() error { return e.err }

func (c *hostHTTPClient) redactAuthError(err error) error {
	if err == nil || c == nil || c.responseToken == "" {
		return err
	}
	message := strings.ReplaceAll(err.Error(), c.responseToken, "[REDACTED]")
	if message == err.Error() {
		return err
	}
	return redactedHostAuthError{err: err, message: message}
}

func (c *hostHTTPClient) redactAuthRequestLog(info helps.UpstreamRequestLog) helps.UpstreamRequestLog {
	if c == nil || c.responseToken == "" {
		return info
	}
	payload := pluginapi.HTTPResponse{Headers: info.Headers, Body: info.Body}
	redactHostAuthToken(&payload, c.responseToken)
	info.Headers, info.Body = payload.Headers, payload.Body
	info.URL = strings.ReplaceAll(info.URL, c.responseToken, "[REDACTED]")
	info.AuthValue = strings.ReplaceAll(info.AuthValue, c.responseToken, "[REDACTED]")
	return info
}
