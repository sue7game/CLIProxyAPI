package pluginhost

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

func (h *Host) callHostAuthRequest(ctx context.Context, request []byte) ([]byte, error) {
	var req pluginapi.HostAuthRequest
	if errUnmarshal := json.Unmarshal(request, &req); errUnmarshal != nil {
		return nil, fmt.Errorf("decode host auth request: %w", errUnmarshal)
	}
	ctx = h.resolveCallbackContext(req.HostCallbackID, ctx)
	if errValidate := validateHostAuthRequest(req); errValidate != nil {
		return nil, errValidate
	}

	auth, errAuth := h.authByIndex(req.AuthIndex)
	if errAuth != nil {
		return nil, errAuth
	}
	headers := cloneHeader(req.Headers)
	token, auth, errHeaders := h.replaceHostAuthTokenHeaders(ctx, auth, headers)
	if errHeaders != nil {
		return nil, errHeaders
	}

	method := strings.ToUpper(strings.TrimSpace(req.Method))
	if method == "" {
		method = http.MethodGet
	}
	resp, errDo := h.newAuthHTTPClient(auth, auth.Provider, token).Do(ctx, pluginapi.HTTPRequest{
		Method:  method,
		URL:     strings.TrimSpace(req.URL),
		Headers: headers,
		Body:    bytes.Clone(req.Body),
	})
	if errDo != nil {
		return nil, fmt.Errorf("execute host auth request: %w", errDo)
	}
	redactHostAuthToken(&resp, token)
	return marshalRPCResult(pluginapi.HostAuthRequestResponse{
		StatusCode: resp.StatusCode,
		Headers:    resp.Headers,
		Body:       resp.Body,
	})
}

func validateHostAuthRequest(req pluginapi.HostAuthRequest) error {
	if strings.TrimSpace(req.AuthIndex) == "" {
		return fmt.Errorf("auth_index is required")
	}
	urlString := strings.TrimSpace(req.URL)
	if urlString == "" {
		return fmt.Errorf("url is required")
	}
	parsedURL, errParse := url.Parse(urlString)
	if errParse != nil || parsedURL.Scheme == "" || parsedURL.Host == "" {
		return fmt.Errorf("url must be absolute")
	}
	if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
		return fmt.Errorf("url scheme must be http or https")
	}
	return nil
}

func (h *Host) replaceHostAuthTokenHeaders(ctx context.Context, auth *coreauth.Auth, headers http.Header) (string, *coreauth.Auth, error) {
	if auth == nil {
		return "", nil, fmt.Errorf("auth is required")
	}
	needsToken := false
	for _, values := range headers {
		for _, value := range values {
			if strings.Contains(value, "$TOKEN$") {
				needsToken = true
				break
			}
		}
		if needsToken {
			break
		}
	}
	if !needsToken {
		return "", auth, nil
	}

	token, updatedAuth, errToken := h.resolveHostAuthToken(ctx, auth)
	if errToken != nil {
		return "", nil, fmt.Errorf("resolve auth token: %w", errToken)
	}
	if token == "" {
		return "", nil, fmt.Errorf("auth token not found")
	}
	for key, values := range headers {
		for i, value := range values {
			headers[key][i] = strings.ReplaceAll(value, "$TOKEN$", token)
		}
	}
	return token, updatedAuth, nil
}

func (h *Host) resolveHostAuthToken(ctx context.Context, auth *coreauth.Auth) (string, *coreauth.Auth, error) {
	if auth == nil {
		return "", nil, nil
	}
	if !strings.EqualFold(strings.TrimSpace(auth.Provider), "antigravity") {
		return hostAuthTokenValue(auth), auth, nil
	}
	return h.resolveHostAntigravityToken(ctx, auth)
}

func (h *Host) resolveHostAntigravityToken(ctx context.Context, auth *coreauth.Auth) (string, *coreauth.Auth, error) {
	current := hostAntigravityTokenValue(auth)
	if current != "" && !hostAntigravityTokenNeedsRefresh(auth.Metadata, time.Now()) {
		return current, auth, nil
	}
	manager := h.currentAuthManager()
	if manager == nil {
		return "", nil, fmt.Errorf("core auth manager unavailable")
	}
	updated, errRefresh := manager.RefreshAuthForRequest(ctx, auth.ID, current)
	if errRefresh != nil {
		return "", nil, fmt.Errorf("refresh antigravity auth: %w", errRefresh)
	}
	if updated == nil {
		return "", nil, fmt.Errorf("refresh antigravity auth returned no auth")
	}
	token := hostAntigravityTokenValue(updated)
	if token == "" {
		return "", nil, fmt.Errorf("antigravity token refresh returned no access token")
	}
	return token, updated, nil
}

func redactHostAuthToken(resp *pluginapi.HTTPResponse, token string) {
	if resp == nil || token == "" {
		return
	}
	for key, values := range resp.Headers {
		for i, value := range values {
			resp.Headers[key][i] = strings.ReplaceAll(value, token, "[REDACTED]")
		}
	}
	resp.Body = bytes.ReplaceAll(resp.Body, []byte(token), []byte("[REDACTED]"))
}
