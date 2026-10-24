package openai

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/interfaces"
	sdkaccess "github.com/router-for-me/CLIProxyAPI/v8/sdk/access"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/usage"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

func (h *OpenAIResponsesAPIHandler) authenticateResponsesWebsocketTurn(c *gin.Context, baseReq *http.Request, payload []byte, model string, update bool) *interfaces.ErrorMessage {
	_, errAuth := h.authenticateResponsesWebsocketTurnContext(c, baseReq, payload, model, update)
	return errAuth
}

func (h *OpenAIResponsesAPIHandler) authenticateResponsesWebsocketTurnContext(c *gin.Context, baseReq *http.Request, payload []byte, model string, update bool) (context.Context, *interfaces.ErrorMessage) {
	source := baseReq
	if source == nil && c != nil {
		source = c.Request
	}
	if source == nil {
		return context.Background(), nil
	}
	if h == nil || h.AccessManager == nil {
		return source.Context(), nil
	}
	req := responsesWebsocketAuthenticationRequest(source, payload, model)
	result, authErr := h.AccessManager.Authenticate(req.Context(), req)
	if authErr != nil {
		message := strings.TrimSpace(authErr.Message)
		if message == "" {
			message = authErr.Error()
		}
		return nil, &interfaces.ErrorMessage{StatusCode: authErr.HTTPStatusCode(), Error: errors.New(message)}
	}
	// Anonymous success must clear any identity inherited from the handshake.
	if result == nil {
		result = &sdkaccess.Result{}
	}
	authCtx := sdkaccess.WithAuthenticatedPrincipal(source.Context(), result.Provider, result.Principal)
	publishResponsesWebsocketPrincipal(c, authCtx, result, update)
	return authCtx, nil
}

func responsesWebsocketAuthenticationRequest(source *http.Request, payload []byte, model string) *http.Request {
	body := payload
	if model != "" && json.Valid(payload) && strings.TrimSpace(gjson.GetBytes(payload, "model").String()) == "" {
		if updated, errSet := sjson.SetBytes(bytes.Clone(payload), "model", model); errSet == nil {
			body = updated
		}
	}
	req := source.Clone(source.Context())
	req.Method = http.MethodPost
	for key := range req.Header {
		lower := strings.ToLower(key)
		if lower == "upgrade" || lower == "connection" || lower == "content-length" || strings.HasPrefix(lower, "sec-websocket-") {
			delete(req.Header, key)
		}
	}
	req.Body = io.NopCloser(bytes.NewReader(body))
	req.ContentLength = int64(len(body))
	req.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(body)), nil
	}
	return req
}

func publishResponsesWebsocketPrincipal(c *gin.Context, authCtx context.Context, result *sdkaccess.Result, update bool) {
	if c == nil {
		return
	}
	c.Set("userApiKey", result.Principal)
	c.Set("accessProvider", result.Provider)
	if len(result.Metadata) > 0 {
		c.Set("accessMetadata", result.Metadata)
	} else {
		c.Set("accessMetadata", nil)
	}
	if update && c.Request != nil {
		ctx := sdkaccess.CopyAuthenticatedPrincipal(c.Request.Context(), authCtx)
		ctx = usage.WithAPIKey(ctx, result.Principal)
		ctx = usage.WithAccessProvider(ctx, result.Provider)
		ctx = usage.WithIsNativeKey(ctx, usage.IsNativeAccessProvider(result.Provider))
		c.Request = c.Request.WithContext(ctx)
	}
}

type websocketTurnAuthorization struct {
	mu  sync.RWMutex
	ctx context.Context
}

func newWebsocketTurnAuthorization(ctx context.Context) *websocketTurnAuthorization {
	return &websocketTurnAuthorization{ctx: ctx}
}

func (a *websocketTurnAuthorization) context() context.Context {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.ctx
}

func (a *websocketTurnAuthorization) updatePrincipal(ctx context.Context) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.ctx = sdkaccess.CopyAuthenticatedPrincipal(a.ctx, ctx)
}
