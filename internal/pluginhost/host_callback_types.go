package pluginhost

import (
	"context"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

type rpcHostHTTPRequest struct {
	HTTPClientID   string                     `json:"http_client_id,omitempty"`
	HostCallbackID string                     `json:"host_callback_id,omitempty"`
	OperationID    string                     `json:"operation_id,omitempty"`
	Method         string                     `json:"method,omitempty"`
	URL            string                     `json:"url,omitempty"`
	Headers        httpHeader                 `json:"headers,omitempty"`
	Body           []byte                     `json:"body,omitempty"`
	WireProfile    *pluginapi.HTTPWireProfile `json:"wire_profile,omitempty"`
	Request        *httpRequest               `json:"request,omitempty"`
}

type httpHeader map[string][]string

type httpRequest struct {
	Method      string                     `json:"method,omitempty"`
	URL         string                     `json:"url,omitempty"`
	Headers     httpHeader                 `json:"headers,omitempty"`
	Body        []byte                     `json:"body,omitempty"`
	WireProfile *pluginapi.HTTPWireProfile `json:"wire_profile,omitempty"`
}

type rpcHostHTTPStreamResponse struct {
	StatusCode int                         `json:"status_code"`
	Headers    httpHeader                  `json:"headers,omitempty"`
	StreamID   string                      `json:"stream_id,omitempty"`
	Chunks     []pluginapi.HTTPStreamChunk `json:"chunks,omitempty"`
}

type rpcHostHTTPStreamReadRequest struct {
	StreamID string `json:"stream_id"`
}

type rpcHostHTTPStreamReadResponse struct {
	Payload []byte `json:"payload,omitempty"`
	Error   string `json:"error,omitempty"`
	Done    bool   `json:"done,omitempty"`
}

type rpcHostHTTPStreamCloseRequest struct {
	StreamID string `json:"stream_id"`
}

type rpcHostHTTPOperationOpenRequest struct {
	HostCallbackID string `json:"host_callback_id,omitempty"`
}

type rpcHostHTTPOperationOpenResponse struct {
	OperationID string `json:"operation_id"`
}

type rpcHostHTTPCancelRequest struct {
	HostCallbackID string `json:"host_callback_id,omitempty"`
	OperationID    string `json:"operation_id"`
}

type rpcHostLogRequest struct {
	HostCallbackID string         `json:"host_callback_id,omitempty"`
	Level          string         `json:"level,omitempty"`
	Message        string         `json:"message,omitempty"`
	Fields         map[string]any `json:"fields,omitempty"`
}

type rpcHostModelExecutionRequest struct {
	pluginapi.HostModelExecutionRequest
	HostCallbackID string `json:"host_callback_id,omitempty"`
}

type dynamicHostCallbackEntry struct {
	host     *Host
	pluginID string
	instance *hostCallbackInstance
}

type hostCallbackPluginIDKey struct{}
type hostCallbackInstanceKey struct{}

type hostCallbackInstance struct {
	closed               atomic.Bool
	runtimeOverrideState atomic.Uint32
	maintenanceMu        sync.Mutex
	maintenanceClose     func()
}

func withHostCallbackPluginID(ctx context.Context, pluginID string) context.Context {
	pluginID = strings.TrimSpace(pluginID)
	if pluginID == "" {
		if ctx == nil {
			return context.Background()
		}
		return ctx
	}
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, hostCallbackPluginIDKey{}, pluginID)
}

func withHostCallbackIdentity(ctx context.Context, pluginID string, instance *hostCallbackInstance) context.Context {
	ctx = withHostCallbackPluginID(ctx, pluginID)
	if ctx == nil {
		ctx = context.Background()
	}
	if instance != nil {
		ctx = context.WithValue(ctx, hostCallbackInstanceKey{}, instance)
	}
	return ctx
}

func hostCallbackInstanceFromContext(ctx context.Context) *hostCallbackInstance {
	if ctx == nil {
		return nil
	}
	instance, _ := ctx.Value(hostCallbackInstanceKey{}).(*hostCallbackInstance)
	return instance
}

func hostCallbackPluginIDFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	pluginID, _ := ctx.Value(hostCallbackPluginIDKey{}).(string)
	return strings.TrimSpace(pluginID)
}
