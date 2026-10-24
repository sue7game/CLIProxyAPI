package pluginhost

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/clienterror"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/interfaces"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/logging"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/api/handlers"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/proxyutil"
	log "github.com/sirupsen/logrus"
)

func (h *Host) callFromPlugin(ctx context.Context, method string, request []byte) (response []byte, err error) {
	defer func() { h.rememberCallbackAccessDenial(ctx, method, request, err) }()
	if instance := hostCallbackInstanceFromContext(ctx); instance != nil && instance.closed.Load() {
		return nil, fmt.Errorf("host plugin callback instance is closed")
	}
	if errCapability := h.validateMaintenanceCallback(ctx, method, request); errCapability != nil {
		return nil, errCapability
	}
	switch method {
	case pluginabi.MethodHostModelExecute:
		return h.callHostModelExecute(ctx, request)
	case pluginabi.MethodHostModelExecuteStream:
		return h.callHostModelExecuteStream(ctx, request)
	case pluginabi.MethodHostModelStreamRead:
		return h.callHostModelStreamRead(ctx, request)
	case pluginabi.MethodHostModelStreamClose:
		return h.callGroupedStreamClose(ctx, method, request)
	case pluginabi.MethodHostHTTPDo:
		return h.callHostHTTPDo(ctx, request)
	case pluginabi.MethodHostHTTPDoStream:
		return h.callHostHTTPDoStream(ctx, request)
	case pluginabi.MethodHostHTTPOperationOpen:
		return h.callHostHTTPOperationOpen(ctx, request)
	case pluginabi.MethodHostHTTPCancel:
		return h.callHostHTTPCancel(ctx, request)
	case pluginabi.MethodHostHTTPStreamRead:
		return h.callHostHTTPStreamRead(ctx, request)
	case pluginabi.MethodHostHTTPStreamClose:
		return h.callGroupedStreamClose(ctx, method, request)
	case pluginabi.MethodHostStreamEmit:
		return h.callHostStreamEmit(ctx, request)
	case pluginabi.MethodHostStreamClose:
		return h.callGroupedStreamClose(ctx, method, request)
	case pluginabi.MethodHostLog:
		return h.callHostLog(ctx, request)
	case pluginabi.MethodHostAuthList:
		return h.callHostAuthList(ctx, request)
	case pluginabi.MethodHostAuthGet:
		return h.callHostAuthGet(ctx, request)
	case pluginabi.MethodHostAuthGetRuntime:
		return h.callHostAuthGetRuntime(ctx, request)
	case pluginabi.MethodHostAuthSave:
		return h.callHostAuthSave(ctx, request)
	case pluginabi.MethodHostAuthSetRuntimeOverride:
		if instance := hostCallbackInstanceFromContext(ctx); instance != nil && !instance.registerRuntimeOverrideUse() {
			return nil, fmt.Errorf("host plugin callback instance is retiring")
		}
		return h.callHostAuthSetRuntimeOverride(ctx, request)
	case pluginabi.MethodHostAuthRequest:
		return h.callHostAuthRequest(ctx, request)
	case pluginabi.MethodHostAuthModels:
		return h.callHostAuthModels(ctx, request)
	case pluginabi.MethodHostAffinityLookup:
		return h.callHostAffinityLookup(ctx, request)
	case pluginabi.MethodHostRoutingResetCooldown:
		return h.callHostRoutingResetCooldown(ctx, request)
	default:
		return nil, fmt.Errorf("unsupported host callback %s", method)
	}
}

func (h *Host) callbackCallerPluginID(ctx context.Context, callbackID string) string {
	if pluginID := hostCallbackPluginIDFromContext(ctx); pluginID != "" {
		return pluginID
	}
	return h.callbackContextPluginID(callbackID)
}

func (h *Host) callHostStreamEmit(ctx context.Context, request []byte) ([]byte, error) {
	var req rpcStreamEmitRequest
	if errUnmarshal := json.Unmarshal(request, &req); errUnmarshal != nil {
		return nil, fmt.Errorf("decode stream emit request: %w", errUnmarshal)
	}
	if errAccess := h.authorizeGroupedStream(ctx, pluginabi.MethodHostStreamEmit, req.StreamID); errAccess != nil {
		return nil, errAccess
	}
	chunk := pluginapi.ExecutorStreamChunk{Payload: append([]byte(nil), req.Payload...)}
	if req.Error != "" {
		chunk.Err = fmt.Errorf("%s", req.Error)
	}
	if errEmit := h.streams.emit(ctx, req.StreamID, chunk); errEmit != nil {
		return nil, errEmit
	}
	return marshalRPCResult(rpcEmptyResponse{})
}

func (h *Host) callHostStreamClose(request []byte) ([]byte, error) {
	var req rpcStreamCloseRequest
	if errUnmarshal := json.Unmarshal(request, &req); errUnmarshal != nil {
		return nil, fmt.Errorf("decode stream close request: %w", errUnmarshal)
	}
	h.streams.close(req.StreamID, req.Error)
	return marshalRPCResult(rpcEmptyResponse{})
}

func (h *Host) callHostModelExecute(ctx context.Context, request []byte) ([]byte, error) {
	var req rpcHostModelExecutionRequest
	if errUnmarshal := json.Unmarshal(request, &req); errUnmarshal != nil {
		return nil, fmt.Errorf("decode host model execution request: %w", errUnmarshal)
	}
	if req.Stream {
		return nil, fmt.Errorf("host.model.execute requires stream=false")
	}
	if errProxy := validateHostModelProxy(req.ProxyURL); errProxy != nil {
		return nil, errProxy
	}
	executor := h.currentModelExecutor()
	if executor == nil {
		return nil, fmt.Errorf("host model executor is unavailable")
	}
	skipPluginID := h.callbackCallerPluginID(ctx, req.HostCallbackID)
	var errContext error
	ctx, errContext = h.resolveGroupingCallbackContext(ctx, req.HostCallbackID)
	if errContext != nil {
		return nil, errContext
	}
	resp, errMsg := executor.ExecuteModel(ctx, modelExecutionRequestFromPlugin(req.HostModelExecutionRequest, skipPluginID))
	if errMsg != nil {
		return nil, modelExecutionError(errMsg)
	}
	return marshalRPCResult(pluginapi.HostModelExecutionResponse{
		StatusCode: resp.StatusCode,
		Headers:    cloneHeader(resp.Headers),
		Body:       append([]byte(nil), resp.Body...),
	})
}

func modelExecutionRequestFromPlugin(req pluginapi.HostModelExecutionRequest, skipPluginID string) handlers.ModelExecutionRequest {
	return handlers.ModelExecutionRequest{
		EntryProtocol:           req.EntryProtocol,
		ExitProtocol:            req.ExitProtocol,
		Model:                   req.Model,
		Stream:                  req.Stream,
		Body:                    append([]byte(nil), req.Body...),
		Headers:                 cloneHeader(req.Headers),
		Query:                   cloneValues(req.Query),
		Alt:                     req.Alt,
		SkipInterceptorPluginID: skipPluginID,
		SkipRouterPluginID:      skipPluginID,
		ForcedProvider:          req.ForcedProvider,
		AuthID:                  req.AuthID,
		ProxyURL:                strings.TrimSpace(req.ProxyURL),
		Path:                    strings.TrimSpace(req.Path),
	}
}

func validateHostModelProxy(raw string) error {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	if !proxyutil.ValidRequestProxy(raw) {
		return &modelExecutionStatusError{
			err:        fmt.Errorf("invalid proxy_url"),
			statusCode: http.StatusBadRequest,
		}
	}
	return nil
}

type modelExecutionStatusError struct {
	err        error
	statusCode int
}

func (e *modelExecutionStatusError) Error() string {
	if e.err != nil {
		return e.err.Error()
	}
	if e.statusCode > 0 {
		return fmt.Sprintf("model execution failed with status %d", e.statusCode)
	}
	return "model execution failed"
}

func (e *modelExecutionStatusError) StatusCode() int {
	return e.statusCode
}

func (e *modelExecutionStatusError) Unwrap() error {
	return e.err
}

func modelExecutionError(errMsg *interfaces.ErrorMessage) error {
	if errMsg == nil {
		return nil
	}
	if errMsg.StatusCode > 0 && clienterror.HTTPStatusFromError(errMsg.Error) != errMsg.StatusCode {
		return &modelExecutionStatusError{
			err:        errMsg.Error,
			statusCode: errMsg.StatusCode,
		}
	}
	if errMsg.Error != nil {
		return errMsg.Error
	}
	return fmt.Errorf("model execution failed")
}

func (h *Host) callHostLog(ctx context.Context, request []byte) ([]byte, error) {
	var req rpcHostLogRequest
	if errUnmarshal := json.Unmarshal(request, &req); errUnmarshal != nil {
		return nil, fmt.Errorf("decode host log request: %w", errUnmarshal)
	}
	ctx = h.resolveCallbackContext(req.HostCallbackID, ctx)
	message := strings.TrimSpace(req.Message)
	if message == "" {
		message = "plugin log"
	}
	fields := log.Fields{}
	for key, value := range req.Fields {
		key = strings.TrimSpace(key)
		if key != "" {
			fields[key] = value
		}
	}
	if requestID := logging.GetRequestID(ctx); requestID != "" {
		fields["request_id"] = requestID
	}
	entry := log.WithFields(fields)
	switch strings.ToLower(strings.TrimSpace(req.Level)) {
	case "trace":
		entry.Trace(message)
	case "info":
		entry.Info(message)
	case "warn", "warning":
		entry.Warn(message)
	case "error":
		entry.Error(message)
	default:
		entry.Debug(message)
	}
	return marshalRPCResult(rpcEmptyResponse{})
}
