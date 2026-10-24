package pluginhost

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

func (h *Host) callHostHTTPDo(ctx context.Context, request []byte) ([]byte, error) {
	httpReq, callbackID, operationID, errDecode := decodeHostHTTPRequestWithOperationID(request)
	if errDecode != nil {
		return nil, errDecode
	}
	operation, errAcquire := h.acquireHostHTTPOperation(ctx, callbackID, operationID)
	if errAcquire != nil {
		return nil, errAcquire
	}
	defer operation.finish()
	resp, errDo := h.newHTTPClient(nil).Do(operation.ctx, httpReq)
	if errDo != nil {
		return nil, errDo
	}
	return marshalRPCResult(resp)
}

func newStreamContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithCancel(ctx)
}

func (h *Host) callHostHTTPDoStream(ctx context.Context, request []byte) ([]byte, error) {
	httpReq, callbackID, operationID, errDecode := decodeHostHTTPRequestWithOperationID(request)
	if errDecode != nil {
		return nil, errDecode
	}
	operation, errAcquire := h.acquireHostHTTPOperation(ctx, callbackID, operationID)
	if errAcquire != nil {
		return nil, errAcquire
	}
	streamCtx := operation.ctx
	streamID := ""
	keepStream := false
	defer func() {
		if keepStream {
			return
		}
		if streamID != "" && h != nil && h.httpStreams != nil {
			h.httpStreams.close(operation.pluginID, operation.instance, streamID)
		}
		operation.finish()
	}()

	resp, errDo := h.newHTTPClient(nil).DoStream(streamCtx, httpReq)
	if errDo != nil {
		return nil, errDo
	}
	if h != nil && h.httpStreams != nil {
		streamID = h.httpStreams.openOwned(operation.pluginID, operation.instance, resp.Chunks, operation.cancel, operation.finish, callbackID)
	}
	if streamID == "" {
		return nil, fmt.Errorf("host http stream bridge is unavailable")
	}
	rawResp, errMarshal := marshalRPCResult(rpcHostHTTPStreamResponse{
		StatusCode: resp.StatusCode,
		Headers:    httpHeader(resp.Headers),
		StreamID:   streamID,
	})
	if errMarshal != nil {
		return nil, errMarshal
	}
	if operation.entry != nil {
		cleanupStream := func() {
			h.httpStreams.close(operation.pluginID, operation.instance, streamID)
		}
		if !h.httpOperations.setCleanup(operation.pluginID, operation.operationID, operation.entry, cleanupStream) {
			return nil, context.Canceled
		}
	}
	keepStream = true
	return rawResp, nil
}

func (h *Host) callHostHTTPOperationOpen(ctx context.Context, request []byte) ([]byte, error) {
	var req rpcHostHTTPOperationOpenRequest
	if errUnmarshal := json.Unmarshal(request, &req); errUnmarshal != nil {
		return nil, fmt.Errorf("decode host http operation open request: %w", errUnmarshal)
	}
	operationID, errOpen := h.openHostHTTPOperation(ctx, req.HostCallbackID)
	if errOpen != nil {
		return nil, errOpen
	}
	return marshalRPCResult(rpcHostHTTPOperationOpenResponse{OperationID: operationID})
}

func (h *Host) callHostHTTPCancel(ctx context.Context, request []byte) ([]byte, error) {
	var req rpcHostHTTPCancelRequest
	if errUnmarshal := json.Unmarshal(request, &req); errUnmarshal != nil {
		return nil, fmt.Errorf("decode host http cancel request: %w", errUnmarshal)
	}
	operationID := strings.TrimSpace(req.OperationID)
	if operationID == "" {
		return nil, fmt.Errorf("host http operation id is required")
	}
	manager, errPolicy := h.groupingAccessManager()
	if errPolicy != nil {
		return nil, errPolicy
	}
	grouped := manager != nil && manager.CredentialAccessPolicyEnabled()
	if grouped {
		if _, errContext := h.resolveGroupingCallbackContext(ctx, req.HostCallbackID); errContext != nil {
			return nil, errContext
		}
	}
	if h != nil && h.httpOperations != nil {
		pluginID := h.callbackCallerPluginID(ctx, req.HostCallbackID)
		instance := hostCallbackInstanceFromContext(ctx)
		if instance == nil {
			_, _, instance, _ = h.lookupCallbackContext(req.HostCallbackID)
		}
		h.httpOperations.cancelOwned(pluginID, instance, operationID, req.HostCallbackID, grouped)
	}
	return marshalRPCResult(rpcEmptyResponse{})
}

func (h *Host) callHostHTTPStreamRead(ctx context.Context, request []byte) ([]byte, error) {
	var req rpcHostHTTPStreamReadRequest
	if errUnmarshal := json.Unmarshal(request, &req); errUnmarshal != nil {
		return nil, fmt.Errorf("decode host http stream read request: %w", errUnmarshal)
	}
	if h == nil || h.httpStreams == nil {
		return nil, fmt.Errorf("host http stream bridge is unavailable")
	}
	if errAccess := h.authorizeGroupedStream(ctx, pluginabi.MethodHostHTTPStreamRead, req.StreamID); errAccess != nil {
		return nil, errAccess
	}
	chunk, done, errRead := h.httpStreams.read(ctx, hostCallbackPluginIDFromContext(ctx), hostCallbackInstanceFromContext(ctx), req.StreamID)
	if errRead != nil {
		return nil, errRead
	}
	resp := rpcHostHTTPStreamReadResponse{
		Payload: append([]byte(nil), chunk.Payload...),
		Done:    done,
	}
	if chunk.Err != nil {
		resp.Error = chunk.Err.Error()
		resp.Done = true
	}
	return marshalRPCResult(resp)
}

func (h *Host) callHostHTTPStreamClose(ctx context.Context, request []byte) ([]byte, error) {
	var req rpcHostHTTPStreamCloseRequest
	if errUnmarshal := json.Unmarshal(request, &req); errUnmarshal != nil {
		return nil, fmt.Errorf("decode host http stream close request: %w", errUnmarshal)
	}
	if h != nil && h.httpStreams != nil {
		h.httpStreams.close(hostCallbackPluginIDFromContext(ctx), hostCallbackInstanceFromContext(ctx), req.StreamID)
	}
	return marshalRPCResult(rpcEmptyResponse{})
}

func decodeHostHTTPRequest(raw []byte) (pluginapi.HTTPRequest, error) {
	httpReq, _, errDecode := decodeHostHTTPRequestWithCallbackID(raw)
	return httpReq, errDecode
}

func decodeHostHTTPRequestWithCallbackID(raw []byte) (pluginapi.HTTPRequest, string, error) {
	httpReq, callbackID, _, errDecode := decodeHostHTTPRequestWithOperationID(raw)
	return httpReq, callbackID, errDecode
}

func decodeHostHTTPRequestWithOperationID(raw []byte) (pluginapi.HTTPRequest, string, string, error) {
	var req rpcHostHTTPRequest
	if errUnmarshal := json.Unmarshal(raw, &req); errUnmarshal != nil {
		return pluginapi.HTTPRequest{}, "", "", fmt.Errorf("decode host http request: %w", errUnmarshal)
	}
	if req.Request != nil {
		wireProfile := req.Request.WireProfile
		if wireProfile == nil {
			wireProfile = req.WireProfile
		}
		return pluginapi.HTTPRequest{
			Method:      req.Request.Method,
			URL:         req.Request.URL,
			Headers:     map[string][]string(req.Request.Headers),
			Body:        append([]byte(nil), req.Request.Body...),
			WireProfile: cloneWireProfile(wireProfile),
		}, req.HostCallbackID, strings.TrimSpace(req.OperationID), nil
	}
	return pluginapi.HTTPRequest{
		Method:      req.Method,
		URL:         req.URL,
		Headers:     map[string][]string(req.Headers),
		Body:        append([]byte(nil), req.Body...),
		WireProfile: cloneWireProfile(req.WireProfile),
	}, req.HostCallbackID, strings.TrimSpace(req.OperationID), nil
}

func cloneWireProfile(src *pluginapi.HTTPWireProfile) *pluginapi.HTTPWireProfile {
	if src == nil {
		return nil
	}
	dst := *src
	dst.HeaderProfile = append([]string(nil), src.HeaderProfile...)
	return &dst
}
