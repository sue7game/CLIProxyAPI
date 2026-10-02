package pluginhost

import (
	"context"
	"encoding/json"

	"github.com/google/uuid"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginabi"
	log "github.com/sirupsen/logrus"
)

func newGroupingBridgeID() string {
	id, err := uuid.NewRandom()
	if err != nil {
		log.Errorf("pluginhost: create stream bridge identifier: %v", err)
		return ""
	}
	return id.String()
}

func (h *Host) authorizeGroupedStream(ctx context.Context, method, id string) error {
	manager, err := h.groupingAccessManager()
	if err != nil {
		return err
	}
	if manager == nil || !manager.CredentialAccessPolicyEnabled() {
		return nil
	}
	owner := h.groupedStreamOwner(method, id)
	_, err = h.resolveGroupingCallbackContext(ctx, owner)
	return err
}

func (h *Host) groupedStreamOwner(method, id string) string {
	switch method {
	case pluginabi.MethodHostModelStreamRead, pluginabi.MethodHostModelStreamClose:
		if h.modelStreams != nil {
			h.modelStreams.mu.Lock()
			defer h.modelStreams.mu.Unlock()
			return h.modelStreams.streams[id].ownerCallbackID
		}
	case pluginabi.MethodHostHTTPStreamRead, pluginabi.MethodHostHTTPStreamClose:
		if h.httpStreams != nil {
			h.httpStreams.mu.Lock()
			defer h.httpStreams.mu.Unlock()
			return h.httpStreams.streams[id].ownerCallbackID
		}
	case pluginabi.MethodHostStreamEmit, pluginabi.MethodHostStreamClose:
		if h.streams != nil {
			h.streams.mu.Lock()
			defer h.streams.mu.Unlock()
			if stream := h.streams.streams[id]; stream != nil {
				return stream.ownerCallbackID
			}
		}
	}
	return ""
}

func (h *Host) callGroupedStreamClose(ctx context.Context, method string, request []byte) ([]byte, error) {
	var req struct {
		StreamID string `json:"stream_id"`
	}
	if err := json.Unmarshal(request, &req); err != nil {
		return nil, err
	}
	if err := h.authorizeGroupedStream(ctx, method, req.StreamID); err != nil {
		return nil, err
	}
	switch method {
	case pluginabi.MethodHostModelStreamClose:
		return h.callHostModelStreamClose(request)
	case pluginabi.MethodHostHTTPStreamClose:
		return h.callHostHTTPStreamClose(request)
	default:
		return h.callHostStreamClose(request)
	}
}
