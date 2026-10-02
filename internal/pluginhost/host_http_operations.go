package pluginhost

import (
	"context"
	"fmt"
	"strings"
)

func (h *Host) closeHostHTTPCallbackInstance(pluginID string, instance *hostCallbackInstance) {
	if instance != nil {
		instance.closed.Store(true)
	}
	if h == nil {
		return
	}
	if h.httpOperations != nil {
		h.httpOperations.closeInstance(pluginID, instance)
	}
	if h.httpStreams != nil {
		h.httpStreams.closeInstance(pluginID, instance)
	}
}

func (h *Host) closeHostHTTPPluginResources(pluginID string, instance *hostCallbackInstance) {
	h.closeHostHTTPCallbackInstance(pluginID, instance)
	if h == nil {
		return
	}
	if h.httpOperations != nil {
		h.httpOperations.cancelPlugin(pluginID)
	}
	if h.httpStreams != nil {
		h.httpStreams.closePlugin(pluginID)
	}
}

func (h *Host) resolveHostHTTPContext(ctx context.Context, callbackID string) (context.Context, string, *hostCallbackInstance, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	parent, errContext := h.resolveGroupingCallbackContext(ctx, callbackID)
	if errContext != nil {
		return nil, "", nil, errContext
	}
	pluginID := hostCallbackPluginIDFromContext(ctx)
	instance := hostCallbackInstanceFromContext(ctx)
	if callbackID == "" {
		return parent, pluginID, instance, nil
	}
	parent, callbackPluginID, callbackInstance, exists := h.lookupCallbackContext(callbackID)
	if !exists {
		return nil, "", nil, fmt.Errorf("host callback ID is not open")
	}
	if pluginID != "" && callbackPluginID != pluginID {
		return nil, "", nil, fmt.Errorf("host callback ID does not belong to the calling plugin")
	}
	if instance != callbackInstance {
		return nil, "", nil, fmt.Errorf("host callback ID does not belong to the calling plugin instance")
	}
	return parent, callbackPluginID, callbackInstance, nil
}

func (h *Host) openHostHTTPOperation(ctx context.Context, callbackID string) (string, error) {
	callbackID = strings.TrimSpace(callbackID)
	parent, pluginID, instance, errContext := h.resolveHostHTTPContext(ctx, callbackID)
	if errContext != nil {
		return "", errContext
	}
	operationID, _, errOpen := h.createHostHTTPOperation(pluginID, instance, callbackID, parent, false)
	return operationID, errOpen
}

func (h *Host) createHostHTTPOperation(pluginID string, instance *hostCallbackInstance, callbackID string, parent context.Context, claimed bool) (string, *hostHTTPOperation, error) {
	if h == nil || h.httpOperations == nil {
		return "", nil, fmt.Errorf("host http operation bridge is unavailable")
	}
	var operationID string
	var entry *hostHTTPOperation
	var opened bool
	if claimed {
		operationID, entry, opened = h.httpOperations.openClaimed(pluginID, instance, callbackID, parent)
	} else {
		operationID, entry, opened = h.httpOperations.open(pluginID, instance, callbackID, parent)
	}
	if !opened {
		return "", nil, fmt.Errorf("host http operation bridge is unavailable")
	}
	if callbackID != "" {
		stopScopeCleanup, attached := h.addCallbackCleanupHandle(callbackID, func() {
			h.httpOperations.cancel(pluginID, instance, operationID)
		})
		if !attached || !h.httpOperations.setScopeCleanup(pluginID, operationID, entry, stopScopeCleanup) {
			h.httpOperations.cancel(pluginID, instance, operationID)
			return "", nil, fmt.Errorf("host callback context closed while opening HTTP operation")
		}
	}
	return operationID, entry, nil
}

func (h *Host) acquireHostHTTPOperation(ctx context.Context, callbackID, operationID string) (hostHTTPOperationHandle, error) {
	operationID = strings.TrimSpace(operationID)
	callbackID = strings.TrimSpace(callbackID)
	parent, pluginID, instance, errContext := h.resolveHostHTTPContext(ctx, callbackID)
	if errContext != nil {
		return hostHTTPOperationHandle{}, errContext
	}
	if h == nil || h.httpOperations == nil {
		return hostHTTPOperationHandle{}, fmt.Errorf("host http operation bridge is unavailable")
	}
	var entry *hostHTTPOperation
	if operationID == "" {
		var errOpen error
		operationID, entry, errOpen = h.createHostHTTPOperation(pluginID, instance, callbackID, parent, true)
		if errOpen != nil {
			return hostHTTPOperationHandle{}, errOpen
		}
	} else {
		var claimed bool
		entry, claimed = h.httpOperations.claim(pluginID, instance, operationID, callbackID)
		if !claimed {
			return hostHTTPOperationHandle{}, fmt.Errorf("host http operation %q is not open", operationID)
		}
	}
	return hostHTTPOperationHandle{
		ctx:         entry.ctx,
		cancel:      entry.cancel,
		finish:      func() { h.httpOperations.finish(pluginID, operationID, entry) },
		pluginID:    pluginID,
		instance:    instance,
		operationID: operationID,
		entry:       entry,
	}, nil
}
