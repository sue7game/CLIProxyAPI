package pluginhost

import (
	"context"
	"encoding/json"
	"strings"
	"sync"

	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

type callbackAccessDenial struct {
	mu   sync.Mutex
	err  error
	done chan struct{}
}

func newCallbackAccessDenial() *callbackAccessDenial {
	return &callbackAccessDenial{done: make(chan struct{})}
}

func (d *callbackAccessDenial) record(err error) {
	if d == nil || err == nil {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.err == nil {
		d.err = err
		close(d.done)
	}
}

func (d *callbackAccessDenial) failure(fallback error) error {
	if d == nil {
		return fallback
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.err != nil {
		return d.err
	}
	return fallback
}

func (h *Host) callbackAccessDenial(id string) *callbackAccessDenial {
	if h == nil || h.callbackContexts == nil {
		return nil
	}
	h.callbackContexts.mu.RLock()
	defer h.callbackContexts.mu.RUnlock()
	return h.callbackContexts.contexts[id].denial
}

func (h *Host) rememberCallbackAccessDenial(ctx context.Context, method string, request []byte, err error) {
	if !coreauth.IsCredentialAccessError(err) || h == nil || h.callbackContexts == nil {
		return
	}
	var req struct {
		HostCallbackID string `json:"host_callback_id"`
		StreamID       string `json:"stream_id"`
	}
	if errJSON := json.Unmarshal(request, &req); errJSON != nil {
		return
	}
	id := strings.TrimSpace(req.HostCallbackID)
	if id == "" {
		id = h.groupedStreamOwner(ctx, method, req.StreamID)
	}
	h.callbackContexts.mu.RLock()
	entry := h.callbackContexts.contexts[id]
	h.callbackContexts.mu.RUnlock()
	if entry.pluginID == "" || entry.pluginID != hostCallbackPluginIDFromContext(ctx) || entry.instance != hostCallbackInstanceFromContext(ctx) {
		return
	}
	entry.denial.record(err)
}

func callPluginWithAccess[T any](ctx context.Context, adapter *rpcPluginAdapter, method string, request any, callbackID string) (T, error) {
	result, err := callPlugin[T](ctx, adapter.client, method, request)
	// The ABI erases Go error types; only the host-owned record can restore a denial.
	if denied := adapter.host.callbackAccessDenial(callbackID).failure(err); denied != nil {
		var zero T
		return zero, denied
	}
	return result, nil
}

func withCallbackAccessErrors(ctx context.Context, source <-chan pluginapi.ExecutorStreamChunk, denial *callbackAccessDenial) <-chan pluginapi.ExecutorStreamChunk {
	if denial == nil {
		return source
	}
	if ctx == nil {
		ctx = context.Background()
	}
	out := make(chan pluginapi.ExecutorStreamChunk)
	go func() {
		defer close(out)
		for {
			var chunk pluginapi.ExecutorStreamChunk
			var ok bool
			select {
			case <-ctx.Done():
				return
			case <-denial.done:
				chunk.Err = denial.failure(nil)
			case chunk, ok = <-source:
				chunk.Err = denial.failure(chunk.Err)
				if !ok && chunk.Err == nil {
					return
				}
			}
			if coreauth.IsCredentialAccessError(chunk.Err) {
				chunk.Payload = nil
			}
			select {
			case <-ctx.Done():
				return
			case out <- chunk:
			}
			if coreauth.IsCredentialAccessError(chunk.Err) {
				return
			}
		}
	}()
	return out
}
