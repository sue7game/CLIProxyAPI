package pluginhost

import (
	"context"
	"fmt"
	"sync"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

func (a *rpcPluginAdapter) ExecuteStream(ctx context.Context, req pluginapi.ExecutorRequest) (pluginapi.ExecutorStreamResponse, error) {
	if a == nil || a.host == nil || a.host.streams == nil {
		return pluginapi.ExecutorStreamResponse{}, fmt.Errorf("plugin stream bridge is unavailable")
	}
	callbackID, closeCallback := a.openHostCallbackContext(ctx)
	streamID, chunks, cleanupStream := a.host.streams.openOwned(ctx, callbackID)
	cleanup := combinedCleanup(cleanupStream, closeCallback)
	if streamID == "" {
		cleanup()
		return pluginapi.ExecutorStreamResponse{}, fmt.Errorf("plugin stream bridge is unavailable")
	}
	rpcReq := rpcExecutorRequest{
		ExecutorRequest: req,
		StreamID:        streamID,
		HostCallbackID:  callbackID,
	}
	resp, errCall := callPluginWithAccess[rpcExecutorStreamResponse](ctx, a, pluginabi.MethodExecutorExecuteStream, rpcReq, callbackID)
	if errCall != nil {
		cleanup()
		return pluginapi.ExecutorStreamResponse{}, errCall
	}
	if len(resp.Chunks) > 0 {
		cleanup()
		out := make(chan pluginapi.ExecutorStreamChunk, len(resp.Chunks))
		for _, chunk := range resp.Chunks {
			out <- chunk
		}
		close(out)
		return pluginapi.ExecutorStreamResponse{Headers: resp.Headers, Chunks: out}, nil
	}
	// Async streaming plugins can return before they finish emitting chunks, so keep callbacks alive until the stream ends.
	return pluginapi.ExecutorStreamResponse{
		Headers: resp.Headers,
		Chunks:  cleanupWhenStreamDone(ctx, withCallbackAccessErrors(ctx, chunks, a.host.callbackAccessDenial(callbackID)), cleanup),
	}, nil
}

func combinedCleanup(cleanups ...func()) func() {
	var once sync.Once
	return func() {
		once.Do(func() {
			for _, cleanup := range cleanups {
				if cleanup != nil {
					cleanup()
				}
			}
		})
	}
}

func cleanupWhenStreamDone(ctx context.Context, chunks <-chan pluginapi.ExecutorStreamChunk, cleanup func()) <-chan pluginapi.ExecutorStreamChunk {
	out := make(chan pluginapi.ExecutorStreamChunk)
	go func() {
		defer func() {
			if cleanup != nil {
				cleanup()
			}
			close(out)
		}()
		var done <-chan struct{}
		if ctx != nil {
			done = ctx.Done()
		}
		for chunk := range chunks {
			select {
			case out <- chunk:
			case <-done:
				return
			}
		}
	}()
	return out
}
