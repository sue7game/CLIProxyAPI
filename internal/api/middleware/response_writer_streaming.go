package middleware

import (
	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/logging"
)

// processStreamingChunks owns immutable snapshots of the stream resources.
// Finalize may detach the wrapper's fields before this goroutine first runs.
func processStreamingChunks(writer logging.StreamingLogWriter, chunks <-chan []byte, done chan<- struct{}) {
	if done == nil {
		return
	}

	defer close(done)

	if writer == nil || chunks == nil {
		return
	}

	for chunk := range chunks {
		writer.WriteChunkAsync(chunk)
	}
}

func (w *ResponseWriterWrapper) finalizeStreaming(c *gin.Context, sources responseLogSources) error {
	if w.chunkChannel != nil {
		close(w.chunkChannel)
		w.chunkChannel = nil
	}
	if w.streamDone != nil {
		<-w.streamDone
		w.streamDone = nil
	}

	w.streamWriter.SetFirstChunkTimestamp(w.firstChunkTimestamp)
	if err := w.writeStreamingAPIExchange(c, sources); err != nil {
		sources.cleanup()
		return err
	}
	apiWebsocketTimeline, errMerge := mergeFileBodySource(w.extractAPIWebsocketTimeline(c), sources.apiWebsocketTimeline)
	if errMerge != nil {
		sources.cleanup()
		return errMerge
	}
	if len(apiWebsocketTimeline) > 0 {
		_ = w.streamWriter.WriteAPIWebsocketTimeline(apiWebsocketTimeline)
	}
	errClose := w.streamWriter.Close()
	w.streamWriter = nil
	sources.cleanup()
	return errClose
}

func (w *ResponseWriterWrapper) writeStreamingAPIExchange(c *gin.Context, sources responseLogSources) error {
	apiRequest := w.extractAPIRequest(c)
	apiResponse := w.extractAPIResponse(c)
	if sourceWriter, ok := w.streamWriter.(interface {
		WriteAPIRequestSource(*logging.FileBodySource) error
		WriteAPIResponseSource(*logging.FileBodySource) error
	}); ok {
		if len(apiRequest) > 0 {
			_ = w.streamWriter.WriteAPIRequest(apiRequest)
		}
		if sources.apiRequest != nil && sources.apiRequest.HasPayload() {
			_ = sourceWriter.WriteAPIRequestSource(sources.apiRequest)
		}
		if len(apiResponse) > 0 {
			_ = w.streamWriter.WriteAPIResponse(apiResponse)
		}
		if sources.apiResponse != nil && sources.apiResponse.HasPayload() {
			_ = sourceWriter.WriteAPIResponseSource(sources.apiResponse)
		}
		return nil
	}

	var errMerge error
	apiRequest, errMerge = mergeFileBodySource(apiRequest, sources.apiRequest)
	if errMerge != nil {
		return errMerge
	}
	apiResponse, errMerge = mergeFileBodySource(apiResponse, sources.apiResponse)
	if errMerge != nil {
		return errMerge
	}
	if len(apiRequest) > 0 {
		_ = w.streamWriter.WriteAPIRequest(apiRequest)
	}
	if len(apiResponse) > 0 {
		_ = w.streamWriter.WriteAPIResponse(apiResponse)
	}
	return nil
}
