package middleware

import (
	"time"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/interfaces"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/logging"
)

type responseLogEntry struct {
	requestBody          []byte
	statusCode           int
	headers              map[string][]string
	body                 []byte
	websocketTimeline    []byte
	apiRequestBody       []byte
	apiResponseBody      []byte
	apiWebsocketTimeline []byte
	apiResponseTimestamp time.Time
	apiResponseErrors    []*interfaces.ErrorMessage
	forceLog             bool
	sources              responseLogSources
}

func (w *ResponseWriterWrapper) captureResponseLogEntry(c *gin.Context, sources responseLogSources, statusCode int, apiErrors []*interfaces.ErrorMessage, forceLog bool) responseLogEntry {
	apiRequest := w.extractAPIRequest(c)
	if forceLog && len(apiRequest) == 0 {
		apiRequest = w.extractDeferredAPIRequest(c)
	}
	return responseLogEntry{
		requestBody:          w.extractRequestBody(c),
		statusCode:           statusCode,
		headers:              w.cloneHeaders(),
		body:                 w.extractResponseBody(c),
		websocketTimeline:    w.extractWebsocketTimeline(c),
		apiRequestBody:       apiRequest,
		apiResponseBody:      w.extractAPIResponse(c),
		apiWebsocketTimeline: w.extractAPIWebsocketTimeline(c),
		apiResponseTimestamp: w.extractAPIResponseTimestamp(c),
		apiResponseErrors:    apiErrors,
		forceLog:             forceLog,
		sources:              sources,
	}
}

func (w *ResponseWriterWrapper) logRequest(entry responseLogEntry) error {
	if w.requestInfo == nil {
		entry.sources.cleanup()
		return nil
	}
	if loggerWithAllSources, ok := w.logger.(interface {
		LogRequestWithOptionsAndAllSources(string, string, map[string][]string, []byte, int, map[string][]string, []byte, []byte, *logging.FileBodySource, []byte, *logging.FileBodySource, []byte, *logging.FileBodySource, []byte, *logging.FileBodySource, []*interfaces.ErrorMessage, bool, string, time.Time, time.Time) error
	}); ok {
		return loggerWithAllSources.LogRequestWithOptionsAndAllSources(
			w.requestInfo.URL,
			w.requestInfo.Method,
			w.requestInfo.Headers,
			entry.requestBody,
			entry.statusCode,
			entry.headers,
			entry.body,
			entry.websocketTimeline,
			entry.sources.websocketTimeline,
			entry.apiRequestBody,
			entry.sources.apiRequest,
			entry.apiResponseBody,
			entry.sources.apiResponse,
			entry.apiWebsocketTimeline,
			entry.sources.apiWebsocketTimeline,
			entry.apiResponseErrors,
			entry.forceLog,
			w.requestInfo.RequestID,
			w.requestInfo.Timestamp,
			entry.apiResponseTimestamp,
		)
	}
	return w.logRequestWithBodySources(entry)
}

func (w *ResponseWriterWrapper) logRequestWithBodySources(entry responseLogEntry) error {
	if loggerWithSources, ok := w.logger.(interface {
		LogRequestWithOptionsAndSources(string, string, map[string][]string, []byte, int, map[string][]string, []byte, []byte, *logging.FileBodySource, []byte, []byte, []byte, *logging.FileBodySource, []*interfaces.ErrorMessage, bool, string, time.Time, time.Time) error
	}); ok {
		if err := entry.mergeAPIBodySources(); err != nil {
			entry.sources.cleanup()
			return err
		}
		return loggerWithSources.LogRequestWithOptionsAndSources(
			w.requestInfo.URL,
			w.requestInfo.Method,
			w.requestInfo.Headers,
			entry.requestBody,
			entry.statusCode,
			entry.headers,
			entry.body,
			entry.websocketTimeline,
			entry.sources.websocketTimeline,
			entry.apiRequestBody,
			entry.apiResponseBody,
			entry.apiWebsocketTimeline,
			entry.sources.apiWebsocketTimeline,
			entry.apiResponseErrors,
			entry.forceLog,
			w.requestInfo.RequestID,
			w.requestInfo.Timestamp,
			entry.apiResponseTimestamp,
		)
	}
	if err := entry.mergeAllBodySources(); err != nil {
		entry.sources.cleanup()
		return err
	}
	return w.logBufferedRequest(entry)
}

func (w *ResponseWriterWrapper) logBufferedRequest(entry responseLogEntry) error {
	if loggerWithOptions, ok := w.logger.(interface {
		LogRequestWithOptions(string, string, map[string][]string, []byte, int, map[string][]string, []byte, []byte, []byte, []byte, []byte, []*interfaces.ErrorMessage, bool, string, time.Time, time.Time) error
	}); ok {
		return loggerWithOptions.LogRequestWithOptions(
			w.requestInfo.URL,
			w.requestInfo.Method,
			w.requestInfo.Headers,
			entry.requestBody,
			entry.statusCode,
			entry.headers,
			entry.body,
			entry.websocketTimeline,
			entry.apiRequestBody,
			entry.apiResponseBody,
			entry.apiWebsocketTimeline,
			entry.apiResponseErrors,
			entry.forceLog,
			w.requestInfo.RequestID,
			w.requestInfo.Timestamp,
			entry.apiResponseTimestamp,
		)
	}
	return w.logger.LogRequest(
		w.requestInfo.URL,
		w.requestInfo.Method,
		w.requestInfo.Headers,
		entry.requestBody,
		entry.statusCode,
		entry.headers,
		entry.body,
		entry.websocketTimeline,
		entry.apiRequestBody,
		entry.apiResponseBody,
		entry.apiWebsocketTimeline,
		entry.apiResponseErrors,
		w.requestInfo.RequestID,
		w.requestInfo.Timestamp,
		entry.apiResponseTimestamp,
	)
}

func (entry *responseLogEntry) mergeAPIBodySources() error {
	var err error
	entry.apiRequestBody, err = mergeFileBodySource(entry.apiRequestBody, entry.sources.apiRequest)
	if err != nil {
		return err
	}
	entry.apiResponseBody, err = mergeFileBodySource(entry.apiResponseBody, entry.sources.apiResponse)
	return err
}

func (entry *responseLogEntry) mergeAllBodySources() error {
	var err error
	entry.websocketTimeline, err = mergeFileBodySource(entry.websocketTimeline, entry.sources.websocketTimeline)
	if err != nil {
		return err
	}
	if err = entry.mergeAPIBodySources(); err != nil {
		return err
	}
	entry.apiWebsocketTimeline, err = mergeFileBodySource(entry.apiWebsocketTimeline, entry.sources.apiWebsocketTimeline)
	return err
}
