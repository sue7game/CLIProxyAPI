package middleware

import (
	"context"
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/clienterror"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/interfaces"
)

// Finalize completes logging after the request handler returns. It drains the
// streaming processor before closing its writer, or logs the buffered response.
func (w *ResponseWriterWrapper) Finalize(c *gin.Context) error {
	if w.requestInfo != nil && w.requestInfo.deferredBodyCapture != nil {
		defer w.requestInfo.deferredBodyCapture.Cleanup()
	}
	if w.logger == nil {
		return nil
	}

	finalStatusCode := w.finalStatusCode()
	apiErrors := extractAPIResponseErrors(c)
	hasAPIError := hasActionableError(c, finalStatusCode, apiErrors)
	forceLog := w.logOnErrorOnly && hasAPIError && !w.logger.IsEnabled()
	sources := w.extractResponseLogSources(c)
	if !w.logger.IsEnabled() && !forceLog {
		sources.cleanup()
		return nil
	}
	if w.isStreaming && w.streamWriter != nil {
		return w.finalizeStreaming(c, sources)
	}
	return w.logRequest(w.captureResponseLogEntry(c, sources, finalStatusCode, apiErrors, forceLog))
}

func (w *ResponseWriterWrapper) finalStatusCode() int {
	if w.statusCode != 0 {
		return w.statusCode
	}
	if statusWriter, ok := w.ResponseWriter.(interface{ Status() int }); ok {
		return statusWriter.Status()
	}
	return http.StatusOK
}

func extractAPIResponseErrors(c *gin.Context) []*interfaces.ErrorMessage {
	value, _ := c.Get("API_RESPONSE_ERROR")
	apiErrors, _ := value.([]*interfaces.ErrorMessage)
	return apiErrors
}

func isClientCancellationErrorMessage(errMsg *interfaces.ErrorMessage) bool {
	if errMsg == nil {
		return true
	}
	return clienterror.IsClientCancellation(errMsg.StatusCode, errMsg.Error)
}

func hasActionableAPIResponseErrors(apiErrors []*interfaces.ErrorMessage) bool {
	for _, err := range apiErrors {
		if !isClientCancellationErrorMessage(err) {
			return true
		}
	}
	return false
}

func isContextCanceled(c *gin.Context) bool {
	if c == nil || c.Request == nil {
		return false
	}
	ctx := c.Request.Context()
	return ctx != nil && errors.Is(ctx.Err(), context.Canceled)
}

func hasActionableError(c *gin.Context, statusCode int, apiErrors []*interfaces.ErrorMessage) bool {
	if hasActionableAPIResponseErrors(apiErrors) {
		return true
	}
	if statusCode == clienterror.StatusClientClosedRequest {
		return false
	}
	if isContextCanceled(c) && statusCode < http.StatusBadRequest {
		return false
	}
	return statusCode >= http.StatusBadRequest
}
