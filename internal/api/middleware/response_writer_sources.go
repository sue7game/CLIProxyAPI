package middleware

import (
	"bytes"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/logging"
	log "github.com/sirupsen/logrus"
)

type responseLogSources struct {
	websocketTimeline    *logging.FileBodySource
	apiRequest           *logging.FileBodySource
	apiResponse          *logging.FileBodySource
	apiWebsocketTimeline *logging.FileBodySource
}

func (w *ResponseWriterWrapper) extractResponseLogSources(c *gin.Context) responseLogSources {
	return responseLogSources{
		websocketTimeline:    w.extractWebsocketTimelineSource(c),
		apiRequest:           w.extractAPIRequestSource(c),
		apiResponse:          w.extractAPIResponseSource(c),
		apiWebsocketTimeline: w.extractAPIWebsocketTimelineSource(c),
	}
}

func (s responseLogSources) cleanup() {
	cleanupFileBodySources(s.websocketTimeline, s.apiRequest, s.apiResponse, s.apiWebsocketTimeline)
}

func mergeFileBodySource(payload []byte, source *logging.FileBodySource) ([]byte, error) {
	if source == nil {
		return payload, nil
	}
	defer cleanupFileBodySources(source)
	if !source.HasPayload() {
		return payload, nil
	}
	var buf bytes.Buffer
	if len(payload) > 0 {
		buf.Write(payload)
		if !bytes.HasSuffix(payload, []byte("\n")) {
			buf.WriteByte('\n')
		}
		buf.WriteByte('\n')
	}
	if _, errWrite := source.WriteTo(&buf); errWrite != nil {
		return nil, errWrite
	}
	return buf.Bytes(), nil
}

func cleanupFileBodySources(sources ...*logging.FileBodySource) {
	for _, source := range sources {
		if source == nil {
			continue
		}
		if errCleanup := source.Cleanup(); errCleanup != nil {
			log.WithError(errCleanup).Warn("failed to clean up log part files")
		}
	}
}
