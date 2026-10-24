package middleware

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"testing/synctest"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/logging"
)

func TestResponseWriterStreamingDrainsWhenFinalizedBeforeProcessorStarts(t *testing.T) {
	gin.SetMode(gin.TestMode)
	synctest.Test(t, func(t *testing.T) {
		writer := &streamingLifecycleWriter{}
		wrapper, c, recorder := newStreamingLifecycleWrapper(writer)
		wrapper.isStreaming = true
		wrapper.streamWriter = writer
		wrapper.chunkChannel = make(chan []byte, 3)
		wrapper.streamDone = make(chan struct{})
		chunks, done := wrapper.chunkChannel, wrapper.streamDone
		processor := func() { processStreamingChunks(writer, chunks, done) }
		writeStreamingLifecycleChunks(t, wrapper)

		finalized := make(chan error, 1)
		go func() { finalized <- wrapper.Finalize(c) }()
		synctest.Wait()
		assertStreamingFinalizationPending(t, finalized, writer)
		if wrapper.chunkChannel != nil {
			t.Fatal("finalization did not detach the closed queue")
		}

		// Reproduce a processor that first runs after Finalize has closed the queue.
		go processor()
		if err := <-finalized; err != nil {
			t.Fatal(err)
		}
		assertStreamingLifecycleComplete(t, wrapper, writer, recorder)
	})
}

func TestResponseWriterStreamingWaitsForInFlightChunks(t *testing.T) {
	gin.SetMode(gin.TestMode)
	synctest.Test(t, func(t *testing.T) {
		entered, release := make(chan struct{}, 1), make(chan struct{})
		writer := &streamingLifecycleWriter{beforeChunk: func() {
			select {
			case entered <- struct{}{}:
			default:
			}
			<-release
		}}
		wrapper, c, recorder := newStreamingLifecycleWrapper(writer)
		wrapper.Header().Set("Content-Type", "text/event-stream")
		wrapper.WriteHeader(http.StatusOK)
		writeStreamingLifecycleChunks(t, wrapper)
		<-entered

		finalized := make(chan error, 1)
		go func() { finalized <- wrapper.Finalize(c) }()
		synctest.Wait()
		assertStreamingFinalizationPending(t, finalized, writer)
		close(release)
		if err := <-finalized; err != nil {
			t.Fatal(err)
		}
		assertStreamingLifecycleComplete(t, wrapper, writer, recorder)
	})
}

func newStreamingLifecycleWrapper(writer *streamingLifecycleWriter) (*ResponseWriterWrapper, *gin.Context, *httptest.ResponseRecorder) {
	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	logger := &streamingLifecycleLogger{testRequestLogger: testRequestLogger{enabled: true}, writer: writer}
	return NewResponseWriterWrapper(c.Writer, logger, &RequestInfo{RequestID: "streaming-lifecycle-test"}), c, recorder
}

func writeStreamingLifecycleChunks(t *testing.T, wrapper *ResponseWriterWrapper) {
	t.Helper()
	chunk := []byte("first")
	if _, err := wrapper.Write(chunk); err != nil {
		t.Fatal(err)
	}
	chunk[0] = 'X'
	if _, err := wrapper.WriteString("second"); err != nil {
		t.Fatal(err)
	}
	if _, err := wrapper.Write([]byte("third")); err != nil {
		t.Fatal(err)
	}
}

func assertStreamingFinalizationPending(t *testing.T, finalized <-chan error, writer *streamingLifecycleWriter) {
	t.Helper()
	select {
	case err := <-finalized:
		t.Fatalf("finalization returned before the processor drained: %v", err)
	default:
	}
	if writer.closed {
		t.Fatal("stream writer closed before the processor drained")
	}
}

func assertStreamingLifecycleComplete(t *testing.T, wrapper *ResponseWriterWrapper, writer *streamingLifecycleWriter, recorder *httptest.ResponseRecorder) {
	t.Helper()
	if got, want := writer.events, []string{"first", "second", "third", "close"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("stream log events = %q, want %q", got, want)
	}
	if !writer.closed || wrapper.streamWriter != nil || wrapper.streamDone != nil || wrapper.chunkChannel != nil {
		t.Fatal("streaming resources were not released")
	}
	if got := recorder.Body.String(); got != "firstsecondthird" {
		t.Fatalf("client response = %q", got)
	}
}

type streamingLifecycleLogger struct {
	testRequestLogger
	writer logging.StreamingLogWriter
}

func (l *streamingLifecycleLogger) LogStreamingRequest(string, string, map[string][]string, []byte, string) (logging.StreamingLogWriter, error) {
	return l.writer, nil
}

type streamingLifecycleWriter struct {
	logging.NoOpStreamingLogWriter
	beforeChunk func()
	events      []string
	closed      bool
}

func (w *streamingLifecycleWriter) WriteChunkAsync(chunk []byte) {
	if w.beforeChunk != nil {
		w.beforeChunk()
	}
	w.events = append(w.events, string(chunk))
}

func (w *streamingLifecycleWriter) Close() error {
	w.events = append(w.events, "close")
	w.closed = true
	return nil
}
