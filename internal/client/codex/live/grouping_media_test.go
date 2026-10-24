package live

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func groupingSDPRequest(h *Handler) *httptest.ResponseRecorder {
	router := gin.New()
	router.POST("/v1/realtime/calls", groupingLiveMiddleware, h.Handle)
	body := multipartBody("grouping-boundary", "v=0\r\no=client-offer\r\n", `{"model":"gpt-live-1-codex"}`)
	request := httptest.NewRequest(http.MethodPost, "/v1/realtime/calls", strings.NewReader(body))
	request.Header.Set("Content-Type", "multipart/form-data; boundary=grouping-boundary")
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	return recorder
}

func TestGroupingRealtimeSDPRejectsUnrevocableDirectMediaOnlyWhenEnabled(t *testing.T) {
	h, _ := groupingLiveFixture(t)
	executor := &captureExecutor{responseBody: io.NopCloser(strings.NewReader("v=0\r\no=answer\r\n"))}
	h.authManager.RegisterExecutor(executor)
	response := groupingSDPRequest(h)
	if response.Code != http.StatusServiceUnavailable || executor.httpCalls.Load() != 0 {
		t.Fatalf("direct SDP response = %d calls=%d", response.Code, executor.httpCalls.Load())
	}
	h.authManager.SetCredentialAccessPolicy(nil)
	response = groupingSDPRequest(h)
	if response.Code != http.StatusCreated || executor.httpCalls.Load() != 1 {
		t.Fatalf("disabled SDP response = %d %s calls=%d", response.Code, response.Body.String(), executor.httpCalls.Load())
	}
}

func TestGroupingRealtimeMediaRevocationClosesRetainedCall(t *testing.T) {
	h, policy := groupingLiveFixture(t)
	h.authManager.RegisterExecutor(&captureExecutor{responseBody: io.NopCloser(strings.NewReader("v=0\r\no=upstream-answer\r\n"))})
	media := &groupingMediaSession{done: make(chan struct{})}
	h.mediaRelay = &groupingMediaRelay{session: media}
	response := groupingSDPRequest(h)
	if response.Code != http.StatusCreated {
		t.Fatalf("relay SDP response = %d %s", response.Code, response.Body.String())
	}
	if _, exists := h.sessions.peek("call-123"); !exists || media.closed.Load() {
		t.Fatal("authorized call was not retained")
	}
	policy.revoked.Store(true)
	h.authManager.NotifyCredentialAccessChanged()
	awaitGroupingClose(t, media.done)
	if _, exists := h.sessions.peek("call-123"); exists {
		t.Fatal("revoked media call remains accessible")
	}
}

func TestGroupingRealtimeClientSecretRejectsSpoofedIssuer(t *testing.T) {
	h, _ := groupingLiveFixture(t)
	router := gin.New()
	router.POST("/v1/realtime/client_secrets", func(c *gin.Context) {
		c.Set("userApiKey", "live-issuer")
		c.Set("accessProvider", "test")
	}, h.CreateClientSecret)
	request := httptest.NewRequest(http.MethodPost, "/v1/realtime/client_secrets", strings.NewReader(`{"session":{"type":"realtime","model":"gpt-realtime"}}`))
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("spoofed issuer response = %d %s", response.Code, response.Body.String())
	}
}
