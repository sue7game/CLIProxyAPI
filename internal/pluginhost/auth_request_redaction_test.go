package pluginhost

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
	log "github.com/sirupsen/logrus"
)

func TestHostAuthRequestRedactsErrorsAndCustomRequestHeaders(t *testing.T) {
	for _, stage := range []string{"transport", "read", "close"} {
		t.Run(stage, func(t *testing.T) { testHostAuthRequestErrorRedaction(t, stage) })
	}
}

func testHostAuthRequestErrorRedaction(t *testing.T, stage string) {
	t.Helper()
	const token = "private-auth-token"
	sentinel := fmt.Errorf("upstream echoed %s", token)
	ginCtx, _ := gin.CreateTestContext(httptest.NewRecorder())
	ctx := context.WithValue(context.Background(), "gin", ginCtx)
	transport := callbackCancelRoundTripper(func(req *http.Request) (*http.Response, error) {
		if req.Header.Get("X-Custom-Auth") != token {
			t.Error("token was not injected into the upstream request")
		}
		if stage == "transport" {
			return nil, sentinel
		}
		body := &authRequestErrorBody{Reader: strings.NewReader("ok")}
		if stage == "read" {
			body.readErr = sentinel
		} else {
			body.closeErr = sentinel
		}
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: body, Request: req}, nil
	})
	ctx = context.WithValue(ctx, "cliproxy.roundtripper", http.RoundTripper(transport))
	host, auth := newHostAuthRequestTestHost(t, &coreauth.Auth{
		ID: "redaction", Provider: "demo", Attributes: map[string]string{"api_key": token, "runtime_only": "true"},
	})
	host.runtimeConfig = &config.Config{SDKConfig: config.SDKConfig{RequestLog: true}}
	request, errMarshal := json.Marshal(pluginapi.HostAuthRequest{
		AuthIndex: auth.Index, URL: "https://quota.example.test/check",
		Headers: http.Header{"X-Custom-Auth": {"$TOKEN$"}},
	})
	if errMarshal != nil {
		t.Fatal(errMarshal)
	}
	var logs bytes.Buffer
	previousOutput := log.StandardLogger().Out
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(previousOutput) })
	_, errCall := host.callFromPlugin(ctx, pluginabi.MethodHostAuthRequest, request)
	if stage == "close" {
		if errCall != nil {
			t.Fatal(errCall)
		}
	} else if !errors.Is(errCall, sentinel) || strings.Contains(errCall.Error(), token) {
		t.Fatalf("error did not preserve identity with redacted text: %v", errCall)
	}
	assertAuthRequestLogsRedacted(t, ginCtx, logs.String(), token)
}

func assertAuthRequestLogsRedacted(t *testing.T, ctx *gin.Context, logs, token string) {
	t.Helper()
	for _, key := range []string{"API_REQUEST", "API_RESPONSE"} {
		value, exists := ctx.Get(key)
		if !exists {
			t.Fatalf("missing %s log", key)
		}
		payload, ok := value.([]byte)
		if !ok || bytes.Contains(payload, []byte(token)) {
			t.Fatalf("%s exposed auth token or had an unexpected type", key)
		}
		if key == "API_REQUEST" && !bytes.Contains(payload, []byte("[REDACTED]")) {
			t.Fatal("custom auth request header was not redacted before logging")
		}
	}
	if strings.Contains(logs, token) {
		t.Fatal("response close logging exposed auth token")
	}
}

type authRequestErrorBody struct {
	io.Reader
	readErr  error
	closeErr error
}

func (b *authRequestErrorBody) Read(payload []byte) (int, error) {
	if b.readErr != nil {
		return 0, b.readErr
	}
	return b.Reader.Read(payload)
}

func (b *authRequestErrorBody) Close() error { return b.closeErr }
