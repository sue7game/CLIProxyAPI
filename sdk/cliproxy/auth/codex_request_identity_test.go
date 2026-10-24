package auth

import (
	"context"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

func TestStreamResultPreservesClientIdentityAfterGinContextReuse(t *testing.T) {
	for _, codexClient := range []bool{false, true} {
		name := map[bool]string{false: "siwc-client", true: "codex-client"}[codexClient]
		t.Run(name, func(t *testing.T) {
			hook := &resultCaptureHook{}
			manager := NewManager(nil, nil, hook)
			ginCtx, _ := gin.CreateTestContext(httptest.NewRecorder())
			ginCtx.Request = httptest.NewRequest("POST", "/v1/responses", nil)
			if codexClient {
				ginCtx.Request.Header.Set("User-Agent", "codex-desktop")
			}
			ctx := context.WithValue(context.Background(), "gin", ginCtx)
			auth := &Auth{ID: "identity-snapshot", Provider: "codex", Metadata: map[string]any{
				"use_siwc": true, "access_token": "outer-token",
				"siwc": map[string]any{"access_token": "siwc-token"},
			}}
			remaining := make(chan cliproxyexecutor.StreamChunk)
			result := manager.wrapStreamResult(ctx, auth, "codex", "model", "model", nil, nil, remaining,
				OAuthModelAliasResult{}, true, cliproxyexecutor.Options{}, 1)
			ginCtx.Request = httptest.NewRequest("POST", "/v1/responses", nil)
			if !codexClient {
				ginCtx.Request.Header.Set("User-Agent", "codex-desktop")
			}
			close(remaining)
			for range result.Chunks {
			}
			results := hook.Results()
			want := map[bool]string{false: "siwc-token", true: "outer-token"}[codexClient]
			if len(results) != 1 || results[0].AccessToken != want {
				t.Fatalf("stream result lost its original token partition: results=%v", len(results))
			}
		})
	}
}
