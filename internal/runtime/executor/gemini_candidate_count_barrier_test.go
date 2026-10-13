package executor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/runtime/executor/helps"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v8/sdk/translator"
	"github.com/tidwall/gjson"
)

type candidateCountExecutor interface {
	Execute(context.Context, *cliproxyauth.Auth, cliproxyexecutor.Request, cliproxyexecutor.Options) (cliproxyexecutor.Response, error)
	ExecuteStream(context.Context, *cliproxyauth.Auth, cliproxyexecutor.Request, cliproxyexecutor.Options) (*cliproxyexecutor.StreamResult, error)
}

func candidateCountOverride(path string) *config.Config {
	return &config.Config{Payload: config.PayloadConfig{Override: []config.PayloadRule{{
		Models: []config.PayloadModelRule{{Name: "*"}},
		Params: map[string]any{path: 2},
	}}}}
}

func TestGeminiCandidateCountAfterPayloadOverride(t *testing.T) {
	for _, provider := range []string{"gemini", "vertex-key", "vertex-service-account"} {
		for _, interactions := range []bool{false, true} {
			for _, stream := range []bool{false, true} {
				name := fmt.Sprintf("%s/interactions=%t/stream=%t", provider, interactions, stream)
				t.Run(name, func(t *testing.T) {
					path := "generationConfig.candidateCount"
					if interactions {
						path = "generation_config.candidate_count"
					}
					cfg := candidateCountOverride(path)
					var executor candidateCountExecutor = NewGeminiExecutor(cfg)
					if provider != "gemini" {
						executor = NewGeminiVertexExecutor(cfg)
					}
					auth := candidateCountAuth(t, provider, interactions)
					wire := captureCandidateCountRequest(t, executor, auth, interactions, stream)
					if got := gjson.GetBytes(wire, path).Int(); got != 1 {
						t.Fatalf("outbound %s = %d, want 1 after override; body=%s", path, got, wire)
					}
				})
			}
		}
	}
}

func candidateCountAuth(t *testing.T, provider string, interactions bool) *cliproxyauth.Auth {
	t.Helper()
	auth := &cliproxyauth.Auth{
		ID:       "candidate-count-" + provider,
		Provider: provider,
		Attributes: map[string]string{
			"api_key": "test-key", "base_url": "https://candidate-count.invalid",
		},
		Metadata: map[string]any{"interactions": interactions},
	}
	if provider != "vertex-service-account" {
		return auth
	}
	auth.Provider = "vertex"
	auth.Attributes = nil
	var serviceAccount map[string]any
	if errUnmarshal := json.Unmarshal(testVertexServiceAccountJSON(t, "https://candidate-count.invalid/token"), &serviceAccount); errUnmarshal != nil {
		t.Fatal(errUnmarshal)
	}
	auth.Metadata["service_account"] = serviceAccount
	auth.Metadata["project_id"] = "candidate-count-test"
	auth.Metadata["location"] = "global"
	return auth
}

func captureCandidateCountRequest(t *testing.T, executor candidateCountExecutor, auth *cliproxyauth.Auth, interactions, stream bool) []byte {
	t.Helper()
	var wire []byte
	stop := errors.New("captured outbound candidate-count request")
	transport := roundTripperFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.Path == "/token" {
			return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(`{"access_token":"candidate-count-token","token_type":"Bearer","expires_in":3600}`))}, nil
		}
		var errRead error
		wire, errRead = io.ReadAll(request.Body)
		if errRead != nil {
			return nil, errRead
		}
		return nil, stop
	})
	ctx := context.WithValue(context.Background(), "cliproxy.roundtripper", transport)
	req := cliproxyexecutor.Request{Model: "gemini-3.1-pro-preview", Payload: []byte(`{"contents":[{"role":"user","parts":[{"text":"hi"}]}]}`)}
	opts := cliproxyexecutor.Options{SourceFormat: sdktranslator.FormatGemini}
	if interactions {
		req.Payload = []byte(`{"model":"gemini-3.1-pro-preview","input":"hi"}`)
		opts.SourceFormat = sdktranslator.FormatInteractions
	}
	var errExecute error
	if stream {
		_, errExecute = executor.ExecuteStream(ctx, auth, req, opts)
	} else {
		_, errExecute = executor.Execute(ctx, auth, req, opts)
	}
	if !errors.Is(errExecute, stop) {
		t.Fatalf("execution did not reach capture transport: %v", errExecute)
	}
	return wire
}

func TestAIStudioCandidateCountAfterPayloadOverride(t *testing.T) {
	executor := NewAIStudioExecutor(candidateCountOverride("generationConfig.candidateCount"), "aistudio", nil)
	for _, stream := range []bool{false, true} {
		body, translated, errTranslate := executor.translateRequest(context.Background(), cliproxyexecutor.Request{
			Model: "gemini-3.1-pro-preview", Payload: []byte(`{"contents":[{"role":"user","parts":[{"text":"hi"}]}]}`),
		}, cliproxyexecutor.Options{SourceFormat: sdktranslator.FormatGemini}, stream)
		if errTranslate != nil {
			t.Fatal(errTranslate)
		}
		for _, payload := range [][]byte{body, translated.payload} {
			if got := gjson.GetBytes(payload, "generationConfig.candidateCount").Int(); got != 1 {
				t.Fatalf("candidate count = %d, want 1 after override; body=%s", got, payload)
			}
		}
	}
}

func TestAntigravityCandidateCountAfterPayloadFinalizer(t *testing.T) {
	for _, schema := range []bool{false, true} {
		for _, stream := range []bool{false, true} {
			t.Run(fmt.Sprintf("schema=%t/stream=%t", schema, stream), func(t *testing.T) {
				cfg := candidateCountOverride("generationConfig.candidateCount")
				req := cliproxyexecutor.Request{Model: "gemini-3.1-pro-preview"}
				body := []byte(`{"contents":[{"role":"user","parts":[{"text":"hi"}]}]}`)
				if schema {
					body = []byte(`{"contents":[{"role":"user","parts":[{"text":"hi"}]}],"tools":[{"functionDeclarations":[{"name":"test","parameters":{"type":"object","properties":{"value":{"type":"string"}}}}]}]}`)
				}
				ctx := helps.WithPayloadFinalizer(context.Background(), helps.NewPayloadFinalizer(cfg, "antigravity", req.Model, "antigravity", "request", body, req, cliproxyexecutor.Options{SourceFormat: sdktranslator.FormatGemini}))
				auth := &cliproxyauth.Auth{Metadata: map[string]any{"project_id": "candidate-count-test"}}
				request, errBuild := NewAntigravityExecutor(cfg).buildRequest(ctx, auth, "token", req.Model, body, stream, "", "https://candidate-count.invalid")
				if errBuild != nil {
					t.Fatal(errBuild)
				}
				wire, errRead := io.ReadAll(request.Body)
				if errRead != nil {
					t.Fatal(errRead)
				}
				if errClose := request.Body.Close(); errClose != nil {
					t.Fatal(errClose)
				}
				if got := gjson.GetBytes(wire, "request.generationConfig.candidateCount").Int(); got != 1 {
					t.Fatalf("candidate count = %d, want 1 after finalizer; body=%s", got, wire)
				}
			})
		}
	}
}
