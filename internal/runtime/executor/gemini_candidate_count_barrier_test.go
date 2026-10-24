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
	CountTokens(context.Context, *cliproxyauth.Auth, cliproxyexecutor.Request, cliproxyexecutor.Options) (cliproxyexecutor.Response, error)
}

func candidateCountConfig(mode, path string) *config.Config {
	cfg := &config.Config{}
	switch mode {
	case "override":
		cfg.Payload.Override = []config.PayloadRule{{
			Models: []config.PayloadModelRule{{Name: "*"}},
			Params: map[string]any{path: 2},
		}}
	case "filter":
		cfg.Payload.Filter = []config.PayloadFilterRule{{
			Models: []config.PayloadModelRule{{Name: "*"}}, Params: []string{path},
		}}
	}
	return cfg
}

func assertCandidateCount(t *testing.T, wire []byte, path, mode string, countTokens bool) {
	t.Helper()
	value := gjson.GetBytes(wire, path)
	if mode == "filter" || (mode == "default" && countTokens) {
		if value.Exists() {
			t.Fatalf("outbound %s was restored after removal; body=%s", path, wire)
		}
		return
	}
	want := int64(1)
	if mode == "override" {
		want = 2
	}
	if !value.Exists() || value.Int() != want {
		t.Fatalf("outbound %s = %s, want %d; body=%s", path, value.Raw, want, wire)
	}
}

func TestGeminiCandidateCountBeforePayloadRules(t *testing.T) {
	for _, provider := range []string{"gemini", "vertex-key", "vertex-service-account"} {
		for _, interactions := range []bool{false, true} {
			for _, action := range []string{"execute", "stream", "count-tokens"} {
				if interactions && action == "count-tokens" {
					continue
				}
				for _, mode := range []string{"default", "override", "filter"} {
					name := fmt.Sprintf("%s/interactions=%t/%s/%s", provider, interactions, action, mode)
					t.Run(name, func(t *testing.T) {
						path := "generationConfig.candidateCount"
						if interactions {
							path = "generation_config.candidate_count"
						}
						cfg := candidateCountConfig(mode, path)
						var executor candidateCountExecutor = NewGeminiExecutor(cfg)
						if provider != "gemini" {
							executor = NewGeminiVertexExecutor(cfg)
						} else if interactions {
							executor = NewGeminiInteractionsExecutor(cfg)
						}
						auth := candidateCountAuth(t, provider, interactions)
						wire := captureCandidateCountRequest(t, executor, auth, interactions, action)
						assertCandidateCount(t, wire, path, mode, action == "count-tokens")
					})
				}
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
	if provider == "gemini" && interactions {
		auth.Provider = "gemini-interactions"
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

func captureCandidateCountRequest(t *testing.T, executor candidateCountExecutor, auth *cliproxyauth.Auth, interactions bool, action string) []byte {
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
	req := cliproxyexecutor.Request{Model: "gemini-3.1-pro-preview", Payload: []byte(`{"contents":[{"role":"user","parts":[{"text":"hi"}]}],"generationConfig":{"candidateCount":2}}`)}
	opts := cliproxyexecutor.Options{SourceFormat: sdktranslator.FormatGemini}
	if interactions {
		req.Payload = []byte(`{"model":"gemini-3.1-pro-preview","input":"hi","generation_config":{"candidate_count":2}}`)
		opts.SourceFormat = sdktranslator.FormatInteractions
	}
	var errExecute error
	switch action {
	case "stream":
		_, errExecute = executor.ExecuteStream(ctx, auth, req, opts)
	case "count-tokens":
		_, errExecute = executor.CountTokens(ctx, auth, req, opts)
	default:
		_, errExecute = executor.Execute(ctx, auth, req, opts)
	}
	if !errors.Is(errExecute, stop) {
		t.Fatalf("execution did not reach capture transport: %v", errExecute)
	}
	return wire
}

func TestAIStudioCandidateCountBeforePayloadRules(t *testing.T) {
	for _, mode := range []string{"default", "override", "filter"} {
		for _, action := range []string{"execute", "stream", "countTokens"} {
			t.Run(mode+"/"+action, func(t *testing.T) {
				executor := NewAIStudioExecutor(candidateCountConfig(mode, "generationConfig.candidateCount"), "aistudio", nil)
				body, translated, errTranslate := executor.translateRequest(context.Background(), cliproxyexecutor.Request{
					Model:    "gemini-3.1-pro-preview",
					Payload:  []byte(`{"contents":[{"role":"user","parts":[{"text":"hi"}]}],"generationConfig":{"candidateCount":2}}`),
					Metadata: map[string]any{"action": action},
				}, cliproxyexecutor.Options{SourceFormat: sdktranslator.FormatGemini}, action == "stream")
				if errTranslate != nil {
					t.Fatal(errTranslate)
				}
				for _, payload := range [][]byte{body, translated.payload} {
					assertCandidateCount(t, payload, "generationConfig.candidateCount", mode, action == "countTokens")
				}
			})
		}
	}
}

func TestAntigravityCandidateCountBeforePayloadFinalizer(t *testing.T) {
	for _, mode := range []string{"default", "override", "filter"} {
		for _, schema := range []bool{false, true} {
			for _, stream := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/schema=%t/stream=%t", mode, schema, stream), func(t *testing.T) {
					cfg := candidateCountConfig(mode, "generationConfig.candidateCount")
					req := cliproxyexecutor.Request{Model: "gemini-3.1-pro-preview"}
					body := []byte(`{"request":{"contents":[{"role":"user","parts":[{"text":"hi"}]}],"generationConfig":{"candidateCount":2}}}`)
					if schema {
						body = []byte(`{"request":{"contents":[{"role":"user","parts":[{"text":"hi"}]}],"generationConfig":{"candidateCount":2},"tools":[{"functionDeclarations":[{"name":"test","parameters":{"type":"object","properties":{"value":{"type":"string"}}}}]}]}}`)
					}
					ctx := helps.WithPayloadFinalizer(context.Background(), helps.NewPayloadFinalizer(cfg, "antigravity", req.Model, "antigravity", "request", body, req, cliproxyexecutor.Options{SourceFormat: sdktranslator.FormatGemini}))
					auth := &cliproxyauth.Auth{Metadata: map[string]any{"project_id": "candidate-count-test"}}
					for attempt := 0; attempt < 2; attempt++ {
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
						assertCandidateCount(t, wire, "request.generationConfig.candidateCount", mode, false)
					}
				})
			}
		}
	}
}
