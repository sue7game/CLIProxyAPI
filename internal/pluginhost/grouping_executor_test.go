package pluginhost

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/access"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	coreexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

func groupingExecutorFixture(t *testing.T) (*Host, *coreauth.Auth, *int) {
	t.Helper()
	calls := 0
	exec := &fakeExecutor{identifier: "demo"}
	exec.execute = func(context.Context, pluginapi.ExecutorRequest) (pluginapi.ExecutorResponse, error) {
		calls++
		return pluginapi.ExecutorResponse{Payload: []byte(`{}`)}, nil
	}
	exec.countTokens = exec.execute
	exec.executeStream = func(context.Context, pluginapi.ExecutorRequest) (pluginapi.ExecutorStreamResponse, error) {
		calls++
		chunks := make(chan pluginapi.ExecutorStreamChunk)
		close(chunks)
		return pluginapi.ExecutorStreamResponse{Chunks: chunks}, nil
	}
	exec.httpRequest = func(context.Context, pluginapi.ExecutorHTTPRequest) (pluginapi.ExecutorHTTPResponse, error) {
		calls++
		return pluginapi.ExecutorHTTPResponse{}, nil
	}
	host := newRouteModelHostWithRecords(capabilityRecord{id: "executor", plugin: pluginapi.Plugin{Capabilities: pluginapi.Capabilities{
		Executor: exec, ExecutorInputFormats: []string{"openai"}, ExecutorOutputFormats: []string{"openai"},
	}}})
	other, auth, _, _, _ := groupingCallbackFixture(t)
	host.SetAuthManager(other.currentAuthManager())
	return host, auth, &calls
}

func TestGroupingDirectPluginExecutionRejectsUnboundAndBlockedAuth(t *testing.T) {
	for _, method := range []string{"execute", "count", "stream", "http", "refresh"} {
		t.Run(method, func(t *testing.T) {
			host, auth, calls := groupingExecutorFixture(t)
			adapter, err := host.executorAdapterForPlugin("executor")
			if err != nil {
				t.Fatal(err)
			}
			ctx := access.WithAuthenticatedPrincipal(context.Background(), "config", "verified")
			for _, candidate := range []*coreauth.Auth{nil, {ID: "blocked", Provider: "demo"}, auth} {
				err = executeGroupingTestAdapter(t, ctx, adapter, candidate, method)
				if candidate != auth && !coreauth.IsCredentialAccessError(err) {
					t.Fatalf("unverified auth reached %s: %v", method, err)
				}
				if candidate == auth && err != nil {
					t.Fatalf("ordinary authorized auth rejected: %v", err)
				}
			}
			want := 1
			if method == "refresh" {
				want = 0
			}
			if *calls != want {
				t.Fatalf("executor calls=%d want=%d", *calls, want)
			}
			host.currentAuthManager().SetCredentialAccessPolicy(nil)
			if err := executeGroupingTestAdapter(t, context.Background(), adapter, nil, method); err != nil {
				t.Fatalf("disabled grouping changed legacy behavior: %v", err)
			}
		})
	}
}

func executeGroupingTestAdapter(t *testing.T, ctx context.Context, adapter *executorAdapter, auth *coreauth.Auth, method string) error {
	t.Helper()
	req := coreexecutor.Request{Model: "model", Payload: []byte(`{}`)}
	options := coreexecutor.Options{}
	switch method {
	case "execute":
		_, err := adapter.Execute(ctx, auth, req, options)
		return err
	case "count":
		_, err := adapter.CountTokens(ctx, auth, req, options)
		return err
	case "stream":
		stream, err := adapter.ExecuteStream(ctx, auth, req, options)
		if stream != nil {
			for range stream.Chunks {
			}
		}
		return err
	case "refresh":
		_, err := adapter.Refresh(ctx, auth)
		return err
	default:
		httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://upstream.invalid/", nil)
		if err != nil {
			t.Fatal(err)
		}
		_, err = adapter.HttpRequest(ctx, auth, httpReq)
		return err
	}
}

func TestGroupingPluginStoragePayloadMustBeAnIndependentCredential(t *testing.T) {
	for _, shared := range []bool{false, true} {
		host, auth, _, _, _ := groupingCallbackFixture(t)
		id := uuid.NewString()
		auth.Attributes["grouping_id"] = id
		auth.Metadata = map[string]any{"type": "demo", "grouping_id": id, "api_key": "fixture"}
		raw, err := json.Marshal(auth.Metadata)
		if err != nil {
			t.Fatal(err)
		}
		if shared {
			raw = []byte(`{"accounts":[{"api_key":"other-group-fixture"}]}`)
		}
		auth.Storage = &pluginTokenStorage{provider: "demo", rawJSON: raw, meta: auth.Metadata}
		coreauth.MarkPluginVirtualAuth(auth, "fixture.json", 0)
		ctx := access.WithAuthenticatedPrincipal(context.Background(), "config", "verified")
		err = host.authorizePluginCredential(ctx, auth)
		if shared != (err != nil) {
			t.Fatalf("shared=%v error=%v", shared, err)
		}
	}
}
