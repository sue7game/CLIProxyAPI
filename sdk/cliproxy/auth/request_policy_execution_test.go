package auth

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/registry"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
)

type accessTestExecutor struct {
	schedulerTestExecutor
	calls        int
	beforeReturn func()
	upstreamErr  error
}

func (e *accessTestExecutor) Execute(context.Context, *Auth, cliproxyexecutor.Request, cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	e.calls++
	if e.beforeReturn != nil {
		e.beforeReturn()
	}
	return cliproxyexecutor.Response{}, e.upstreamErr
}

func (e *accessTestExecutor) CountTokens(ctx context.Context, a *Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	return e.Execute(ctx, a, req, opts)
}

func (e *accessTestExecutor) ExecuteStream(context.Context, *Auth, cliproxyexecutor.Request, cliproxyexecutor.Options) (*cliproxyexecutor.StreamResult, error) {
	e.calls++
	if e.beforeReturn != nil {
		e.beforeReturn()
	}
	if e.upstreamErr != nil {
		return nil, e.upstreamErr
	}
	chunks := make(chan cliproxyexecutor.StreamChunk, 1)
	chunks <- cliproxyexecutor.StreamChunk{Payload: []byte("data: ok\n\n")}
	close(chunks)
	return &cliproxyexecutor.StreamResult{Chunks: chunks}, nil
}

func (e *accessTestExecutor) PrepareRequest(*http.Request, *Auth) error {
	e.calls++
	return nil
}

func (e *accessTestExecutor) HttpRequest(context.Context, *Auth, *http.Request) (*http.Response, error) {
	e.calls++
	return &http.Response{StatusCode: http.StatusOK}, nil
}

func accessExecutionFixture(t *testing.T) (*Manager, *accessTestScope, *accessTestExecutor) {
	t.Helper()
	m, scope := newAccessTestManager(t)
	e := &accessTestExecutor{schedulerTestExecutor: schedulerTestExecutor{provider: "test"}}
	m.RegisterExecutor(e)
	for _, id := range []string{"allowed", "blocked"} {
		registry.GetGlobalRegistry().RegisterClient(id, "test", []*registry.ModelInfo{{ID: "policy-test-model"}})
		t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(id) })
	}
	return m, scope, e
}

func runAccessExecution(m *Manager, kind string, opts cliproxyexecutor.Options) error {
	req := cliproxyexecutor.Request{Model: "policy-test-model"}
	ctx := context.Background()
	switch kind {
	case "execute":
		_, err := m.Execute(ctx, []string{"test"}, req, opts)
		return err
	case "count":
		_, err := m.ExecuteCount(ctx, []string{"test"}, req, opts)
		return err
	default:
		result, err := m.ExecuteStream(ctx, []string{"test"}, req, opts)
		if result != nil {
			for range result.Chunks {
			}
		}
		return err
	}
}

func TestCredentialAccessChecksBeforeExecution(t *testing.T) {
	for _, kind := range []string{"execute", "count", "stream"} {
		t.Run(kind, func(t *testing.T) {
			m, scope, executor := accessExecutionFixture(t)
			denied := errors.New("permission revoked after selection")
			opts := cliproxyexecutor.Options{RequestAfterAuthInterceptor: func(context.Context, cliproxyexecutor.RequestAfterAuthInterceptRequest) cliproxyexecutor.RequestAfterAuthInterceptResponse {
				scope.denied = denied
				return cliproxyexecutor.RequestAfterAuthInterceptResponse{}
			}}
			err := runAccessExecution(m, kind, opts)
			if !errors.Is(err, denied) || executor.calls != 0 {
				t.Fatalf("error=%v calls=%d", err, executor.calls)
			}
			assertAccessNoFailureState(t, m)
		})
	}
}

func assertAccessNoFailureState(t *testing.T, m *Manager) {
	t.Helper()
	for _, a := range m.List() {
		if a.LastError != nil || a.Unavailable || len(a.ModelStates) != 0 {
			t.Fatalf("policy refusal mutated auth %s: %+v", a.ID, a)
		}
	}
}

func TestCredentialAccessDirectHTTP(t *testing.T) {
	for _, method := range []string{"inject", "prepare", "new", "http"} {
		t.Run(method, func(t *testing.T) {
			m, _, executor := accessExecutionFixture(t)
			a := &Auth{ID: "blocked", Provider: "test"}
			req, err := http.NewRequest(http.MethodGet, "https://example.invalid/", nil)
			if err != nil {
				t.Fatal(err)
			}
			switch method {
			case "inject":
				err = m.InjectCredentials(req, a.ID)
			case "prepare":
				err = m.PrepareHttpRequest(nil, a, req)
			case "new":
				_, err = m.NewHttpRequest(nil, a, http.MethodGet, "https://example.invalid/", nil, nil)
			case "http":
				_, err = m.HttpRequest(nil, a, req)
			}
			if err == nil || executor.calls != 0 {
				t.Fatalf("error=%v calls=%d", err, executor.calls)
			}
			assertAccessNoFailureState(t, m)
		})
	}
}
