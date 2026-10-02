package auth

import (
	"context"
	"errors"
	"net/http"
	"testing"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

type accessRefreshExecutor struct {
	*accessTestExecutor
	scope     *accessTestScope
	refreshes int
	bootstrap bool
}

func (e *accessRefreshExecutor) Refresh(_ context.Context, a *Auth) (*Auth, error) {
	e.refreshes++
	e.scope.denied = errors.New("permission changed during refresh")
	a.Metadata["access_token"] = "fresh"
	return a, nil
}

func (e *accessRefreshExecutor) ExecuteStream(ctx context.Context, a *Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (*cliproxyexecutor.StreamResult, error) {
	if !e.bootstrap {
		return e.accessTestExecutor.ExecuteStream(ctx, a, req, opts)
	}
	e.calls++
	chunks := make(chan cliproxyexecutor.StreamChunk, 1)
	chunks <- cliproxyexecutor.StreamChunk{Err: e.upstreamErr}
	close(chunks)
	return &cliproxyexecutor.StreamResult{Chunks: chunks}, nil
}

func TestCredentialAccessChecksAfterRefresh(t *testing.T) {
	for _, kind := range []string{"execute", "count", "stream", "bootstrap"} {
		t.Run(kind, func(t *testing.T) {
			m, scope, base := accessExecutionFixture(t)
			a, _ := m.GetByID("allowed")
			a.Metadata = map[string]any{"access_token": "expired", "refresh_token": "refresh"}
			if _, err := m.Update(context.Background(), a); err != nil {
				t.Fatal(err)
			}
			base.upstreamErr = &Error{HTTPStatus: http.StatusUnauthorized, Message: "expired"}
			executor := &accessRefreshExecutor{accessTestExecutor: base, scope: scope, bootstrap: kind == "bootstrap"}
			m.RegisterExecutor(executor)
			err := runAccessExecution(m, kind, cliproxyexecutor.Options{})
			if !isCredentialAccessError(err) || base.calls != 1 || executor.refreshes != 1 {
				t.Fatalf("error=%v executions=%d refreshes=%d", err, base.calls, executor.refreshes)
			}
			assertAccessNoFailureState(t, m)
		})
	}
}

func TestCredentialAccessChecksNextCredentialAfterUpstreamFailure(t *testing.T) {
	m, _, executor := accessExecutionFixture(t)
	executor.upstreamErr = &Error{HTTPStatus: http.StatusBadGateway, Message: "upstream failed"}
	executor.beforeReturn = func() { m.SetCredentialAccessPolicy(&accessTestPolicy{err: errors.New("identity revoked")}) }
	err := runAccessExecution(m, "execute", cliproxyexecutor.Options{})
	if !isCredentialAccessError(err) || executor.calls != 1 {
		t.Fatalf("error=%v calls=%d", err, executor.calls)
	}
	blocked, _ := m.GetByID("blocked")
	if blocked.LastError != nil || len(blocked.ModelStates) != 0 {
		t.Fatal("unauthorized fallback was attempted")
	}
}

func TestCredentialAccessPrepareAuthRejectsBeforeMinting(t *testing.T) {
	m, scope := newAccessTestManager(t)
	preparer := &requestPrepareExecutor{}
	scope.denied = errors.New("revoked")
	a, _ := m.GetByID("allowed")
	if _, err := m.PrepareRequestAuth(context.Background(), preparer, a); !errors.Is(err, scope.denied) {
		t.Fatalf("error=%v", err)
	}
	if preparer.prepareCalls.Load() != 0 {
		t.Fatal("unauthorized credential minted")
	}
	assertAccessNoFailureState(t, m)
}

func TestCredentialAccessFailedAllowedCredentialDoesNotUseBlockedFallback(t *testing.T) {
	for _, kind := range []string{"execute", "count", "stream"} {
		t.Run(kind, func(t *testing.T) {
			m, _, executor := accessExecutionFixture(t)
			executor.upstreamErr = &Error{HTTPStatus: http.StatusTooManyRequests, Message: "quota"}
			if err := runAccessExecution(m, kind, cliproxyexecutor.Options{}); err == nil {
				t.Fatal("expected upstream failure")
			}
			if executor.calls != 1 {
				t.Fatalf("executions=%d", executor.calls)
			}
			blocked, _ := m.GetByID("blocked")
			if blocked.LastError != nil || len(blocked.ModelStates) != 0 {
				t.Fatal("blocked credential mutated")
			}
		})
	}
}
