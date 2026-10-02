package auth

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/access"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
)

func TestCredentialAccessRefreshRejectsBeforeUseAndReuse(t *testing.T) {
	for _, failedToken := range []string{"", "outdated"} {
		t.Run(failedToken, func(t *testing.T) {
			m, scope, base := accessExecutionFixture(t)
			exec := &accessRefreshExecutor{accessTestExecutor: base, scope: scope}
			m.RegisterExecutor(exec)
			for _, id := range []string{"allowed", "blocked"} {
				a, _ := m.GetByID(id)
				a.Metadata = map[string]any{"access_token": "current", "refresh_token": "refresh"}
				if _, err := m.Update(context.Background(), a); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := m.RefreshAuthForRequest(context.Background(), "blocked", failedToken); !isCredentialAccessError(err) {
				t.Fatalf("blocked refresh/reuse error=%v", err)
			}
			scope.denied = errors.New("revoked")
			if _, err := m.ForceRefreshAuth(context.Background(), "allowed"); !isCredentialAccessError(err) {
				t.Fatalf("revoked refresh error=%v", err)
			}
			if exec.refreshes != 0 {
				t.Fatalf("unauthorized refreshes=%d", exec.refreshes)
			}
			assertAccessNoFailureState(t, m)
		})
	}
}

func TestCredentialAccessRevokedOn401NeverRefreshesOrCoolsDown(t *testing.T) {
	for _, kind := range []string{"execute", "count", "stream", "bootstrap"} {
		t.Run(kind, func(t *testing.T) {
			m, scope, base := accessExecutionFixture(t)
			a, _ := m.GetByID("allowed")
			a.Metadata = map[string]any{"access_token": "expired", "refresh_token": "refresh"}
			if _, err := m.Update(context.Background(), a); err != nil {
				t.Fatal(err)
			}
			base.upstreamErr = &Error{HTTPStatus: http.StatusUnauthorized}
			base.beforeReturn = func() { scope.denied = errors.New("revoked before refresh") }
			exec := &accessRefreshExecutor{accessTestExecutor: base, scope: scope}
			if kind == "bootstrap" {
				m.RegisterExecutor(&accessRevokingBootstrapExecutor{accessRefreshExecutor: exec})
			} else {
				m.RegisterExecutor(exec)
			}
			if err := runAccessExecution(m, kind, cliproxyexecutor.Options{}); !isCredentialAccessError(err) {
				t.Fatalf("error=%v", err)
			}
			if exec.refreshes != 0 || base.calls != 1 {
				t.Fatalf("refreshes=%d executions=%d", exec.refreshes, base.calls)
			}
			assertAccessNoFailureState(t, m)
		})
	}
}

type accessRevokingBootstrapExecutor struct{ *accessRefreshExecutor }

func (e *accessRevokingBootstrapExecutor) ExecuteStream(context.Context, *Auth, cliproxyexecutor.Request, cliproxyexecutor.Options) (*cliproxyexecutor.StreamResult, error) {
	e.calls++
	e.beforeReturn()
	chunks := make(chan cliproxyexecutor.StreamChunk, 1)
	chunks <- cliproxyexecutor.StreamChunk{Err: e.upstreamErr}
	close(chunks)
	return &cliproxyexecutor.StreamResult{Chunks: chunks}, nil
}

func TestCredentialAccessAttemptCannotChangeTrustedIdentity(t *testing.T) {
	m, _ := newAccessTestManager(t)
	contexts := []context.Context{
		access.WithAuthenticatedPrincipal(context.Background(), "config", "token-a"),
		access.WithInternalOperation(context.Background(), access.InternalMaintenance),
	}
	for _, original := range contexts {
		ctx, err := m.beginCredentialAccess(original)
		if err != nil {
			t.Fatal(err)
		}
		changed := access.WithAuthenticatedPrincipal(ctx, "config", "token-b")
		if err = m.AuthorizeCredentialUse(changed, &Auth{ID: "allowed"}); !isCredentialAccessError(err) {
			t.Fatalf("inherited a different identity's scope: %v", err)
		}
		if _, err = m.AccessibleAuths(changed); !isCredentialAccessError(err) {
			t.Fatalf("catalog inherited a different identity's scope: %v", err)
		}
	}
}

func TestCredentialAccessExecutorFailureDoesNotMutateCredentials(t *testing.T) {
	for _, kind := range []string{"execute", "count", "stream", "bootstrap"} {
		t.Run(kind, func(t *testing.T) {
			m, scope, base := accessExecutionFixture(t)
			base.upstreamErr = credentialAccessFailure(errors.New("callback denied"))
			m.RegisterExecutor(&accessRefreshExecutor{accessTestExecutor: base, scope: scope, bootstrap: kind == "bootstrap"})
			if err := runAccessExecution(m, kind, cliproxyexecutor.Options{}); !isCredentialAccessError(err) {
				t.Fatalf("error=%v", err)
			}
			if base.calls != 1 {
				t.Fatalf("executions=%d", base.calls)
			}
			assertAccessNoFailureState(t, m)
		})
	}
}

func TestCredentialAccessStreamChunkFailureDoesNotMutateCredentials(t *testing.T) {
	m, _, _ := accessExecutionFixture(t)
	a, _ := m.GetByID("allowed")
	chunks := make(chan cliproxyexecutor.StreamChunk, 1)
	denied := credentialAccessFailure(errors.New("callback denied during stream"))
	chunks <- cliproxyexecutor.StreamChunk{Err: denied}
	close(chunks)
	stream := m.wrapStreamResult(context.Background(), a, "test", "policy-test-model", "policy-test-model", nil, nil, chunks, OAuthModelAliasResult{}, false, cliproxyexecutor.Options{})
	var observed error
	for chunk := range stream.Chunks {
		observed = chunk.Err
	}
	if !errors.Is(observed, denied) {
		t.Fatalf("chunk error=%v", observed)
	}
	assertAccessNoFailureState(t, m)
}
