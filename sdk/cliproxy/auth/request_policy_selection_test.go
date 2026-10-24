package auth

import (
	"context"
	"errors"
	"net/http"
	"testing"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/access"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

type accessPolicyFunc func(context.Context) (CredentialAccessScope, error)

func (f accessPolicyFunc) BeginAttempt(ctx context.Context) (CredentialAccessScope, error) {
	return f(ctx)
}

func TestCredentialAccessRequiresTrustedIdentity(t *testing.T) {
	m, scope := newAccessTestManager(t)
	m.SetCredentialAccessPolicy(accessPolicyFunc(func(ctx context.Context) (CredentialAccessScope, error) {
		if _, ok := access.AuthenticatedPrincipalFromContext(ctx); !ok {
			return nil, &Error{HTTPStatus: http.StatusUnauthorized, Message: "missing identity"}
		}
		return scope, nil
	}))
	opts := cliproxyexecutor.Options{Metadata: map[string]any{"principal": "forged", "group_id": "all"}}
	for _, ctx := range []context.Context{nil, context.Background()} {
		if _, err := m.SelectAuth(ctx, "test", "", opts); statusCodeFromError(err) != http.StatusUnauthorized {
			t.Fatalf("anonymous request error=%v", err)
		}
	}
	ctx := access.WithAuthenticatedPrincipal(context.Background(), "config", "verified")
	if _, err := m.SelectAuth(ctx, "test", "", opts); err != nil {
		t.Fatal(err)
	}
}

func TestCredentialAccessPluginCandidatesAndDelegates(t *testing.T) {
	for _, mixed := range []bool{false, true} {
		for _, delegate := range []string{"", pluginapi.SchedulerBuiltinRoundRobin, pluginapi.SchedulerBuiltinFillFirst} {
			t.Run(delegate+map[bool]string{true: "-mixed", false: "-single"}[mixed], func(t *testing.T) {
				m, _ := newAccessTestManager(t)
				plugin := &fakePluginScheduler{acrossPriorities: true, pick: func(_ context.Context, req pluginapi.SchedulerPickRequest) (pluginapi.SchedulerPickResponse, bool, error) {
					if len(req.Candidates) != 1 || req.Candidates[0].ID != "allowed" {
						t.Fatalf("plugin candidates=%v", req.Candidates)
					}
					return pluginapi.SchedulerPickResponse{Handled: true, AuthID: "blocked", DelegateBuiltin: delegate}, true, nil
				}}
				m.SetPluginScheduler(plugin)
				var selected *Auth
				var err error
				if mixed {
					selected, _, _, err = m.pickNextMixed(context.Background(), []string{"test"}, "", cliproxyexecutor.Options{}, nil)
				} else {
					selected, _, err = m.pickNext(context.Background(), "test", "", cliproxyexecutor.Options{}, nil)
				}
				if err != nil || selected == nil || selected.ID != "allowed" {
					t.Fatalf("selected=%v error=%v", selected, err)
				}
			})
		}
	}
}

func TestCredentialAccessPinnedAndExhaustedNeverFallback(t *testing.T) {
	m, _ := newAccessTestManager(t)
	for _, opts := range []cliproxyexecutor.Options{{Metadata: map[string]any{cliproxyexecutor.PinnedAuthMetadataKey: "blocked"}}, {}} {
		selected, _, err := m.pickNext(context.Background(), "test", "", opts, map[string]struct{}{"allowed": {}})
		if err == nil || selected != nil {
			t.Fatalf("selected=%v error=%v", selected, err)
		}
	}
}

func TestCredentialAccessPolicyReplacementRejectsOldAttempt(t *testing.T) {
	m, scope := newAccessTestManager(t)
	ctx, err := m.beginCredentialAccess(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	m.SetCredentialAccessPolicy(&accessTestPolicy{scope: scope})
	if err = m.AuthorizeCredentialUse(ctx, &Auth{ID: "allowed"}); !isCredentialAccessError(err) {
		t.Fatalf("error=%v", err)
	}
	if _, err = m.AccessibleAuths(ctx); !isCredentialAccessError(err) {
		t.Fatalf("error=%v", err)
	}
	m.SetCredentialAccessPolicy(nil)
	all, err := m.AccessibleAuths(ctx)
	if err != nil || len(all) != 2 {
		t.Fatalf("disabled policy auths=%v error=%v", all, err)
	}
}

func TestCredentialAccessHomeCombinationDeniedBeforeDispatch(t *testing.T) {
	m, _ := newAccessTestManager(t)
	m.SetConfig(&internalconfig.Config{Home: internalconfig.HomeConfig{Enabled: true}})
	if _, err := m.SelectHomeAuthByKind(context.Background(), "test", "", AuthKindOAuth, cliproxyexecutor.Options{}); statusCodeFromError(err) != http.StatusServiceUnavailable {
		t.Fatalf("error=%v", err)
	}
	if _, err := m.SelectHomeAuthWithCredentialPolicy(context.Background(), "test", "", CredentialPolicyCodexAlphaSearchV1, cliproxyexecutor.Options{}); statusCodeFromError(err) != http.StatusServiceUnavailable {
		t.Fatalf("error=%v", err)
	}
	for _, kind := range []string{"execute", "count", "stream"} {
		if err := runAccessExecution(m, kind, cliproxyexecutor.Options{}); statusCodeFromError(err) != http.StatusServiceUnavailable {
			t.Fatalf("%s error=%v", kind, err)
		}
	}
}

type accessEscapingSelector struct{}

func (accessEscapingSelector) Pick(context.Context, string, string, cliproxyexecutor.Options, []*Auth) (*Auth, error) {
	return &Auth{ID: "blocked", Provider: "test"}, nil
}

func TestCredentialAccessRejectsSelectorEscape(t *testing.T) {
	m, _ := newAccessTestManager(t)
	m.SetSelector(accessEscapingSelector{})
	if _, err := m.SelectAuth(context.Background(), "test", "", cliproxyexecutor.Options{}); !isCredentialAccessError(err) {
		t.Fatalf("error=%v", err)
	}
}

func TestCredentialAccessErrorCannotBeReplacedOrRetried(t *testing.T) {
	m, _ := newAccessTestManager(t)
	cause := errors.New("policy revoked")
	denied := credentialAccessFailure(cause)
	upstream := &Error{HTTPStatus: http.StatusTooManyRequests}
	if got := preferredExecutionAttemptError(denied, upstream); !errors.Is(got, cause) {
		t.Fatalf("error=%v", got)
	}
	if shouldReturnLastErrorOnPickFailure(false, upstream, denied) {
		t.Fatal("authorization error replaced by upstream error")
	}
	if _, retry := m.shouldRetryAfterErrorWithAttempted(context.Background(), cliproxyexecutor.Options{}, denied, 0, []string{"test"}, "", 0, -1, 3, nil); retry {
		t.Fatal("authorization error retried")
	}
	if shouldAttemptAntigravityCreditsFallback(m, denied, []string{"antigravity"}) {
		t.Fatal("authorization error triggers credits fallback")
	}
}
