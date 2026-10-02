package auth

import (
	"context"
	"errors"
	"net/http"
	"testing"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
)

type accessTestPolicy struct {
	scope CredentialAccessScope
	err   error
	calls int
}

func (p *accessTestPolicy) BeginAttempt(context.Context) (CredentialAccessScope, error) {
	p.calls++
	return p.scope, p.err
}

type accessTestScope struct {
	allowed string
	denied  error
	uses    int
}

func (s *accessTestScope) Allows(a *Auth) bool {
	return a != nil && a.ID == s.allowed
}

func (s *accessTestScope) AuthorizeUse(_ context.Context, a *Auth) error {
	s.uses++
	if s.denied != nil {
		return s.denied
	}
	if !s.Allows(a) {
		return errors.New("not allowed")
	}
	return nil
}

func newAccessTestManager(t *testing.T) (*Manager, *accessTestScope) {
	t.Helper()
	m := NewManager(nil, &FillFirstSelector{}, nil)
	m.RegisterExecutor(schedulerTestExecutor{provider: "test"})
	for _, id := range []string{"blocked", "allowed"} {
		if _, err := m.Register(context.Background(), &Auth{ID: id, Provider: "test"}); err != nil {
			t.Fatal(err)
		}
	}
	scope := &accessTestScope{allowed: "allowed"}
	m.SetCredentialAccessPolicy(&accessTestPolicy{scope: scope})
	return m, scope
}

func TestCredentialAccessSelectionFiltersEveryPath(t *testing.T) {
	for _, path := range []string{"legacy", "fast", "mixed-legacy", "mixed-fast"} {
		t.Run(path, func(t *testing.T) {
			m, _ := newAccessTestManager(t)
			var selected *Auth
			var err error
			switch path {
			case "legacy":
				selected, _, err = m.pickNextLegacy(context.Background(), "test", "", cliproxyexecutor.Options{}, nil)
			case "fast":
				selected, _, err = m.pickNext(context.Background(), "test", "", cliproxyexecutor.Options{}, nil)
			case "mixed-legacy":
				selected, _, _, err = m.pickNextMixedLegacy(context.Background(), []string{"test"}, "", cliproxyexecutor.Options{}, nil)
			case "mixed-fast":
				selected, _, _, err = m.pickNextMixed(context.Background(), []string{"test"}, "", cliproxyexecutor.Options{}, nil)
			}
			if err != nil || selected == nil || selected.ID != "allowed" {
				t.Fatalf("selected=%v error=%v", selected, err)
			}
		})
	}
}

func TestCredentialAccessNilScopeFailsClosed(t *testing.T) {
	m, _ := newAccessTestManager(t)
	m.SetCredentialAccessPolicy(&accessTestPolicy{})
	if _, err := m.SelectAuth(context.Background(), "test", "", cliproxyexecutor.Options{}); err == nil {
		t.Fatal("nil scope accepted")
	}
}

func TestCredentialAccessHelpers(t *testing.T) {
	m, scope := newAccessTestManager(t)
	allowed, err := m.AccessibleAuths(context.Background())
	if err != nil || len(allowed) != 1 || allowed[0].ID != "allowed" {
		t.Fatalf("auths=%v error=%v", allowed, err)
	}
	denied := &Error{Code: "policy_changed", HTTPStatus: http.StatusForbidden}
	scope.denied = denied
	if err = m.AuthorizeCredentialUse(context.Background(), allowed[0]); !errors.Is(err, denied) {
		t.Fatalf("error=%v", err)
	}
	m.SetCredentialAccessPolicy(nil)
	if err = m.AuthorizeCredentialUse(nil, nil); err != nil {
		t.Fatal(err)
	}
}
