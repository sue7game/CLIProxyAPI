package auth

import (
	"context"
	"errors"
	"net/http"
	"testing"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

const groupingCreditsModel = "claude-grouping-credits"

func groupingCreditsFixture(t *testing.T) (*Manager, *accessTestScope, *accessTestExecutor) {
	t.Helper()
	m := NewManager(nil, &FillFirstSelector{}, nil)
	m.SetConfig(&internalconfig.Config{QuotaExceeded: internalconfig.QuotaExceeded{AntigravityCredits: true}})
	exec := &accessTestExecutor{schedulerTestExecutor: schedulerTestExecutor{provider: "antigravity"}}
	m.RegisterExecutor(exec)
	for _, id := range []string{"grouping-credits-allowed", "grouping-credits-blocked"} {
		if _, err := m.Register(context.Background(), &Auth{ID: id, Provider: "antigravity"}); err != nil {
			t.Fatal(err)
		}
		registry.GetGlobalRegistry().RegisterClient(id, "antigravity", []*registry.ModelInfo{{ID: groupingCreditsModel}})
		t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(id) })
	}
	scope := &accessTestScope{allowed: "grouping-credits-allowed"}
	m.SetCredentialAccessPolicy(&accessTestPolicy{scope: scope})
	return m, scope, exec
}

func runGroupingCredits(m *Manager, stream bool, options cliproxyexecutor.Options) (bool, error) {
	req := cliproxyexecutor.Request{Model: groupingCreditsModel}
	if stream {
		result, used, err := m.tryAntigravityCreditsExecuteStream(context.Background(), req, options)
		if result != nil {
			for range result.Chunks {
			}
		}
		return used, err
	}
	_, used, err := m.tryAntigravityCreditsExecute(context.Background(), req, options)
	return used, err
}

func TestCredentialAccessCreditsCandidatesAndPinnedSelection(t *testing.T) {
	m, _, _ := groupingCreditsFixture(t)
	for _, pinned := range []string{"", "grouping-credits-allowed", "grouping-credits-blocked"} {
		opts := cliproxyexecutor.Options{Metadata: map[string]any{cliproxyexecutor.PinnedAuthMetadataKey: pinned}}
		candidates, err := m.findAllAntigravityCreditsCandidateAuths(context.Background(), groupingCreditsModel, opts)
		if err != nil {
			t.Fatal(err)
		}
		if pinned == "grouping-credits-blocked" {
			if len(candidates) != 0 {
				t.Fatal("blocked pin became a credits candidate")
			}
		} else if len(candidates) != 1 || candidates[0].auth.ID != "grouping-credits-allowed" {
			t.Fatalf("unfiltered credits candidates: %v", candidates)
		}
	}
}

type groupingCreditsTransport struct{ scope *accessTestScope }

func (p groupingCreditsTransport) RoundTripperFor(*Auth) http.RoundTripper {
	p.scope.denied = errors.New("revoked after credits selection")
	return nil
}

func TestCredentialAccessCreditsRechecksUseAndNeverRecordsDenial(t *testing.T) {
	for _, stream := range []bool{false, true} {
		for _, duringUse := range []bool{false, true} {
			m, scope, exec := groupingCreditsFixture(t)
			if duringUse {
				exec.upstreamErr = credentialAccessFailure(errors.New("plugin callback denied"))
			} else {
				m.rtProvider = groupingCreditsTransport{scope: scope}
			}
			used, err := runGroupingCredits(m, stream, cliproxyexecutor.Options{})
			if used || !isCredentialAccessError(err) {
				t.Fatalf("stream=%v used=%v error=%v", stream, used, err)
			}
			wantCalls := 0
			if duringUse {
				wantCalls = 1
			}
			if exec.calls != wantCalls {
				t.Fatalf("executions=%d want=%d", exec.calls, wantCalls)
			}
			assertAccessNoFailureState(t, m)
		}
	}
}

func TestCredentialAccessHomeAlsoRejectsDirectHTTPAndRefresh(t *testing.T) {
	m, _, exec := accessExecutionFixture(t)
	m.SetConfig(&internalconfig.Config{Home: internalconfig.HomeConfig{Enabled: true}})
	auth, _ := m.GetByID("allowed")
	req, err := http.NewRequest(http.MethodGet, "https://upstream.invalid/", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = m.HttpRequest(nil, auth, req); statusCodeFromError(err) != http.StatusServiceUnavailable {
		t.Fatalf("Home direct HTTP error=%v", err)
	}
	if _, err = m.RefreshAuthForRequest(context.Background(), auth.ID, ""); statusCodeFromError(err) != http.StatusServiceUnavailable {
		t.Fatalf("Home refresh error=%v", err)
	}
	if exec.calls != 0 {
		t.Fatal("Home combination used local credentials")
	}
}
