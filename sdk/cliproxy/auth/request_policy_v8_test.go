package auth

import (
	"context"
	"testing"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

func TestCredentialAccessIntersectsCodexAlphaSearchPolicy(t *testing.T) {
	m := NewManager(nil, &FillFirstSelector{}, nil)
	m.RegisterExecutor(schedulerTestExecutor{provider: "codex"})
	for _, candidate := range []*Auth{
		{ID: "ordinary", Provider: "codex", Attributes: map[string]string{AttributeAPIKey: "ordinary-fixture"}},
		{ID: "alpha", Provider: "codex", Attributes: map[string]string{
			AttributeAPIKey: "alpha-fixture", AttributeCodexAlphaSearch: "true", "base_url": "https://example.invalid",
		}},
	} {
		if _, err := m.Register(context.Background(), candidate); err != nil {
			t.Fatal(err)
		}
	}
	for _, allowed := range []string{"ordinary", "alpha", "missing"} {
		t.Run(allowed, func(t *testing.T) {
			m.SetCredentialAccessPolicy(&accessTestPolicy{scope: &accessTestScope{allowed: allowed}})
			selected, err := m.SelectAuthWithCredentialPolicy(context.Background(), "codex", "", CredentialPolicyCodexAlphaSearchV1, cliproxyexecutor.Options{})
			if allowed == "alpha" {
				if err != nil || selected == nil || selected.ID != "alpha" {
					t.Fatalf("eligible in-scope credential was rejected: %v", err)
				}
			} else if err == nil || selected != nil {
				t.Fatal("group scope bypassed the credential policy or selected another group's source")
			}
		})
	}
}

func TestCredentialAccessEpochRefreshRejectsReplacementBeforeExecutor(t *testing.T) {
	m, scope, base := accessExecutionFixture(t)
	exec := &accessRefreshExecutor{accessTestExecutor: base, scope: scope}
	m.RegisterExecutor(exec)
	original, ok := m.GetByID("allowed")
	if !ok {
		t.Fatal("missing fixture credential")
	}
	if _, err := m.refreshAuthForRequestAtEpoch(context.Background(), original.ID, "", original.RegistrationEpoch+1); err == nil {
		t.Fatal("stale refresh job accepted a different registration")
	}
	if exec.refreshes != 0 {
		t.Fatal("stale refresh job reached the provider")
	}
	assertAccessNoFailureState(t, m)
}
