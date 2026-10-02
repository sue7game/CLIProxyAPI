package handlers

import (
	"context"
	"testing"

	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

func TestGroupingRetainedCredentialRejectsRuntimeIDReuse(t *testing.T) {
	m := coreauth.NewManager(nil, nil, nil)
	m.SetCredentialAccessPolicy(pluginGroupingPolicy{})
	original := &coreauth.Auth{ID: "retained", Provider: "codex", Attributes: map[string]string{"grouping_id": "original"}}
	for _, tc := range []struct {
		name    string
		modify  func(*coreauth.Auth)
		allowed bool
	}{
		{"unchanged", func(*coreauth.Auth) {}, true},
		{"uuid-replaced", func(a *coreauth.Auth) { a.Attributes["grouping_id"] = "replacement" }, false},
		{"provider-replaced", func(a *coreauth.Auth) { a.Provider = "xai" }, false},
		{"missing-identity", func(a *coreauth.Auth) { delete(a.Attributes, "grouping_id") }, false},
		{"conflicting-identity", func(a *coreauth.Auth) { a.Metadata = map[string]any{"grouping_id": "conflict"} }, false},
		{"disabled", func(a *coreauth.Auth) { a.Disabled = true }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			current := original.Clone()
			tc.modify(current)
			if _, err := m.Register(context.Background(), current); err != nil {
				t.Fatal(err)
			}
			_, err := AuthorizeRetainedCredential(context.Background(), m, original)
			if (err == nil) != tc.allowed {
				t.Fatalf("allowed = %v, error = %v", tc.allowed, err)
			}
		})
	}
}
