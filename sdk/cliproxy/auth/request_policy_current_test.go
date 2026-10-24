package auth

import (
	"context"
	"testing"
)

func TestCredentialAccessRejectsStaleCredentialSnapshots(t *testing.T) {
	for _, mutation := range []string{"disable", "remove", "replace", "update"} {
		t.Run(mutation, func(t *testing.T) {
			m, _ := newAccessTestManager(t)
			auth, _ := m.GetByID("allowed")
			old := auth.Clone()
			events, unsubscribe := m.SubscribeCredentialAccessChanges()
			defer unsubscribe()
			switch mutation {
			case "disable":
				disabled := true
				if _, err := m.PatchRuntimeAuthOverride(auth.Index, nil, RuntimeAuthOverride{Disabled: &disabled}); err != nil {
					t.Fatal(err)
				}
			case "remove":
				m.Remove(context.Background(), auth.ID)
			case "replace":
				if _, err := m.Register(context.Background(), auth); err != nil {
					t.Fatal(err)
				}
			case "update":
				auth.Disabled = true
				if _, err := m.Update(context.Background(), auth); err != nil {
					t.Fatal(err)
				}
			}
			if err := m.AuthorizeCredentialUse(context.Background(), old); !isCredentialAccessError(err) {
				t.Fatalf("stale credential snapshot accepted: %v", err)
			}
			select {
			case <-events:
			default:
				t.Fatal("credential change did not invalidate persistent sessions")
			}
		})
	}
}
