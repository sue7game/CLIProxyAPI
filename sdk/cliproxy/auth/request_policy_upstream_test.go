package auth

import (
	"context"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
)

func TestCredentialAccessChangesCoverNewMutationEntrypoints(t *testing.T) {
	for _, operation := range []string{"modify", "registration-update", "siwc-bind", "load"} {
		t.Run(operation, func(t *testing.T) {
			manager, base, _, _ := setupSIWCBinding(t, "auth.json")
			changes, cancel := manager.SubscribeCredentialAccessChanges()
			defer cancel()
			runAccessNotifyingMutation(t, manager, base, operation)
			select {
			case <-changes:
			default:
				t.Fatal("credential mutation did not invalidate retained permissions")
			}
		})
	}
}

func runAccessNotifyingMutation(t *testing.T, manager *Manager, base *Auth, operation string) {
	t.Helper()
	ctx := context.Background()
	var errMutation error
	switch operation {
	case "modify":
		_, _, errMutation = manager.Modify(ctx, base.ID, base.RegistrationEpoch, func(auth *Auth) error {
			auth.Attributes["grouping_id"] = "replacement"
			return nil
		})
	case "registration-update":
		updated := base.Clone()
		updated.Attributes["grouping_id"] = "replacement"
		_, _, errMutation = manager.UpdateIfRegistrationCurrent(ctx, base, updated)
	case "siwc-bind":
		_, errMutation = manager.BindCodexSIWC(ctx, base.ID, base.RegistrationEpoch, "account", bindingTokens("bound"))
	case "load":
		manager.SetStore(newRuntimeOverrideCloneStore(base))
		errMutation = manager.Load(ctx)
	}
	if errMutation != nil {
		t.Fatal(errMutation)
	}
}

func TestDiscardedRegistrationUpdateDoesNotInvalidateCredentialAccess(t *testing.T) {
	manager, base, _, _ := setupSIWCBinding(t, "auth.json")
	manager.Remove(context.Background(), base.ID)
	if _, errRegister := manager.Register(context.Background(), base.Clone()); errRegister != nil {
		t.Fatal(errRegister)
	}
	changes, cancel := manager.SubscribeCredentialAccessChanges()
	defer cancel()
	_, applied, errUpdate := manager.UpdateIfRegistrationCurrent(context.Background(), base, base.Clone())
	if errUpdate != nil || applied {
		t.Fatalf("stale update: applied=%t error=%v", applied, errUpdate)
	}
	select {
	case <-changes:
		t.Fatal("discarded update published a credential access change")
	default:
	}
}

func TestScopedNativeToolSearchDoesNotConsultUnauthorizedCredentials(t *testing.T) {
	manager := NewManager(nil, nil, nil)
	yes := &toolSearchSupportExecutor{replaceAwareExecutor: &replaceAwareExecutor{id: "scoped-search-yes"}, supported: true}
	no := &toolSearchSupportExecutor{replaceAwareExecutor: &replaceAwareExecutor{id: "scoped-search-no"}}
	manager.RegisterExecutor(yes)
	manager.RegisterExecutor(no)
	registerToolSearchAuth(t, manager, "scoped-search-allowed", yes.Identifier(), false, "scoped-search-model")
	registerToolSearchAuth(t, manager, "scoped-search-denied", no.Identifier(), false, "scoped-search-model")
	allowed, _ := manager.GetByID("scoped-search-allowed")
	if !manager.SupportsNativeToolSearchForAuths("scoped-search-model", []*Auth{allowed}) {
		t.Fatal("unauthorized credential affected scoped tool-search capability")
	}
	if len(no.seen) != 0 {
		t.Fatal("scoped capability consulted an unauthorized executor")
	}
	disabled := true
	allowed, errOverride := manager.SetRuntimeAuthOverride(allowed.Index, RuntimeAuthOverride{Disabled: &disabled})
	if errOverride != nil {
		t.Fatal(errOverride)
	}
	if manager.SupportsNativeToolSearchForAuths("scoped-search-model", []*Auth{allowed}) {
		t.Fatal("runtime-disabled credential advertised tool search")
	}
}

func TestCredentialAccessBlocksCrossGroupGuardianParentAffinity(t *testing.T) {
	selector := NewSessionAffinitySelector(&FillFirstSelector{})
	t.Cleanup(selector.Stop)
	manager := NewManager(nil, selector, nil)
	manager.RegisterExecutor(schedulerTestExecutor{provider: "codex"})
	r := registry.GetGlobalRegistry()
	for _, id := range []string{"guardian-group-parent", "guardian-group-child"} {
		if _, errRegister := manager.Register(context.Background(), &Auth{ID: id, Provider: "codex"}); errRegister != nil {
			t.Fatal(errRegister)
		}
		r.RegisterClient(id, "codex", []*registry.ModelInfo{{ID: "parent-model"}, {ID: "review-model"}})
		t.Cleanup(func() { r.UnregisterClient(id) })
	}
	manager.SetCredentialAccessPolicy(&accessTestPolicy{scope: &accessTestScope{allowed: "guardian-group-parent"}})
	parent, errParent := manager.SelectAuth(context.Background(), "codex", "parent-model", guardianTestOptions("main-thread", ""))
	if errParent != nil || parent == nil || parent.ID != "guardian-group-parent" {
		t.Fatalf("parent selection failed: auth=%v error=%v", parent, errParent)
	}
	manager.SetCredentialAccessPolicy(&accessTestPolicy{scope: &accessTestScope{allowed: "guardian-group-child"}})
	child, errChild := manager.SelectAuth(context.Background(), "codex", "review-model", guardianTestOptions("review-thread", "main-thread"))
	if errChild != nil || child == nil || child.ID != "guardian-group-child" {
		t.Fatalf("guardian inherited an unauthorized parent: auth=%v error=%v", child, errChild)
	}
}
