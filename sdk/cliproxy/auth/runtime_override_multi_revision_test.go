package auth

import (
	"context"
	"testing"
)

func TestRuntimeAuthOverrideMultiFieldCASIsAtomic(t *testing.T) {
	manager := NewManager(nil, nil, nil)
	auth := &Auth{
		ID:         "auth-multi-revision",
		Provider:   "antigravity",
		Attributes: map[string]string{"priority": "14"},
	}
	registered, errRegister := manager.Register(WithSkipPersist(context.Background()), auth)
	if errRegister != nil {
		t.Fatalf("Register() error = %v", errRegister)
	}

	disabled := true
	priority := 13
	if _, errSet := manager.SetRuntimeAuthOverride(registered.Index, RuntimeAuthOverride{
		Priority: &priority,
	}); errSet != nil {
		t.Fatalf("SetRuntimeAuthOverride() error = %v", errSet)
	}

	newPriority := 12
	stale := RuntimeAuthOverrideRevisions{Disabled: 0, Priority: 0, ProxyURL: 99}
	patched, revisions, applied, errPatch := manager.PatchRuntimeAuthOverrideIfRevisions(
		registered.Index,
		nil,
		RuntimeAuthOverride{Disabled: &disabled, Priority: &newPriority},
		stale,
	)
	if errPatch != nil {
		t.Fatalf("stale PatchRuntimeAuthOverrideIfRevisions() error = %v", errPatch)
	}
	if applied || revisions.Disabled != 0 || revisions.Priority != 1 {
		t.Fatalf("stale patch applied=%v revisions=%#v", applied, revisions)
	}
	staleOverride := patched.RuntimeAuthOverride()
	if staleOverride.Disabled != nil || staleOverride.Priority == nil || *staleOverride.Priority != priority {
		t.Fatalf("stale patch partially changed override: %#v", staleOverride)
	}

	current := RuntimeAuthOverrideRevisions{Disabled: 0, Priority: 1, ProxyURL: 99}
	patched, revisions, applied, errPatch = manager.PatchRuntimeAuthOverrideIfRevisions(
		registered.Index,
		nil,
		RuntimeAuthOverride{Disabled: &disabled, Priority: &newPriority},
		current,
	)
	if errPatch != nil || !applied {
		t.Fatalf("current PatchRuntimeAuthOverrideIfRevisions() error=%v applied=%v", errPatch, applied)
	}
	if revisions.Disabled != 1 || revisions.Priority != 2 || revisions.ProxyURL != 0 {
		t.Fatalf("successful multi-field revisions = %#v", revisions)
	}
	override := patched.RuntimeAuthOverride()
	if override.Disabled == nil || !*override.Disabled || override.Priority == nil || *override.Priority != newPriority {
		t.Fatalf("successful multi-field override = %#v", override)
	}
}
