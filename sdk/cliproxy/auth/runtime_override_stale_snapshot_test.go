package auth

import (
	"context"
	"testing"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
)

func TestRuntimeOverrideRejectsStaleSchedulerSnapshots(t *testing.T) {
	disabled, priority, proxy := true, 23, "http://runtime.example:8080"
	for name, override := range map[string]RuntimeAuthOverride{
		"disabled": {Disabled: &disabled},
		"priority": {Priority: &priority},
		"proxy":    {ProxyURL: &proxy},
	} {
		for _, clear := range []bool{false, true} {
			operation := "set/"
			if clear {
				operation = "clear/"
			}
			for _, mode := range []string{"lifecycle", "result", "rebuild"} {
				t.Run(operation+name+"/"+mode, func(t *testing.T) {
					checkRuntimeOverrideStaleSnapshot(t, override, clear, mode)
				})
			}
		}
	}
}

func checkRuntimeOverrideStaleSnapshot(t *testing.T, override RuntimeAuthOverride, clear bool, mode string) {
	t.Helper()
	manager := NewManager(nil, nil, nil)
	auth, errRegister := manager.Register(WithSkipPersist(context.Background()), schedulerSyncTestAuth("test-token"))
	if errRegister != nil {
		t.Fatal(errRegister)
	}
	patch := func() {
		t.Helper()
		if _, errPatch := manager.SetRuntimeAuthOverride(auth.Index, override); errPatch != nil {
			t.Fatal(errPatch)
		}
	}
	if clear {
		patch()
	}
	stale, _ := manager.GetByID(auth.ID)
	if clear {
		if _, errClear := manager.ClearRuntimeAuthOverride(auth.Index); errClear != nil {
			t.Fatal(errClear)
		}
	} else {
		patch()
	}
	want, _ := manager.GetByID(auth.ID)
	switch mode {
	case "lifecycle":
		manager.scheduler.upsertAuth(stale)
	case "result":
		manager.scheduler.upsertAuthResult(stale, nil, true)
	case "rebuild":
		manager.scheduler.rebuild([]*Auth{stale})
	}
	got, errPick := manager.scheduler.pickSingle(context.Background(), auth.Provider, "", cliproxyexecutor.Options{}, nil)
	if want.EffectiveDisabled() {
		if errPick == nil || got != nil {
			t.Fatalf("stale snapshot resurrected disabled credential: %v, %v", got, errPick)
		}
		return
	}
	if errPick != nil || got == nil {
		t.Fatalf("stale snapshot removed active credential: %v", errPick)
	}
	if got.EffectivePriority() != want.EffectivePriority() || got.EffectiveProxyURL() != want.EffectiveProxyURL() {
		t.Fatalf("stale routing state: priority=%d proxy=%q; want priority=%d proxy=%q", got.EffectivePriority(), got.EffectiveProxyURL(), want.EffectivePriority(), want.EffectiveProxyURL())
	}
}
