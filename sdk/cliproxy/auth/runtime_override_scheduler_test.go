package auth

import (
	"context"
	"testing"
	"time"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
)

func TestManagerRuntimeAuthOverrideControlsNativeScheduler(t *testing.T) {
	store := &runtimeOverrideStore{}
	manager := NewManager(store, nil, nil)
	ctx := WithSkipPersist(context.Background())
	high := &Auth{ID: "high", Provider: "antigravity", Attributes: map[string]string{"priority": "14"}}
	low := &Auth{ID: "low", Provider: "antigravity", Attributes: map[string]string{"priority": "13"}}
	if _, errRegister := manager.Register(ctx, high); errRegister != nil {
		t.Fatalf("Register(high) error = %v", errRegister)
	}
	if _, errRegister := manager.Register(ctx, low); errRegister != nil {
		t.Fatalf("Register(low) error = %v", errRegister)
	}

	assertScheduledAuthID(t, manager, "high")
	priority := 12
	if _, errSet := manager.SetRuntimeAuthOverride(high.Index, RuntimeAuthOverride{Priority: &priority}); errSet != nil {
		t.Fatalf("SetRuntimeAuthOverride(priority) error = %v", errSet)
	}
	assertScheduledAuthID(t, manager, "low")

	if _, errClear := manager.ClearRuntimeAuthOverride(high.Index, RuntimeAuthOverridePriority); errClear != nil {
		t.Fatalf("ClearRuntimeAuthOverride(priority) error = %v", errClear)
	}
	assertScheduledAuthID(t, manager, "high")

	disabled := true
	if _, errSet := manager.SetRuntimeAuthOverride(high.Index, RuntimeAuthOverride{Disabled: &disabled}); errSet != nil {
		t.Fatalf("SetRuntimeAuthOverride(disabled) error = %v", errSet)
	}
	assertScheduledAuthID(t, manager, "low")

	if _, errClear := manager.ClearRuntimeAuthOverride(high.Index); errClear != nil {
		t.Fatalf("ClearRuntimeAuthOverride(all) error = %v", errClear)
	}
	assertScheduledAuthID(t, manager, "high")
	if got := store.saveCount.Load(); got != 0 {
		t.Fatalf("runtime override unexpectedly persisted %d times", got)
	}
}

func TestManagerRuntimeDisableStillControlsSchedulerWhenCoolingDisabled(t *testing.T) {
	manager := NewManager(nil, nil, nil)
	manager.SetConfigSnapshot(&internalconfig.Config{DisableCooling: true})
	ctx := WithSkipPersist(context.Background())
	limited := &Auth{ID: "limited", Provider: "codex", Attributes: map[string]string{"priority": "14"}}
	fallback := &Auth{ID: "fallback", Provider: "codex", Attributes: map[string]string{"priority": "13"}}
	if _, errRegister := manager.Register(ctx, limited); errRegister != nil {
		t.Fatalf("Register(limited) error = %v", errRegister)
	}
	if _, errRegister := manager.Register(ctx, fallback); errRegister != nil {
		t.Fatalf("Register(fallback) error = %v", errRegister)
	}

	assertScheduledAuthIDForProvider(t, manager, "codex", "limited")
	disabled := true
	if _, errSet := manager.SetRuntimeAuthOverride(limited.Index, RuntimeAuthOverride{Disabled: &disabled}); errSet != nil {
		t.Fatalf("SetRuntimeAuthOverride(disabled) error = %v", errSet)
	}
	assertScheduledAuthIDForProvider(t, manager, "codex", "fallback")
}

func TestManagerMutationSchedulerSyncUsesCurrentAuthState(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(context.Context, *Manager, *Auth) error
	}{
		{
			name: "register",
			mutate: func(ctx context.Context, manager *Manager, auth *Auth) error {
				_, errRegister := manager.Register(ctx, auth)
				return errRegister
			},
		},
		{
			name: "update",
			mutate: func(ctx context.Context, manager *Manager, auth *Auth) error {
				_, errUpdate := manager.Update(ctx, auth)
				return errUpdate
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			testMutationSchedulerSyncUsesCurrentAuthState(t, test.mutate)
		})
	}
}

func testMutationSchedulerSyncUsesCurrentAuthState(
	t *testing.T,
	mutate func(context.Context, *Manager, *Auth) error,
) {
	t.Helper()
	manager := NewManager(nil, nil, nil)
	ctx := WithDeferredAPIKeyModelAliasRebuild(WithSkipPersist(context.Background()))
	auth := schedulerSyncTestAuth("token-old")
	if _, errRegister := manager.Register(ctx, auth); errRegister != nil {
		t.Fatalf("Register(initial) error = %v", errRegister)
	}

	priority := 13
	runBlockedSchedulerMutation(t, manager, auth, func() error {
		return mutate(ctx, manager, schedulerSyncTestAuth("token-new"))
	}, func() error {
		_, errSet := manager.SetRuntimeAuthOverride(auth.Index, RuntimeAuthOverride{Priority: &priority})
		return errSet
	})

	selected := scheduledAuthForTest(t, manager)
	if got := authAccessToken(selected); got != "token-new" {
		t.Fatalf("scheduled access token = %q, want token-new", got)
	}
	if got := selected.EffectivePriority(); got != priority {
		t.Fatalf("scheduled EffectivePriority() = %d, want %d", got, priority)
	}
	assertRuntimeDisabledAuthRemovedFromScheduler(t, manager, auth)
}

func runBlockedSchedulerMutation(
	t *testing.T,
	manager *Manager,
	auth *Auth,
	mutate func() error,
	override func() error,
) {
	t.Helper()
	manager.scheduler.mu.Lock()
	schedulerLocked := true
	defer func() {
		if schedulerLocked {
			manager.scheduler.mu.Unlock()
		}
	}()

	mutationDone := make(chan error, 1)
	go func() { mutationDone <- mutate() }()
	if !waitForManagerAuthToken(manager, auth.ID, "token-new", time.Second) {
		manager.scheduler.mu.Unlock()
		schedulerLocked = false
		t.Fatalf("manager auth token did not update before scheduler sync")
	}
	if !waitForManagerReadLock(manager, time.Second) {
		manager.scheduler.mu.Unlock()
		schedulerLocked = false
		if errMutation := <-mutationDone; errMutation != nil {
			t.Fatalf("auth mutation error = %v", errMutation)
		}
		t.Fatal("scheduler sync did not retain the manager read lock")
	}

	overrideDone := make(chan error, 1)
	go func() { overrideDone <- override() }()

	manager.scheduler.mu.Unlock()
	schedulerLocked = false
	if errMutation := <-mutationDone; errMutation != nil {
		t.Fatalf("auth mutation error = %v", errMutation)
	}
	if errOverride := <-overrideDone; errOverride != nil {
		t.Fatalf("SetRuntimeAuthOverride(priority) error = %v", errOverride)
	}
}

func assertRuntimeDisabledAuthRemovedFromScheduler(t *testing.T, manager *Manager, auth *Auth) {
	t.Helper()
	disabled := true
	if _, errSet := manager.SetRuntimeAuthOverride(auth.Index, RuntimeAuthOverride{Disabled: &disabled}); errSet != nil {
		t.Fatalf("SetRuntimeAuthOverride(disabled) error = %v", errSet)
	}
	manager.scheduler.upsertAuth(schedulerSyncTestAuth("token-stale"))
	manager.syncSchedulerAuth(auth.ID)
	if selected, errPick := manager.scheduler.pickSingle(context.Background(), "antigravity", "", cliproxyexecutor.Options{}, nil); errPick == nil || selected != nil {
		t.Fatalf("scheduler selected %#v after runtime disable, error = %v", selected, errPick)
	}
}

func TestSyncSchedulerHoldsManagerStateThroughRebuild(t *testing.T) {
	manager := NewManager(nil, nil, nil)
	ctx := WithDeferredAPIKeyModelAliasRebuild(WithSkipPersist(context.Background()))
	auth := schedulerSyncTestAuth("token-current")
	if _, errRegister := manager.Register(ctx, auth); errRegister != nil {
		t.Fatalf("Register() error = %v", errRegister)
	}

	manager.scheduler.mu.Lock()
	schedulerLocked := true
	defer func() {
		if schedulerLocked {
			manager.scheduler.mu.Unlock()
		}
	}()

	syncDone := make(chan struct{})
	go func() {
		manager.syncScheduler()
		close(syncDone)
	}()
	if !waitForManagerReadLock(manager, time.Second) {
		manager.scheduler.mu.Unlock()
		schedulerLocked = false
		<-syncDone
		t.Fatal("full scheduler rebuild released manager state before acquiring the scheduler lock")
	}

	priority := 13
	overrideDone := make(chan error, 1)
	go func() {
		_, errSet := manager.SetRuntimeAuthOverride(auth.Index, RuntimeAuthOverride{Priority: &priority})
		overrideDone <- errSet
	}()
	manager.scheduler.mu.Unlock()
	schedulerLocked = false
	<-syncDone
	if errOverride := <-overrideDone; errOverride != nil {
		t.Fatalf("SetRuntimeAuthOverride() error = %v", errOverride)
	}
	if got := scheduledAuthForTest(t, manager).EffectivePriority(); got != priority {
		t.Fatalf("scheduled EffectivePriority() = %d, want %d", got, priority)
	}
}

func schedulerSyncTestAuth(token string) *Auth {
	return &Auth{
		ID:         "antigravity-scheduler-sync",
		Provider:   "antigravity",
		Attributes: map[string]string{"priority": "14"},
		Metadata:   map[string]any{"access_token": token},
	}
}

func scheduledAuthForTest(t *testing.T, manager *Manager) *Auth {
	t.Helper()
	selected, errPick := manager.scheduler.pickSingle(
		context.Background(),
		"antigravity",
		"",
		cliproxyexecutor.Options{},
		nil,
	)
	if errPick != nil {
		t.Fatalf("scheduler.pickSingle() error = %v", errPick)
	}
	if selected == nil {
		t.Fatal("scheduler.pickSingle() auth = nil")
	}
	return selected
}

func waitForManagerAuthToken(manager *Manager, authID string, want string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if auth, ok := manager.GetByID(authID); ok && authAccessToken(auth) == want {
			return true
		}
		time.Sleep(time.Millisecond)
	}
	return false
}

func waitForManagerReadLock(manager *Manager, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if !manager.mu.TryLock() {
			return true
		}
		manager.mu.Unlock()
		time.Sleep(time.Millisecond)
	}
	return false
}

func assertScheduledAuthID(t *testing.T, manager *Manager, want string) {
	t.Helper()
	selected := scheduledAuthForTest(t, manager)
	if selected.ID != want {
		t.Fatalf("scheduler.pickSingle() selected %#v, want ID %q", selected, want)
	}
}

func assertScheduledAuthIDForProvider(t *testing.T, manager *Manager, provider, want string) {
	t.Helper()
	selected, errPick := manager.scheduler.pickSingle(
		context.Background(),
		provider,
		"",
		cliproxyexecutor.Options{},
		nil,
	)
	if errPick != nil {
		t.Fatalf("scheduler.pickSingle() error = %v", errPick)
	}
	if selected.ID != want {
		t.Fatalf("scheduler.pickSingle() selected %#v, want ID %q", selected, want)
	}
}
