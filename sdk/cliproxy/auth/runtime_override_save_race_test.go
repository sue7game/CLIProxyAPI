package auth

import (
	"context"
	"fmt"
	"reflect"
	"sync"
	"testing"
)

func TestRuntimeOverrideSurvivesConcurrentStoreSave(t *testing.T) {
	for _, operation := range []string{"Register", "Update", "Prepare", "Refresh", "Metadata"} {
		t.Run(operation, func(t *testing.T) {
			testRuntimeOverrideDuringStoreSave(t, operation)
		})
	}
}

func testRuntimeOverrideDuringStoreSave(t *testing.T, operation string) {
	t.Helper()
	store := &blockingEnrichingAuthStore{entered: make(chan struct{}), release: make(chan struct{})}
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(store.release) }) }
	defer release()
	manager := NewManager(store, nil, nil)
	base := registerRuntimeOverrideSaveAuth(t, manager)
	done := make(chan error, 1)
	go func() { done <- runRuntimeOverrideSaveOperation(manager, base, operation) }()
	<-store.entered

	priority, proxy := 13, "direct"
	latest, errPatch := manager.PatchRuntimeAuthOverride(base.Index,
		[]RuntimeAuthOverrideField{RuntimeAuthOverrideDisabled},
		RuntimeAuthOverride{Priority: &priority, ProxyURL: &proxy})
	if errPatch != nil {
		t.Fatal(errPatch)
	}
	staleRevision := latest.RuntimeAuthOverrideRevisions().Priority
	latest, errPatch = manager.SetRuntimeAuthOverride(base.Index, RuntimeAuthOverride{Priority: &priority})
	if errPatch != nil {
		t.Fatal(errPatch)
	}
	release()
	if errSave := <-done; errSave != nil {
		t.Fatal(errSave)
	}
	assertRuntimeOverrideAfterStoreSave(t, manager, base.ID, latest, operation)
	assertRuntimeOverrideStoreIsClean(t, store)
	_, _, applied, errCAS := manager.PatchRuntimeAuthOverrideIfRevision(base.Index, nil,
		RuntimeAuthOverride{Priority: &priority}, RuntimeAuthOverridePriority, &staleRevision)
	if errCAS != nil || applied {
		t.Fatalf("stale CAS after save: applied=%t error=%v", applied, errCAS)
	}
}

func registerRuntimeOverrideSaveAuth(t *testing.T, manager *Manager) *Auth {
	t.Helper()
	base, errRegister := manager.Register(WithSkipPersist(context.Background()), &Auth{
		ID: "runtime-save", Provider: "audit", Status: StatusActive,
		Attributes: map[string]string{"priority": "3"},
		Metadata:   map[string]any{"access_token": "old-token"},
	})
	if errRegister != nil {
		t.Fatal(errRegister)
	}
	disabled, priority, proxy := true, 5, "http://proxy.example:8080"
	base, errOverride := manager.SetRuntimeAuthOverride(base.Index,
		RuntimeAuthOverride{Disabled: &disabled, Priority: &priority, ProxyURL: &proxy})
	if errOverride != nil {
		t.Fatal(errOverride)
	}
	return base
}

func runRuntimeOverrideSaveOperation(manager *Manager, base *Auth, operation string) error {
	ctx := context.Background()
	updated := base.Clone()
	updated.Metadata["access_token"] = "new-token"
	var errSave error
	switch operation {
	case "Register":
		_, errSave = manager.Register(ctx, updated)
	case "Update":
		_, errSave = manager.Update(ctx, updated)
	case "Prepare":
		_, errSave = manager.UpdatePreparedAuth(ctx, base, updated)
	case "Refresh":
		_, errSave = manager.UpdateRefreshedAuth(ctx, base, updated)
	case "Metadata":
		applied, preempted := manager.PersistMetadataEntry(ctx, base.ID, base.RegistrationEpoch,
			"capability", "supported", nil)
		if !applied || preempted {
			return fmt.Errorf("metadata save: applied=%t preempted=%t", applied, preempted)
		}
	default:
		return fmt.Errorf("unknown save operation %q", operation)
	}
	return errSave
}

func assertRuntimeOverrideAfterStoreSave(t *testing.T, manager *Manager, id string, latest *Auth, operation string) {
	t.Helper()
	current, ok := manager.GetByID(id)
	if !ok {
		t.Fatal("auth disappeared during save")
	}
	if !reflect.DeepEqual(current.RuntimeAuthOverride(), latest.RuntimeAuthOverride()) ||
		current.RuntimeAuthOverrideRevisions() != latest.RuntimeAuthOverrideRevisions() {
		t.Fatalf("runtime routing changed during save: override=%+v revisions=%+v",
			current.RuntimeAuthOverride(), current.RuntimeAuthOverrideRevisions())
	}
	if current.EffectiveDisabled() || current.EffectivePriority() != 13 || current.EffectiveProxyURL() != "direct" {
		t.Fatal("effective routing does not reflect the concurrent patch")
	}
	if current.FileName != id+".json" || current.Attributes[AttributeSourceBackend] != AuthSourceFile {
		t.Fatal("Store.Save enrichment was lost")
	}
	if operation == "Metadata" && current.Metadata["capability"] != "supported" {
		t.Fatal("metadata save was lost")
	}
	if operation != "Register" && current.Generation < latest.Generation {
		t.Fatal("save rolled back the runtime override generation")
	}
	assertRuntimeOverrideSchedulerAfterSave(t, manager, current)
}

func assertRuntimeOverrideSchedulerAfterSave(t *testing.T, manager *Manager, current *Auth) {
	t.Helper()
	manager.scheduler.mu.Lock()
	defer manager.scheduler.mu.Unlock()
	provider := manager.scheduler.providers[current.Provider]
	if provider == nil || provider.auths[current.ID] == nil {
		t.Fatal("scheduler lost the enabled credential")
	}
	scheduled := provider.auths[current.ID].auth
	if !reflect.DeepEqual(scheduled.RuntimeAuthOverride(), current.RuntimeAuthOverride()) ||
		scheduled.RuntimeAuthOverrideRevisions() != current.RuntimeAuthOverrideRevisions() {
		t.Fatal("scheduler retained pre-save runtime routing")
	}
}

func assertRuntimeOverrideStoreIsClean(t *testing.T, store *blockingEnrichingAuthStore) {
	t.Helper()
	store.mu.Lock()
	defer store.mu.Unlock()
	if len(store.saved) != 1 {
		t.Fatalf("store saves=%d, want 1", len(store.saved))
	}
	for _, saved := range store.saved {
		if !saved.RuntimeAuthOverride().Empty() || saved.RuntimeAuthOverrideRevisions() != (RuntimeAuthOverrideRevisions{}) {
			t.Fatal("Store.Save received process-local runtime routing")
		}
	}
}
