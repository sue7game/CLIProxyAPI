package auth

import (
	"context"
	"sync"
	"testing"
)

type runtimeOverrideCloneStore struct {
	mu    sync.Mutex
	items map[string]*Auth
}

func newRuntimeOverrideCloneStore(auths ...*Auth) *runtimeOverrideCloneStore {
	store := &runtimeOverrideCloneStore{items: make(map[string]*Auth, len(auths))}
	for _, auth := range auths {
		if auth != nil {
			store.items[auth.ID] = auth.Clone()
		}
	}
	return store
}

func (s *runtimeOverrideCloneStore) List(context.Context) ([]*Auth, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	items := make([]*Auth, 0, len(s.items))
	for _, auth := range s.items {
		items = append(items, auth.Clone())
	}
	return items, nil
}

func (s *runtimeOverrideCloneStore) Save(_ context.Context, auth *Auth) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.items[auth.ID] = auth.Clone()
	return auth.ID, nil
}

func (s *runtimeOverrideCloneStore) Delete(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.items, id)
	return nil
}

func (s *runtimeOverrideCloneStore) auth(id string) *Auth {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.items[id].Clone()
}

func (s *runtimeOverrideCloneStore) replace(auth *Auth) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.items[auth.ID] = auth.Clone()
}

func TestPersistStripsRuntimeAuthOverrideFromCustomStore(t *testing.T) {
	store := newRuntimeOverrideCloneStore()
	manager := NewManager(store, nil, nil)
	auth := &Auth{
		ID:         "antigravity-persist-override",
		Provider:   "antigravity",
		Attributes: map[string]string{"priority": "14"},
		Metadata:   map[string]any{"access_token": "token-old"},
	}
	if _, errRegister := manager.Register(context.Background(), auth); errRegister != nil {
		t.Fatalf("Register() error = %v", errRegister)
	}

	priority := 13
	if _, errSet := manager.SetRuntimeAuthOverride(auth.Index, RuntimeAuthOverride{Priority: &priority}); errSet != nil {
		t.Fatalf("SetRuntimeAuthOverride() error = %v", errSet)
	}
	updated, ok := manager.GetByID(auth.ID)
	if !ok {
		t.Fatal("GetByID() auth not found")
	}
	updated.Metadata["access_token"] = "token-new"
	if _, errUpdate := manager.Update(context.Background(), updated); errUpdate != nil {
		t.Fatalf("Update() error = %v", errUpdate)
	}

	if override := store.auth(auth.ID).RuntimeAuthOverride(); !override.Empty() {
		t.Fatalf("persisted runtime override = %#v, want empty", override)
	}
}

func TestLoadRejectsRuntimeOverrideReturnedByStore(t *testing.T) {
	priority := 9
	stored := &Auth{
		ID:         "antigravity-load-restart",
		Provider:   "antigravity",
		Attributes: map[string]string{"priority": "14"},
		runtimeOverride: RuntimeAuthOverride{
			Priority: &priority,
		},
	}
	manager := NewManager(newRuntimeOverrideCloneStore(stored), nil, nil)
	if errLoad := manager.Load(context.Background()); errLoad != nil {
		t.Fatalf("Load() error = %v", errLoad)
	}

	loaded, ok := manager.GetByID(stored.ID)
	if !ok {
		t.Fatal("GetByID() auth not found")
	}
	if override := loaded.RuntimeAuthOverride(); !override.Empty() {
		t.Fatalf("loaded runtime override = %#v, want empty", override)
	}
	if got := loaded.EffectivePriority(); got != 14 {
		t.Fatalf("EffectivePriority() = %d, want configured priority 14", got)
	}
}

func TestLoadRestoresOnlyCurrentManagerRuntimeOverride(t *testing.T) {
	stored := &Auth{
		ID:         "antigravity-load-hot-reload",
		Provider:   "antigravity",
		Attributes: map[string]string{"priority": "14"},
	}
	store := newRuntimeOverrideCloneStore(stored)
	manager := NewManager(store, nil, nil)
	if errLoad := manager.Load(context.Background()); errLoad != nil {
		t.Fatalf("Load() error = %v", errLoad)
	}
	loaded, _ := manager.GetByID(stored.ID)
	priority := 13
	if _, errSet := manager.SetRuntimeAuthOverride(loaded.Index, RuntimeAuthOverride{Priority: &priority}); errSet != nil {
		t.Fatalf("SetRuntimeAuthOverride() error = %v", errSet)
	}

	storePriority := 9
	store.replace(&Auth{
		ID:         stored.ID,
		Provider:   stored.Provider,
		Attributes: map[string]string{"priority": "20"},
		runtimeOverride: RuntimeAuthOverride{
			Priority: &storePriority,
		},
	})
	if errLoad := manager.Load(context.Background()); errLoad != nil {
		t.Fatalf("Load(reload) error = %v", errLoad)
	}

	reloaded, _ := manager.GetByID(stored.ID)
	if got := reloaded.ConfiguredPriority(); got != 20 {
		t.Fatalf("ConfiguredPriority() = %d, want 20", got)
	}
	if got := reloaded.EffectivePriority(); got != priority {
		t.Fatalf("EffectivePriority() = %d, want current manager override %d", got, priority)
	}
}
