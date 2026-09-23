package auth

import (
	"context"
	"testing"
)

func TestManagerRuntimeAuthOverrideInvalidatesSessionAffinityForRoutingChanges(t *testing.T) {
	selector := NewSessionAffinitySelector(&RoundRobinSelector{})
	t.Cleanup(selector.Stop)
	manager := NewManager(nil, selector, nil)
	auth := &Auth{
		ID:         "antigravity-affinity-routing",
		Provider:   "antigravity",
		Attributes: map[string]string{"priority": "14"},
	}
	if _, errRegister := manager.Register(WithSkipPersist(context.Background()), auth); errRegister != nil {
		t.Fatalf("Register() error = %v", errRegister)
	}

	cacheKey := "antigravity::session-routing::gemini"
	disabled := true
	assertRuntimeOverrideInvalidatesAffinity(t, selector, cacheKey, auth.ID, func() error {
		_, errSet := manager.SetRuntimeAuthOverride(auth.Index, RuntimeAuthOverride{Disabled: &disabled})
		return errSet
	})
	assertRuntimeOverrideInvalidatesAffinity(t, selector, cacheKey, auth.ID, func() error {
		_, errClear := manager.ClearRuntimeAuthOverride(auth.Index, RuntimeAuthOverrideDisabled)
		return errClear
	})

	priority := 13
	assertRuntimeOverrideInvalidatesAffinity(t, selector, cacheKey, auth.ID, func() error {
		_, errSet := manager.SetRuntimeAuthOverride(auth.Index, RuntimeAuthOverride{Priority: &priority})
		return errSet
	})
	assertRuntimeOverrideInvalidatesAffinity(t, selector, cacheKey, auth.ID, func() error {
		_, errClear := manager.ClearRuntimeAuthOverride(auth.Index, RuntimeAuthOverridePriority)
		return errClear
	})
}

func TestManagerRuntimeAuthOverridePreservesSessionAffinityForProxyOnlyChanges(t *testing.T) {
	selector := NewSessionAffinitySelector(&RoundRobinSelector{})
	t.Cleanup(selector.Stop)
	manager := NewManager(nil, selector, nil)
	auth := &Auth{ID: "antigravity-affinity-proxy", Provider: "antigravity"}
	if _, errRegister := manager.Register(WithSkipPersist(context.Background()), auth); errRegister != nil {
		t.Fatalf("Register() error = %v", errRegister)
	}

	cacheKey := "antigravity::session-proxy::gemini"
	proxyURL := "http://runtime-proxy.example:8080"
	assertRuntimeOverridePreservesAffinity(t, selector, cacheKey, auth.ID, func() error {
		_, errSet := manager.SetRuntimeAuthOverride(auth.Index, RuntimeAuthOverride{ProxyURL: &proxyURL})
		return errSet
	})
	assertRuntimeOverridePreservesAffinity(t, selector, cacheKey, auth.ID, func() error {
		_, errClear := manager.ClearRuntimeAuthOverride(auth.Index, RuntimeAuthOverrideProxyURL)
		return errClear
	})
}

func TestManagerRuntimeAuthOverridePreservesSessionAffinityWhenRoutingIsUnchanged(t *testing.T) {
	selector := NewSessionAffinitySelector(&RoundRobinSelector{})
	t.Cleanup(selector.Stop)
	manager := NewManager(nil, selector, nil)
	auth := &Auth{
		ID:         "antigravity-affinity-noop",
		Provider:   "antigravity",
		Disabled:   true,
		Attributes: map[string]string{"priority": "14"},
	}
	if _, errRegister := manager.Register(WithSkipPersist(context.Background()), auth); errRegister != nil {
		t.Fatalf("Register() error = %v", errRegister)
	}

	cacheKey := "antigravity::session-noop::gemini"
	disabled := true
	assertRuntimeOverridePreservesAffinity(t, selector, cacheKey, auth.ID, func() error {
		_, errSet := manager.SetRuntimeAuthOverride(auth.Index, RuntimeAuthOverride{Disabled: &disabled})
		return errSet
	})
	assertRuntimeOverridePreservesAffinity(t, selector, cacheKey, auth.ID, func() error {
		_, errClear := manager.ClearRuntimeAuthOverride(auth.Index, RuntimeAuthOverrideDisabled)
		return errClear
	})

	priority := 14
	assertRuntimeOverridePreservesAffinity(t, selector, cacheKey, auth.ID, func() error {
		_, errSet := manager.SetRuntimeAuthOverride(auth.Index, RuntimeAuthOverride{Priority: &priority})
		return errSet
	})
	assertRuntimeOverridePreservesAffinity(t, selector, cacheKey, auth.ID, func() error {
		_, errClear := manager.ClearRuntimeAuthOverride(auth.Index, RuntimeAuthOverridePriority)
		return errClear
	})
}

func assertRuntimeOverrideInvalidatesAffinity(
	t *testing.T,
	selector *SessionAffinitySelector,
	cacheKey string,
	authID string,
	mutate func() error,
) {
	t.Helper()
	selector.cache.Set(cacheKey, authID)
	if errMutate := mutate(); errMutate != nil {
		t.Fatalf("runtime override mutation error = %v", errMutate)
	}
	if got, ok := selector.cache.Get(cacheKey); ok {
		t.Fatalf("session affinity binding still exists for auth %q: %q", authID, got)
	}
}

func assertRuntimeOverridePreservesAffinity(
	t *testing.T,
	selector *SessionAffinitySelector,
	cacheKey string,
	authID string,
	mutate func() error,
) {
	t.Helper()
	selector.cache.Set(cacheKey, authID)
	if errMutate := mutate(); errMutate != nil {
		t.Fatalf("runtime override mutation error = %v", errMutate)
	}
	if got, ok := selector.cache.Get(cacheKey); !ok || got != authID {
		t.Fatalf("session affinity binding = %q, %v, want %q, true", got, ok, authID)
	}
}
