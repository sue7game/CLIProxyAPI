package auth

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"
)

func TestFileSnapshotUpdatePreservesRuntimeOverride(t *testing.T) {
	manager, base, path, _ := setupSIWCBinding(t, "auth.json")
	disabled, priority, proxy := true, 17, "direct"
	latest, errOverride := manager.SetRuntimeAuthOverride(base.Index, RuntimeAuthOverride{
		Disabled: &disabled, Priority: &priority, ProxyURL: &proxy,
	})
	if errOverride != nil {
		t.Fatal(errOverride)
	}
	metadata := readBindingDisk(t, path)
	data, errMarshal := json.Marshal(metadata)
	if errMarshal != nil {
		t.Fatal(errMarshal)
	}
	snapshot := &Auth{
		ID: base.ID, Provider: base.Provider, Metadata: metadata,
		FileName: base.FileName, Attributes: map[string]string{"path": path},
	}
	snapshot.BindFileSnapshot(path, data)
	updated, errUpdate := manager.Update(WithSkipPersist(context.Background()), snapshot)
	if errUpdate != nil {
		t.Fatal(errUpdate)
	}
	assertMatchingRuntimeOverrides(t, updated, latest)
	if updated.HasFileSnapshot() || updated.Generation <= latest.Generation {
		t.Fatal("file snapshot was not committed as a new runtime generation")
	}
	if updated.CreatedAt != base.CreatedAt || updated.Success != base.Success {
		t.Fatal("file snapshot replaced runtime identity or traffic fields")
	}
}

func TestBindCodexSIWCPreservesRuntimeOverride(t *testing.T) {
	manager, base, path, _ := setupSIWCBinding(t, "auth.json")
	disabled, priority, proxy := true, 17, "direct"
	latest, errOverride := manager.SetRuntimeAuthOverride(base.Index, RuntimeAuthOverride{
		Disabled: &disabled, Priority: &priority, ProxyURL: &proxy,
	})
	if errOverride != nil {
		t.Fatal(errOverride)
	}
	bound, errBind := manager.BindCodexSIWC(context.Background(), base.ID,
		base.RegistrationEpoch, "account", bindingTokens("bound"))
	if errBind != nil {
		t.Fatal(errBind)
	}
	assertMatchingRuntimeOverrides(t, bound, latest)
	current, _ := manager.GetByID(base.ID)
	assertMatchingRuntimeOverrides(t, current, latest)
	if !current.EffectiveDisabled() || current.Disabled || current.Status == StatusDisabled {
		t.Fatal("binding changed the configured or runtime disabled state")
	}
	disk := readBindingDisk(t, path)
	if disk["disabled"] != false || disk["priority"] != nil || disk["proxy_url"] != nil {
		t.Fatal("binding persisted runtime overrides")
	}
	if _, errClear := manager.ClearRuntimeAuthOverride(base.Index, RuntimeAuthOverrideDisabled); errClear != nil {
		t.Fatal(errClear)
	}
	current, _ = manager.GetByID(base.ID)
	assertRuntimeOverrideSchedulerAfterSave(t, manager, current)
}

func assertMatchingRuntimeOverrides(t *testing.T, got, want *Auth) {
	t.Helper()
	if got == nil || want == nil {
		t.Fatal("missing auth snapshot")
	}
	if !reflect.DeepEqual(got.RuntimeAuthOverride(), want.RuntimeAuthOverride()) ||
		got.RuntimeAuthOverrideRevisions() != want.RuntimeAuthOverrideRevisions() {
		t.Fatal("runtime overrides or revisions changed across credential mutation")
	}
}

func TestRuntimeOverrideInvalidatesGuardianParentBindings(t *testing.T) {
	selector := NewSessionAffinitySelector(&RoundRobinSelector{})
	t.Cleanup(selector.Stop)
	manager := NewManager(nil, selector, nil)
	auth, errRegister := manager.Register(WithSkipPersist(context.Background()), &Auth{
		ID: "guardian-runtime", Provider: "codex", Attributes: map[string]string{"priority": "3"},
	})
	if errRegister != nil {
		t.Fatal(errRegister)
	}
	providers := map[string]struct{}{"codex": {}}
	selector.cache.setSessionAliases(auth.ID, "codex", "parent", "codex::parent::primary")
	proxy := "direct"
	if _, errOverride := manager.SetRuntimeAuthOverride(auth.Index, RuntimeAuthOverride{ProxyURL: &proxy}); errOverride != nil {
		t.Fatal(errOverride)
	}
	if got := selector.cache.latestSessionAuth("parent", providers); got != auth.ID {
		t.Fatal("proxy-only override removed the guardian parent binding")
	}
	priority := 7
	if _, errOverride := manager.SetRuntimeAuthOverride(auth.Index, RuntimeAuthOverride{Priority: &priority}); errOverride != nil {
		t.Fatal(errOverride)
	}
	if got := selector.cache.latestSessionAuth("parent", providers); got != "" {
		t.Fatal("routing override retained a stale guardian parent binding")
	}
	selector.cache.setSessionAliases(auth.ID, "codex", "parent", "codex::parent::primary")
	disabled := true
	if _, errOverride := manager.SetRuntimeAuthOverride(auth.Index, RuntimeAuthOverride{Disabled: &disabled}); errOverride != nil {
		t.Fatal(errOverride)
	}
	if got := selector.cache.latestSessionAuth("parent", providers); got != "" {
		t.Fatal("runtime disable retained a guardian parent binding")
	}
}
