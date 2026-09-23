package auth

import (
	"context"
	"encoding/json"
	"strings"
	"sync/atomic"
	"testing"
)

type runtimeOverrideStore struct {
	saveCount atomic.Int32
	items     []*Auth
}

func (s *runtimeOverrideStore) List(context.Context) ([]*Auth, error) {
	items := make([]*Auth, 0, len(s.items))
	for _, auth := range s.items {
		items = append(items, auth.Clone())
	}
	return items, nil
}

func (s *runtimeOverrideStore) Save(context.Context, *Auth) (string, error) {
	s.saveCount.Add(1)
	return "", nil
}

func (s *runtimeOverrideStore) Delete(context.Context, string) error { return nil }

func TestManagerUpdatePreservesRuntimeAuthOverride(t *testing.T) {
	manager := NewManager(nil, nil, nil)
	ctx := WithSkipPersist(context.Background())
	auth := &Auth{
		ID:         "antigravity-auth",
		Provider:   "antigravity",
		ProxyURL:   "http://configured.example:8080",
		Attributes: map[string]string{"priority": "14"},
	}
	if _, errRegister := manager.Register(ctx, auth); errRegister != nil {
		t.Fatalf("Register() error = %v", errRegister)
	}
	priority := 13
	proxyURL := "socks5://runtime.example:1080"
	if _, errSet := manager.SetRuntimeAuthOverride(auth.Index, RuntimeAuthOverride{
		Priority: &priority,
		ProxyURL: &proxyURL,
	}); errSet != nil {
		t.Fatalf("SetRuntimeAuthOverride() error = %v", errSet)
	}

	updated := &Auth{
		ID:         auth.ID,
		Provider:   auth.Provider,
		ProxyURL:   "http://updated-config.example:8080",
		Attributes: map[string]string{"priority": "20"},
	}
	saved, errUpdate := manager.Update(ctx, updated)
	if errUpdate != nil {
		t.Fatalf("Update() error = %v", errUpdate)
	}
	if got := saved.ConfiguredPriority(); got != 20 {
		t.Fatalf("ConfiguredPriority() = %d, want 20", got)
	}
	if got := saved.EffectivePriority(); got != 13 {
		t.Fatalf("EffectivePriority() = %d, want 13", got)
	}
	if got := saved.EffectiveProxyURL(); got != proxyURL {
		t.Fatalf("EffectiveProxyURL() = %q, want %q", got, proxyURL)
	}
	override, found := manager.GetRuntimeAuthOverride(auth.Index)
	if !found || override.Priority == nil || *override.Priority != 13 {
		t.Fatalf("GetRuntimeAuthOverride() = %#v, %v", override, found)
	}
}

func TestManagerRegisterPreservesRuntimeAuthOverrideForExistingID(t *testing.T) {
	manager := NewManager(nil, nil, nil)
	ctx := WithSkipPersist(context.Background())
	auth := &Auth{
		ID:         "antigravity-register",
		Provider:   "antigravity",
		FileName:   "antigravity-register.json",
		Attributes: map[string]string{"priority": "14"},
	}
	if _, errRegister := manager.Register(ctx, auth); errRegister != nil {
		t.Fatalf("Register() error = %v", errRegister)
	}
	priority := 13
	if _, errSet := manager.SetRuntimeAuthOverride(auth.Index, RuntimeAuthOverride{Priority: &priority}); errSet != nil {
		t.Fatalf("SetRuntimeAuthOverride() error = %v", errSet)
	}

	replacement := &Auth{
		ID:         auth.ID,
		Provider:   auth.Provider,
		FileName:   "antigravity-register-renamed.json",
		Attributes: map[string]string{"priority": "20"},
	}
	registered, errRegister := manager.Register(ctx, replacement)
	if errRegister != nil {
		t.Fatalf("Register(replacement) error = %v", errRegister)
	}
	if got := registered.ConfiguredPriority(); got != 20 {
		t.Fatalf("ConfiguredPriority() = %d, want 20", got)
	}
	if got := registered.EffectivePriority(); got != priority {
		t.Fatalf("EffectivePriority() = %d, want %d", got, priority)
	}
	if registered.Index != auth.Index {
		t.Fatalf("Index = %q, want preserved %q", registered.Index, auth.Index)
	}
}

func TestManagerLoadPreservesRuntimeAuthOverrideForExistingIDs(t *testing.T) {
	store := &runtimeOverrideStore{
		items: []*Auth{{
			ID:         "antigravity-load",
			Provider:   "antigravity",
			FileName:   "antigravity-load.json",
			Attributes: map[string]string{"priority": "14"},
		}},
	}
	manager := NewManager(store, nil, nil)
	ctx := context.Background()
	if errLoad := manager.Load(ctx); errLoad != nil {
		t.Fatalf("Load() error = %v", errLoad)
	}
	loaded, ok := manager.GetByID("antigravity-load")
	if !ok {
		t.Fatal("loaded auth not found")
	}
	priority := 13
	if _, errSet := manager.SetRuntimeAuthOverride(loaded.Index, RuntimeAuthOverride{Priority: &priority}); errSet != nil {
		t.Fatalf("SetRuntimeAuthOverride() error = %v", errSet)
	}

	store.items = []*Auth{
		{
			ID:         loaded.ID,
			Provider:   loaded.Provider,
			FileName:   "antigravity-load-renamed.json",
			Attributes: map[string]string{"priority": "20"},
		},
		{
			ID:         "antigravity-new",
			Provider:   "antigravity",
			Attributes: map[string]string{"priority": "11"},
		},
	}
	if errLoad := manager.Load(ctx); errLoad != nil {
		t.Fatalf("Load(reload) error = %v", errLoad)
	}
	reloaded, ok := manager.GetByID(loaded.ID)
	if !ok {
		t.Fatal("reloaded auth not found")
	}
	if got := reloaded.ConfiguredPriority(); got != 20 {
		t.Fatalf("ConfiguredPriority() = %d, want 20", got)
	}
	if got := reloaded.EffectivePriority(); got != priority {
		t.Fatalf("EffectivePriority() = %d, want %d", got, priority)
	}
	if reloaded.Index != loaded.Index {
		t.Fatalf("Index = %q, want preserved %q", reloaded.Index, loaded.Index)
	}
	newAuth, ok := manager.GetByID("antigravity-new")
	if !ok {
		t.Fatal("new auth not found")
	}
	if override := newAuth.RuntimeAuthOverride(); !override.Empty() {
		t.Fatalf("new auth inherited runtime override: %#v", override)
	}
}

func TestRuntimeAuthOverrideCloneAndSerialization(t *testing.T) {
	disabled := true
	priority := 13
	proxyURL := "direct"
	auth := &Auth{
		ID:       "auth-a",
		Provider: "antigravity",
		runtimeOverride: RuntimeAuthOverride{
			Disabled: &disabled,
			Priority: &priority,
			ProxyURL: &proxyURL,
		},
	}
	cloned := auth.Clone()
	*cloned.runtimeOverride.Priority = 7
	if got := auth.EffectivePriority(); got != 13 {
		t.Fatalf("original EffectivePriority() = %d after clone mutation, want 13", got)
	}

	payload, errMarshal := json.Marshal(auth)
	if errMarshal != nil {
		t.Fatalf("json.Marshal() error = %v", errMarshal)
	}
	serialized := string(payload)
	if strings.Contains(serialized, "runtimeOverride") || strings.Contains(serialized, "proxy_url\":\"direct") {
		t.Fatalf("runtime override leaked into serialized auth: %s", serialized)
	}
}

func TestRuntimeAuthOverrideValidation(t *testing.T) {
	manager := NewManager(nil, nil, nil)
	auth := &Auth{ID: "auth-a", Provider: "antigravity"}
	if _, errRegister := manager.Register(WithSkipPersist(context.Background()), auth); errRegister != nil {
		t.Fatalf("Register() error = %v", errRegister)
	}

	disabled := false
	if _, errSet := manager.SetRuntimeAuthOverride(auth.Index, RuntimeAuthOverride{Disabled: &disabled}); errSet == nil {
		t.Fatal("SetRuntimeAuthOverride(disabled=false) error = nil, want validation error")
	}
	emptyProxy := "  "
	if _, errSet := manager.SetRuntimeAuthOverride(auth.Index, RuntimeAuthOverride{ProxyURL: &emptyProxy}); errSet == nil {
		t.Fatal("SetRuntimeAuthOverride(empty proxy) error = nil, want validation error")
	}
	if _, errClear := manager.ClearRuntimeAuthOverride(auth.Index, RuntimeAuthOverrideField("unknown")); errClear == nil {
		t.Fatal("ClearRuntimeAuthOverride(unknown) error = nil, want validation error")
	}
}

func TestPatchRuntimeAuthOverrideClearsAndSetsTogether(t *testing.T) {
	manager := NewManager(nil, nil, nil)
	auth := &Auth{
		ID:         "auth-patch",
		Provider:   "antigravity",
		ProxyURL:   "http://configured.example:8080",
		Attributes: map[string]string{"priority": "14"},
	}
	if _, errRegister := manager.Register(WithSkipPersist(context.Background()), auth); errRegister != nil {
		t.Fatalf("Register() error = %v", errRegister)
	}
	disabled := true
	oldPriority := 13
	oldProxy := "http://old-runtime.example:8080"
	if _, errSet := manager.SetRuntimeAuthOverride(auth.Index, RuntimeAuthOverride{
		Disabled: &disabled,
		Priority: &oldPriority,
		ProxyURL: &oldProxy,
	}); errSet != nil {
		t.Fatalf("SetRuntimeAuthOverride() error = %v", errSet)
	}

	newPriority := 12
	direct := "direct"
	patched, errPatch := manager.PatchRuntimeAuthOverride(
		auth.Index,
		[]RuntimeAuthOverrideField{RuntimeAuthOverrideDisabled, RuntimeAuthOverridePriority},
		RuntimeAuthOverride{Priority: &newPriority, ProxyURL: &direct},
	)
	if errPatch != nil {
		t.Fatalf("PatchRuntimeAuthOverride() error = %v", errPatch)
	}
	if patched.EffectiveDisabled() || patched.EffectivePriority() != newPriority || patched.EffectiveProxyURL() != direct {
		t.Fatalf("patched auth = %#v, want enabled priority %d direct", patched, newPriority)
	}
	override, found := manager.GetRuntimeAuthOverride(auth.Index)
	if !found || override.Disabled != nil || override.Priority == nil || *override.Priority != newPriority || override.ProxyURL == nil || *override.ProxyURL != direct {
		t.Fatalf("GetRuntimeAuthOverride() = %#v, %v", override, found)
	}
}

func TestRuntimeAuthOverrideFieldRevisionsFenceSameValueWrites(t *testing.T) {
	manager := NewManager(nil, nil, nil)
	auth := &Auth{
		ID:         "auth-revision",
		Provider:   "antigravity",
		Attributes: map[string]string{"priority": "14"},
	}
	registered, errRegister := manager.Register(WithSkipPersist(context.Background()), auth)
	if errRegister != nil {
		t.Fatalf("Register() error = %v", errRegister)
	}

	priority := 13
	if _, errSet := manager.SetRuntimeAuthOverride(registered.Index, RuntimeAuthOverride{Priority: &priority}); errSet != nil {
		t.Fatalf("SetRuntimeAuthOverride() error = %v", errSet)
	}
	firstRevisions, found := manager.GetRuntimeAuthOverrideRevisions(registered.Index)
	if !found || firstRevisions.Priority != 1 || firstRevisions.Disabled != 0 || firstRevisions.ProxyURL != 0 {
		t.Fatalf("first revisions = %#v, found=%v", firstRevisions, found)
	}

	if _, errSet := manager.SetRuntimeAuthOverride(registered.Index, RuntimeAuthOverride{Priority: &priority}); errSet != nil {
		t.Fatalf("same-value SetRuntimeAuthOverride() error = %v", errSet)
	}
	secondRevisions, _ := manager.GetRuntimeAuthOverrideRevisions(registered.Index)
	if secondRevisions.Priority != 2 {
		t.Fatalf("same-value priority revision = %d, want 2", secondRevisions.Priority)
	}

	staleRevision := firstRevisions.Priority
	patched, currentRevisions, applied, errPatch := manager.PatchRuntimeAuthOverrideIfRevision(
		registered.Index,
		[]RuntimeAuthOverrideField{RuntimeAuthOverridePriority},
		RuntimeAuthOverride{},
		RuntimeAuthOverridePriority,
		&staleRevision,
	)
	if errPatch != nil {
		t.Fatalf("PatchRuntimeAuthOverrideIfRevision() error = %v", errPatch)
	}
	if applied || currentRevisions.Priority != 2 {
		t.Fatalf("stale patch applied=%v revisions=%#v", applied, currentRevisions)
	}
	if override := patched.RuntimeAuthOverride(); override.Priority == nil || *override.Priority != priority {
		t.Fatalf("stale patch changed priority: %#v", override)
	}
}

func TestRuntimeAuthOverrideFieldRevisionsIgnoreUnrelatedWrites(t *testing.T) {
	manager := NewManager(nil, nil, nil)
	auth := &Auth{ID: "auth-field-revision", Provider: "antigravity"}
	registered, errRegister := manager.Register(WithSkipPersist(context.Background()), auth)
	if errRegister != nil {
		t.Fatalf("Register() error = %v", errRegister)
	}

	priority := 13
	if _, errSet := manager.SetRuntimeAuthOverride(registered.Index, RuntimeAuthOverride{Priority: &priority}); errSet != nil {
		t.Fatalf("set priority error = %v", errSet)
	}
	guardedRevisions, _ := manager.GetRuntimeAuthOverrideRevisions(registered.Index)
	proxyURL := "direct"
	if _, errSet := manager.SetRuntimeAuthOverride(registered.Index, RuntimeAuthOverride{ProxyURL: &proxyURL}); errSet != nil {
		t.Fatalf("set proxy error = %v", errSet)
	}

	expectedPriorityRevision := guardedRevisions.Priority
	patched, revisions, applied, errPatch := manager.PatchRuntimeAuthOverrideIfRevision(
		registered.Index,
		[]RuntimeAuthOverrideField{RuntimeAuthOverridePriority},
		RuntimeAuthOverride{},
		RuntimeAuthOverridePriority,
		&expectedPriorityRevision,
	)
	if errPatch != nil || !applied {
		t.Fatalf("priority CAS error=%v applied=%v revisions=%#v", errPatch, applied, revisions)
	}
	if revisions.Priority != guardedRevisions.Priority+1 || revisions.ProxyURL != 1 {
		t.Fatalf("independent revisions = %#v", revisions)
	}
	override := patched.RuntimeAuthOverride()
	if override.Priority != nil || override.ProxyURL == nil || *override.ProxyURL != proxyURL {
		t.Fatalf("patched override = %#v, want proxy only", override)
	}
}

func TestRuntimeAuthOverrideRevisionSurvivesAuthReplacement(t *testing.T) {
	manager := NewManager(nil, nil, nil)
	ctx := WithSkipPersist(context.Background())
	auth := &Auth{ID: "auth-replaced-revision", Provider: "antigravity"}
	registered, errRegister := manager.Register(ctx, auth)
	if errRegister != nil {
		t.Fatalf("Register() error = %v", errRegister)
	}
	priority := 13
	if _, errSet := manager.SetRuntimeAuthOverride(registered.Index, RuntimeAuthOverride{Priority: &priority}); errSet != nil {
		t.Fatalf("set priority error = %v", errSet)
	}
	staleRevision := uint64(1)

	replacement := &Auth{ID: auth.ID, Provider: auth.Provider}
	if _, errUpdate := manager.Update(ctx, replacement); errUpdate != nil {
		t.Fatalf("Update() error = %v", errUpdate)
	}
	if _, errSet := manager.SetRuntimeAuthOverride(registered.Index, RuntimeAuthOverride{Priority: &priority}); errSet != nil {
		t.Fatalf("same-value replacement write error = %v", errSet)
	}
	_, revisions, applied, errPatch := manager.PatchRuntimeAuthOverrideIfRevision(
		registered.Index,
		[]RuntimeAuthOverrideField{RuntimeAuthOverridePriority},
		RuntimeAuthOverride{},
		RuntimeAuthOverridePriority,
		&staleRevision,
	)
	if errPatch != nil || applied || revisions.Priority != 2 {
		t.Fatalf("replacement CAS error=%v applied=%v revisions=%#v", errPatch, applied, revisions)
	}
}
