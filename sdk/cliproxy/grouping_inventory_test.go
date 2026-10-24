package cliproxy

import (
	"reflect"
	"testing"

	"github.com/google/uuid"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/api/handlers/groupingapi"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/grouping"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/watcher/synthesizer"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/config"
)

func TestGroupingInventoryDisableReenablePreservesIdentity(t *testing.T) {
	for _, test := range []struct {
		name     string
		disabled bool
	}{
		{"initially-enabled", false}, {"initially-disabled", true},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newGroupingInventoryFixture(t, test.disabled)
			auth := groupingInventoryCredential(t, f)
			id := auth.Attributes["grouping_id"]
			groupID := f.createGroup(t, "Inventory group")
			f.bind(t, groupingapi.BindingRequest{CredentialIDs: []string{id}, GroupID: groupID})
			f.activate(t)
			before := f.snapshot(t).Identities[id]
			if before.State != grouping.Active || before.GroupID != groupID {
				t.Fatal("source was not initialized as an active, bound identity")
			}
			assertGroupingInventoryScheduling(t, f, auth, test.disabled)
			for _, disabled := range []bool{true, false} {
				setGroupingInventoryDisabled(t, f, disabled)
				current := groupingInventoryCredential(t, f)
				if current.Attributes["grouping_id"] != id || current.EffectiveDisabled() != disabled {
					t.Fatal("inventory lost its UUID or runtime disabled flag")
				}
				if actual := f.snapshot(t).Identities[id]; !reflect.DeepEqual(actual, before) {
					t.Fatalf("disabled=%v changed UUID, binding, fingerprint or active state", disabled)
				}
				assertGroupingInventoryScheduling(t, f, current, disabled)
			}
		})
	}
}

func TestGroupingInventoryPreservesEnabledDuplicateRuntimeIDs(t *testing.T) {
	disabledID, enabledID := uuid.NewString(), uuid.NewString()
	compat := config.OpenAICompatibility{
		Name: "inventory-duplicate", BaseURL: "https://example.invalid/v1",
		APIKeyEntries: []config.OpenAICompatibilityAPIKey{{APIKey: "same-test-key", GroupingID: disabledID}},
	}
	cfg := &config.Config{AuthDir: t.TempDir(), OpenAICompatibility: []config.OpenAICompatibility{compat, compat}}
	cfg.OpenAICompatibility[0].Disabled = true
	cfg.OpenAICompatibility[1].APIKeyEntries = []config.OpenAICompatibilityAPIKey{{APIKey: "same-test-key", GroupingID: enabledID}}
	cfg.Grouping.Enabled = true
	before := cfg.CloneForRuntime()
	runtime, err := synthesizer.NewConfigSynthesizer().Synthesize(&synthesizer.SynthesisContext{Config: cfg})
	if err != nil || len(runtime) != 1 {
		t.Fatalf("synthesize enabled duplicate: %v", err)
	}
	g := &groupingService{owner: &Service{}}
	inventory, err := g.collectSources(cfg, nil)
	if err != nil || len(inventory) != 2 {
		t.Fatalf("expected both independent records in inventory, got %d: %v", len(inventory), err)
	}
	byID := make(map[string]*coreauth.Auth, len(inventory))
	for _, auth := range inventory {
		byID[auth.Attributes["grouping_id"]] = auth
	}
	enabled, disabled := byID[enabledID], byID[disabledID]
	if enabled == nil || disabled == nil || enabled.ID == disabled.ID {
		t.Fatal("duplicate sources did not retain independent identities")
	}
	if enabled.ID != runtime[0].ID || enabled.Attributes["config_index"] != "1" || enabled.EffectiveDisabled() {
		t.Fatal("inventory changed the enabled duplicate's runtime identity or index")
	}
	if !disabled.Disabled || disabled.Status != coreauth.StatusDisabled || disabled.Attributes["config_index"] != "0" {
		t.Fatal("disabled inventory entry was not explicitly disabled")
	}
	if !reflect.DeepEqual(cfg, before) {
		t.Fatal("inventory synthesis mutated the runtime configuration")
	}
}
