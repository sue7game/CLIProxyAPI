package cliproxy

import (
	"context"
	"reflect"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/grouping"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/config"
)

func TestGroupingInventoryRuntimeSyncBlocksOldSelection(t *testing.T) {
	for _, enabled := range []bool{true, false} {
		t.Run(map[bool]string{true: "grouping-on", false: "grouping-off"}[enabled], func(t *testing.T) {
			f := newGroupingInventoryFixture(t, false)
			if enabled {
				f.activate(t)
			}
			auth := groupingInventoryCredential(t, f)
			assertGroupingInventoryScheduling(t, f, auth, false)
			finish := blockInventoryRuntime(t, f, true)
			if f.service.grouping.healthy() == enabled {
				t.Fatal("runtime publication gate does not match grouping activation")
			}
			assertGroupingInventoryScheduling(t, f, auth, enabled)
			if len(GlobalModelRegistry().GetModelsForClient(auth.ID)) == 0 {
				t.Fatal("test did not pause before the old model registration was retired")
			}
			if err := finish(); err != nil {
				t.Fatal(err)
			}
			if !f.service.grouping.healthy() {
				t.Fatal("completed runtime synchronization did not restore readiness")
			}
			assertInventoryRuntimeRetired(t, f, auth.ID)
			assertGroupingInventoryScheduling(t, f, auth, true)
		})
	}
}

func TestGroupingInventoryRuntimeFailureRemainsClosed(t *testing.T) {
	f := newGroupingInventoryFixture(t, false)
	f.activate(t)
	auth := groupingInventoryCredential(t, f)
	policy := &groupingAccessPolicy{store: f.service.grouping.store, principalCurrent: f.service.grouping.principalCurrent, ready: f.service.grouping.healthy}
	scope, err := policy.BeginAttempt(f.principal())
	if err != nil {
		t.Fatal(err)
	}
	finish := blockInventoryRuntime(t, f, false)
	if err := scope.AuthorizeUse(f.principal(), auth); err == nil {
		t.Fatal("retained access scope ignored the runtime publication gate")
	}
	assertGroupingInventoryScheduling(t, f, auth, true)
	if err := finish(); err == nil || f.service.grouping.healthy() {
		t.Fatal("failed runtime publication reported success or reopened authorization")
	}
	assertGroupingInventoryScheduling(t, f, auth, true)
}

func TestGroupingInventoryRejectedMutationRestoresReadiness(t *testing.T) {
	f := newGroupingInventoryFixture(t, false)
	f.activate(t)
	before := f.snapshot(t)
	request := inventoryConfigRequest(f, func(cfg *config.Config) { cfg.OpenAICompatibility[0].Disabled = true })
	request.Current.Debug = !request.Current.Debug
	if err := f.service.applyGroupingConfigMutation(f.ctx, request); err == nil {
		t.Fatal("stale configuration was accepted")
	}
	if !f.service.grouping.healthy() || !reflect.DeepEqual(before, f.snapshot(t)) {
		t.Fatal("rejected validation changed policy or left the runtime unavailable")
	}
	assertGroupingInventoryScheduling(t, f, groupingInventoryCredential(t, f), false)
}

func TestGroupingInventoryDeletionRetiresOnlyConfigSources(t *testing.T) {
	f := newGroupingInventoryFixture(t, false)
	f.activate(t)
	auth := groupingInventoryCredential(t, f)
	other := &coreauth.Auth{ID: "inventory-file-source", Provider: "codex", Status: coreauth.StatusActive,
		Attributes: map[string]string{"api_key": "file-test-key", "source": "file:inventory"}}
	if _, err := f.service.coreManager.Register(coreauth.WithSkipPersist(context.Background()), other); err != nil {
		t.Fatal(err)
	}
	applyInventoryConfig(t, f, func(cfg *config.Config) { cfg.OpenAICompatibility = nil })
	assertInventoryRuntimeRetired(t, f, auth.ID)
	if f.snapshot(t).Identities[auth.Attributes["grouping_id"]].State != grouping.Tombstone {
		t.Fatal("deletion did not retire the persisted source identity")
	}
	if _, exists := f.service.coreManager.GetByID(other.ID); !exists {
		t.Fatal("configuration synchronization removed a non-config credential")
	}
	assertGroupingInventoryScheduling(t, f, auth, true)
}

func TestGroupingInventoryManagedDisabledAdditionStartsActive(t *testing.T) {
	f := newGroupingInventoryFixture(t, false)
	f.activate(t)
	applyInventoryConfig(t, f, func(cfg *config.Config) {
		added := cfg.CloneForRuntime().OpenAICompatibility[0]
		added.Name, added.Disabled = "inventory-added", true
		added.APIKeyEntries[0].GroupingID = ""
		cfg.OpenAICompatibility = append(cfg.OpenAICompatibility, added)
	})
	id := f.service.cfg.OpenAICompatibility[1].APIKeyEntries[0].GroupingID
	identity := f.snapshot(t).Identities[id]
	if identity.State != grouping.Active || identity.GroupID != grouping.AllGroups {
		t.Fatal("managed disabled addition was treated as an untrusted external source")
	}
	applyInventoryConfig(t, f, func(cfg *config.Config) { cfg.OpenAICompatibility[1].Disabled = false })
	if f.snapshot(t).Identities[id] != identity {
		t.Fatal("enabling a managed source changed its identity")
	}
	for _, auth := range f.service.coreManager.List() {
		if auth.Attributes["grouping_id"] == id {
			assertGroupingInventoryScheduling(t, f, auth, false)
			return
		}
	}
	t.Fatal("enabled source was not published")
}

func assertInventoryRuntimeRetired(t *testing.T, f *groupingIntegrationFixture, runtimeID string) {
	t.Helper()
	if _, exists := f.service.coreManager.GetByID(runtimeID); exists {
		t.Fatal("obsolete configuration source remains in the runtime manager")
	}
	if len(GlobalModelRegistry().GetModelsForClient(runtimeID)) != 0 {
		t.Fatal("obsolete configuration source retained advertised models")
	}
}
