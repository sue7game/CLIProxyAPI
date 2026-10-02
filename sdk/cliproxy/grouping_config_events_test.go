package cliproxy

import (
	"reflect"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/watcher"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/config"
)

func TestGroupingConfigEventsLateAddAndModifyCannotReviveDisabledDuplicate(t *testing.T) {
	for _, action := range []watcher.AuthUpdateAction{watcher.AuthUpdateActionAdd, watcher.AuthUpdateActionModify} {
		t.Run(string(action), func(t *testing.T) {
			f, first, secondID := newConfigEventDuplicateFixture(t)
			w, queue := newConfigEventWatcher(t, f, f.service.applyWatcherConfigUpdate)
			late := receiveConfigEvents(t, queue, 2)
			if action == watcher.AuthUpdateActionModify {
				f.service.handleAuthUpdates(coreauth.WithSkipPersist(f.ctx), late)
				proposed := f.service.cfg.CloneForRuntime()
				proposed.RequestRetry++
				writeDeferredConfig(t, f, proposed)
				w.ReloadConfigIfChanged()
				late = receiveConfigEvents(t, queue, 2)
			}
			for _, update := range late {
				if update.Action != action {
					t.Fatalf("watcher emitted %s, want %s", update.Action, action)
				}
			}
			before := f.snapshot(t)
			applyInventoryConfig(t, f, func(cfg *config.Config) { cfg.OpenAICompatibility[0].Disabled = true })
			assertGroupingInventoryScheduling(t, f, first, true)
			f.service.handleAuthUpdates(coreauth.WithSkipPersist(f.ctx), late)
			assertGroupingInventoryScheduling(t, f, first, true)
			assertInventoryActiveSourceSet(t, f, map[string]bool{secondID: true})
			assertConfigEventRuntimeMatchesConfig(t, f)
			if !reflect.DeepEqual(before.Identities, f.snapshot(t).Identities) {
				t.Fatal("late watcher event changed source identity or group")
			}
		})
	}
}

func TestGroupingConfigEventsLateBareDeleteUsesAcceptedOwner(t *testing.T) {
	for _, reuse := range []bool{false, true} {
		t.Run(map[bool]string{false: "reenabled", true: "different-uuid"}[reuse], func(t *testing.T) {
			f := newGroupingInventoryFixture(t, false)
			f.activate(t)
			first := groupingInventoryCredential(t, f)
			w, queue := newConfigEventWatcher(t, f, nil)
			f.service.handleAuthUpdates(coreauth.WithSkipPersist(f.ctx), receiveConfigEvents(t, queue, 1))
			setGroupingInventoryDisabled(t, f, true)
			w.ReloadConfigIfChanged()
			late := receiveConfigEvents(t, queue, 1)
			if late[0].Action != watcher.AuthUpdateActionDelete || late[0].Auth != nil {
				t.Fatal("test did not obtain a real bare-ID deletion")
			}
			applyInventoryConfig(t, f, func(cfg *config.Config) {
				if !reuse {
					cfg.OpenAICompatibility[0].Disabled = false
					return
				}
				next := cfg.CloneForRuntime().OpenAICompatibility[0]
				next.Disabled, next.APIKeyEntries[0].GroupingID = false, ""
				cfg.OpenAICompatibility = append(cfg.OpenAICompatibility, next)
			})
			current, ok := f.service.coreManager.GetByID(first.ID)
			if !ok || (current.Attributes["grouping_id"] != first.Attributes["grouping_id"]) != reuse {
				t.Fatal("test did not establish the expected owner of the reused runtime ID")
			}
			f.service.handleAuthUpdates(coreauth.WithSkipPersist(f.ctx), late)
			assertConfigEventRuntimeMatchesConfig(t, f)
			assertGroupingInventoryScheduling(t, f, current, false)
		})
	}
}

func TestGroupingConfigEventsLatePayloadCannotUndoDuplicateReorder(t *testing.T) {
	f, first, _ := newConfigEventDuplicateFixture(t)
	_, queue := newConfigEventWatcher(t, f, nil)
	late := receiveConfigEvents(t, queue, 2)
	before := f.snapshot(t)
	applyInventoryConfig(t, f, func(cfg *config.Config) {
		cfg.OpenAICompatibility[0], cfg.OpenAICompatibility[1] = cfg.OpenAICompatibility[1], cfg.OpenAICompatibility[0]
	})
	f.service.handleAuthUpdates(coreauth.WithSkipPersist(f.ctx), late)
	assertConfigEventRuntimeMatchesConfig(t, f)
	assertGroupingInventoryScheduling(t, f, first, false)
	if !reflect.DeepEqual(before.Identities, f.snapshot(t).Identities) {
		t.Fatal("reordered sources lost independent UUIDs or bindings")
	}
}

func TestGroupingConfigEventsLatePayloadCannotRestoreDeletedOrReplacedSource(t *testing.T) {
	for _, remove := range []bool{true, false} {
		t.Run(map[bool]string{true: "deleted", false: "key-edited"}[remove], func(t *testing.T) {
			f := newGroupingInventoryFixture(t, false)
			f.activate(t)
			first := groupingInventoryCredential(t, f)
			_, queue := newConfigEventWatcher(t, f, nil)
			late := receiveConfigEvents(t, queue, 1)
			applyInventoryConfig(t, f, func(cfg *config.Config) {
				if remove {
					cfg.OpenAICompatibility = nil
				} else {
					cfg.OpenAICompatibility[0].APIKeyEntries[0].APIKey = "replacement-test-key"
				}
			})
			f.service.handleAuthUpdates(coreauth.WithSkipPersist(f.ctx), late)
			assertInventoryRuntimeRetired(t, f, first.ID)
			assertConfigEventRuntimeMatchesConfig(t, f)
		})
	}
}
