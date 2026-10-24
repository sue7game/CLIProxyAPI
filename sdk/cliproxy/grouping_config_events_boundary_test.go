package cliproxy

import (
	"reflect"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/watcher"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/config"
)

func TestGroupingConfigEventsRemainClosedDuringManagedRuntimeCallback(t *testing.T) {
	f := newGroupingInventoryFixture(t, false)
	f.activate(t)
	auth := groupingInventoryCredential(t, f)
	_, queue := newConfigEventWatcher(t, f, nil)
	late := receiveConfigEvents(t, queue, 1)
	finish := blockInventoryRuntime(t, f, true)
	f.service.handleAuthUpdates(coreauth.WithSkipPersist(f.ctx), late)
	assertGroupingInventoryScheduling(t, f, auth, true)
	assertInventoryRuntimeRetired(t, f, auth.ID)
	if err := finish(); err != nil {
		t.Fatal(err)
	}
	if !f.service.grouping.healthy() {
		t.Fatal("successful runtime synchronization remained unavailable")
	}
	assertGroupingInventoryScheduling(t, f, auth, true)
	assertInventoryRuntimeRetired(t, f, auth.ID)
}

func TestGroupingConfigEventsLegacyModesAreUnchanged(t *testing.T) {
	for _, mode := range []string{"no-grouping", "grouping-off", "home"} {
		t.Run(mode, func(t *testing.T) {
			cfg := &config.Config{}
			s := &Service{cfg: cfg, coreManager: coreauth.NewManager(nil, nil, nil)}
			if mode != "no-grouping" {
				s.grouping = &groupingService{}
			}
			if mode == "home" {
				cfg.Home.Enabled = true
				s.grouping.enabled.Store(true)
			}
			auth := &coreauth.Auth{ID: "legacy-config", Provider: "codex", Attributes: map[string]string{
				"source": "config:codex", "api_key": "legacy-test-key", "grouping_id": "old-id",
			}}
			updates := []watcher.AuthUpdate{
				{Action: watcher.AuthUpdateActionAdd, ID: auth.ID, Auth: auth},
				{Action: watcher.AuthUpdateActionDelete, ID: auth.ID},
			}
			actual, err := s.authoritativeConfigAuthUpdates(cfg, updates)
			if err != nil || !reflect.DeepEqual(actual, updates) {
				t.Fatal("non-grouped or Home watcher semantics changed", err)
			}
		})
	}
}
