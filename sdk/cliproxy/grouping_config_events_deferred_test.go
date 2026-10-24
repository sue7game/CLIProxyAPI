package cliproxy

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/grouping"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/config"
)

func TestGroupingConfigEventsDeferredWatcherReplaysCredentialChanges(t *testing.T) {
	for _, runtimeOK := range []bool{true, false} {
		t.Run(map[bool]string{true: "success", false: "runtime-failure"}[runtimeOK], func(t *testing.T) {
			f := newGroupingInventoryFixture(t, false)
			f.activate(t)
			oldAuth := groupingInventoryCredential(t, f)
			calls := 0
			w, queue := newConfigEventWatcher(t, f, func(cfg *config.Config) {
				calls++
				f.service.applyWatcherConfigUpdate(cfg)
			})
			f.service.handleAuthUpdates(coreauth.WithSkipPersist(f.ctx), receiveConfigEvents(t, queue, 1))
			record := prepareDeferredOAuth(t, f)
			proposed, addedID := changedDeferredConfigSources(f.service.cfg)
			writeDeferredConfig(t, f, proposed)
			w.ReloadConfigIfChanged()
			f.service.handleAuthUpdates(coreauth.WithSkipPersist(f.ctx), receiveConfigEvents(t, queue, 2))
			assertPendingConfigEventsUseOldConfig(t, f, oldAuth, addedID)
			f.service.updateServerClientsContextFn = func(context.Context, *config.Config) bool { return runtimeOK }
			saveDeferredOAuth(t, f, record)
			err := f.service.grouping.finalizeOAuthRecord(f.ctx, record)
			if !runtimeOK {
				if err == nil {
					t.Fatal("failed watcher replay reported success")
				}
				assertDeferredConfigState(t, f, true, false)
				assertGroupingInventoryScheduling(t, f, oldAuth, true)
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			w.ReloadConfigIfChanged()
			if calls != 2 || f.service.cfg.Routing.Strategy != proposed.Routing.Strategy {
				t.Fatal("replay required an additional watcher callback or lost accepted config")
			}
			assertDeferredConfigState(t, f, false, true)
			assertInventoryRuntimeRetired(t, f, oldAuth.ID)
			assertConfigEventRuntimeMatchesConfig(t, f)
			if f.snapshot(t).Identities[addedID].State != grouping.PendingRebind {
				t.Fatal("external new credential bypassed explicit identity approval")
			}
		})
	}
}

func changedDeferredConfigSources(current *config.Config) (*config.Config, string) {
	proposed := current.CloneForRuntime()
	added := current.CloneForRuntime().OpenAICompatibility[0]
	added.Name = "deferred-added"
	added.APIKeyEntries[0].GroupingID = uuid.NewString()
	proposed.OpenAICompatibility[0].Disabled = true
	proposed.OpenAICompatibility = append(proposed.OpenAICompatibility, added)
	proposed.Routing.Strategy = "fill-first"
	return proposed, added.APIKeyEntries[0].GroupingID
}

func assertPendingConfigEventsUseOldConfig(t *testing.T, f *groupingIntegrationFixture, oldAuth *coreauth.Auth, addedID string) {
	t.Helper()
	g := f.service.grouping
	g.mu.Lock()
	queued := g.deferredConfig
	g.mu.Unlock()
	if queued == nil || queued.synthesize || f.service.cfg.OpenAICompatibility[0].Disabled {
		t.Fatal("watcher configuration was not deferred with synthesize=false")
	}
	assertGroupingInventoryScheduling(t, f, oldAuth, false)
	for _, auth := range f.service.coreManager.List() {
		if auth.Attributes["grouping_id"] == addedID {
			t.Fatal("new config source was registered before its configuration was accepted")
		}
	}
}
