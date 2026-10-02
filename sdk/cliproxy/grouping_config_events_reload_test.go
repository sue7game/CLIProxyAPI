package cliproxy

import (
	"context"
	"sync"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/grouping"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/watcher"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/config"
)

func TestGroupingConfigEventsWatcherPublishesBeforeDeleteConsumption(t *testing.T) {
	f := newGroupingInventoryFixture(t, false)
	f.activate(t)
	auth := groupingInventoryCredential(t, f)
	w, queue := newConfigEventWatcher(t, f, f.service.applyWatcherConfigUpdate)
	f.service.handleAuthUpdates(coreauth.WithSkipPersist(f.ctx), receiveConfigEvents(t, queue, 1))
	proposed := f.service.cfg.CloneForRuntime()
	proposed.OpenAICompatibility[0].Disabled = true
	writeDeferredConfig(t, f, proposed)
	w.ReloadConfigIfChanged()
	if !f.service.grouping.healthy() || !f.service.cfg.OpenAICompatibility[0].Disabled {
		t.Fatal("watcher did not finish accepting the disabled configuration")
	}
	if f.snapshot(t).Identities[auth.Attributes["grouping_id"]].State != grouping.Active {
		t.Fatal("disabling the source changed its persistent identity state")
	}
	// Deliberately leave the watcher deletion queued until after these checks.
	assertGroupingInventoryScheduling(t, f, auth, true)
	assertInventoryRuntimeRetired(t, f, auth.ID)
	late := receiveConfigEvents(t, queue, 1)
	if late[0].Action != watcher.AuthUpdateActionDelete {
		t.Fatal("watcher did not emit the expected deletion")
	}
	f.service.handleAuthUpdates(coreauth.WithSkipPersist(f.ctx), late)
	assertInventoryRuntimeRetired(t, f, auth.ID)
}

func TestGroupingConfigEventsWatcherRuntimeWindowIsClosed(t *testing.T) {
	for _, runtimeOK := range []bool{true, false} {
		t.Run(map[bool]string{true: "success", false: "failure"}[runtimeOK], func(t *testing.T) {
			f := newGroupingInventoryFixture(t, false)
			f.activate(t)
			auth := groupingInventoryCredential(t, f)
			w, queue := newConfigEventWatcher(t, f, f.service.applyWatcherConfigUpdate)
			f.service.handleAuthUpdates(coreauth.WithSkipPersist(f.ctx), receiveConfigEvents(t, queue, 1))
			proposed := f.service.cfg.CloneForRuntime()
			proposed.OpenAICompatibility[0].Disabled = true
			writeDeferredConfig(t, f, proposed)
			finish := blockConfigEventWatcherReload(t, f, w, runtimeOK)
			if f.service.grouping.healthy() {
				t.Fatal("ordinary watcher reopened authorization before runtime synchronization")
			}
			assertGroupingInventoryScheduling(t, f, auth, true)
			finish()
			if f.service.grouping.healthy() != runtimeOK {
				t.Fatal("watcher readiness did not reflect runtime publication success")
			}
			assertGroupingInventoryScheduling(t, f, auth, true)
			if runtimeOK {
				assertInventoryRuntimeRetired(t, f, auth.ID)
			}
			f.service.handleAuthUpdates(coreauth.WithSkipPersist(f.ctx), receiveConfigEvents(t, queue, 1))
			if f.service.grouping.healthy() != runtimeOK {
				t.Fatal("late deletion reopened a failed configuration transaction")
			}
		})
	}
}

func blockConfigEventWatcherReload(t *testing.T, f *groupingIntegrationFixture, w *watcher.Watcher, runtimeOK bool) func() {
	t.Helper()
	entered, release, finished := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	f.service.updateServerClientsContextFn = func(context.Context, *config.Config) bool {
		close(entered)
		<-release
		return runtimeOK
	}
	go func() {
		defer close(finished)
		w.ReloadConfigIfChanged()
	}()
	t.Cleanup(func() {
		unblock()
		<-finished
		f.service.updateServerClientsContextFn = nil
	})
	select {
	case <-entered:
	case <-finished:
		t.Fatal("watcher did not enter runtime publication")
	}
	return func() {
		unblock()
		<-finished
	}
}
