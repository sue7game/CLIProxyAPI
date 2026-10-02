package cliproxy

import (
	"sync"
	"sync/atomic"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/watcher"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/config"
)

func TestGroupingConfigEventsSupersededRegistrationCannotReclaimReusedID(t *testing.T) {
	f, first, secondID := newConfigEventDuplicateFixture(t)
	const secondModel = "inventory-second-model"
	applyInventoryConfig(t, f, func(cfg *config.Config) {
		cfg.OpenAICompatibility[1].Models = []config.OpenAICompatibilityModel{{Name: secondModel}}
	})
	_, queue := newConfigEventWatcher(t, f, nil)
	var late watcher.AuthUpdate
	for _, update := range receiveConfigEvents(t, queue, 2) {
		if update.Auth.Attributes["grouping_id"] == first.Attributes["grouping_id"] {
			late = update
		}
	}
	if late.Auth == nil {
		t.Fatal("watcher did not emit the first source")
	}
	finish := blockConfigEventRegistration(t, f, late)
	applyInventoryConfig(t, f, func(cfg *config.Config) { cfg.OpenAICompatibility[0].Disabled = true })
	current, ok := f.service.coreManager.GetByID(first.ID)
	if !ok || current.Attributes["grouping_id"] != secondID {
		t.Fatal("runtime ID was not reassigned while the old model task was paused")
	}
	finish()
	models := GlobalModelRegistry().GetModelsForClient(first.ID)
	if len(models) != 1 || models[0].ID != secondModel {
		t.Fatal("old registration task replaced the new runtime owner's model catalog")
	}
	assertConfigEventRuntimeMatchesConfig(t, f)
}

func blockConfigEventRegistration(t *testing.T, f *groupingIntegrationFixture, update watcher.AuthUpdate) func() {
	t.Helper()
	entered, release, finished := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	var calls atomic.Int32
	previousHook := modelRegistrationTaskHook
	modelRegistrationTaskHook = func() {
		if calls.Add(1) == 1 {
			close(entered)
			<-release
		}
	}
	go func() {
		defer close(finished)
		f.service.handleAuthUpdate(coreauth.WithSkipPersist(f.ctx), update)
	}()
	t.Cleanup(func() {
		unblock()
		<-finished
		modelRegistrationTaskHook = previousHook
	})
	select {
	case <-entered:
	case <-finished:
		t.Fatal("watcher did not enter its model registration phase")
	}
	return func() {
		unblock()
		<-finished
	}
}
