package cliproxy

import (
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/watcher"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/config"
)

func newConfigEventWatcher(t *testing.T, f *groupingIntegrationFixture, callback func(*config.Config)) (*watcher.Watcher, <-chan watcher.AuthUpdate) {
	t.Helper()
	w := newDeferredConfigWatcher(t, f, callback)
	queue := make(chan watcher.AuthUpdate, 32)
	w.SetAuthUpdateQueue(queue)
	w.ReloadConfigIfChanged()
	return w, queue
}

func receiveConfigEvents(t *testing.T, queue <-chan watcher.AuthUpdate, count int) []watcher.AuthUpdate {
	t.Helper()
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	updates := make([]watcher.AuthUpdate, 0, count)
	for len(updates) < count {
		select {
		case update := <-queue:
			if update.ID == "" || update.Revision() == 0 {
				t.Fatal("watcher emitted an unversioned source update")
			}
			updates = append(updates, update)
		case <-deadline.C:
			t.Fatalf("received %d config events, want %d", len(updates), count)
		}
	}
	return updates
}

func newConfigEventDuplicateFixture(t *testing.T) (*groupingIntegrationFixture, *coreauth.Auth, string) {
	t.Helper()
	f := newGroupingInventoryFixture(t, false)
	first := groupingInventoryCredential(t, f)
	applyInventoryConfig(t, f, func(cfg *config.Config) {
		duplicate := cfg.CloneForRuntime().OpenAICompatibility[0]
		duplicate.APIKeyEntries[0].GroupingID = ""
		cfg.OpenAICompatibility = append(cfg.OpenAICompatibility, duplicate)
	})
	secondID := f.service.cfg.OpenAICompatibility[1].APIKeyEntries[0].GroupingID
	bindInventoryDuplicateGroups(t, f, first.Attributes["grouping_id"], secondID)
	f.activate(t)
	return f, first, secondID
}

func assertConfigEventRuntimeMatchesConfig(t *testing.T, f *groupingIntegrationFixture) {
	t.Helper()
	auths, err := synthesizeConfigAPIKeyAuths(f.service.cfg)
	if err != nil {
		t.Fatal(err)
	}
	want := make(map[string]bool)
	for _, expected := range auths {
		if !coreauth.IsConfigAPIKeyAuth(expected) {
			continue
		}
		want[expected.Attributes["grouping_id"]] = true
		actual, ok := f.service.coreManager.GetByID(expected.ID)
		if !ok || actual.Provider != expected.Provider || actual.Attributes["grouping_id"] != expected.Attributes["grouping_id"] ||
			actual.Attributes["api_key"] != expected.Attributes["api_key"] || actual.Attributes["config_index"] != expected.Attributes["config_index"] {
			t.Fatal("runtime ID no longer belongs to the accepted config source")
		}
		if len(GlobalModelRegistry().GetModelsForClient(expected.ID)) == 0 {
			t.Fatal("accepted config source has no runtime models")
		}
	}
	assertInventoryActiveSourceSet(t, f, want)
}
