package cliproxy

import (
	"context"
	"os"
	"sync"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/watcher"
	sdkauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/auth"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/config"
	"gopkg.in/yaml.v3"
)

func prepareDeferredOAuth(t *testing.T, f *groupingIntegrationFixture) *coreauth.Auth {
	t.Helper()
	record := oauthTestRecord("deferred.json")
	if err := f.service.grouping.prepareOAuthRecord(f.ctx, record); err != nil {
		t.Fatal(err)
	}
	return record
}

func saveDeferredOAuth(t *testing.T, f *groupingIntegrationFixture, record *coreauth.Auth) {
	t.Helper()
	if _, err := sdkauth.GetTokenStore().Save(coreauth.WithAuthCreationIntent(f.ctx), record); err != nil {
		t.Fatal(err)
	}
}

func queueDeferredConfig(t *testing.T, f *groupingIntegrationFixture, cfg *config.Config, synthesize bool) {
	t.Helper()
	if f.service.applyConfigUpdateWithAuthSynthesis(f.ctx, cfg, synthesize) {
		t.Fatal("pending OAuth accepted a configuration reload")
	}
	g := f.service.grouping
	g.mu.Lock()
	queued := g.deferredConfig
	g.mu.Unlock()
	if queued == nil || queued.synthesize != synthesize {
		t.Fatal("pending reload or synthesis mode was lost")
	}
}

func assertDeferredConfigState(t *testing.T, f *groupingIntegrationFixture, queued, healthy bool) {
	t.Helper()
	g := f.service.grouping
	g.mu.Lock()
	hasDeferred := g.deferredConfig != nil
	g.mu.Unlock()
	if hasDeferred != queued || g.healthy() != healthy {
		t.Fatalf("queued=%v healthy=%v, want queued=%v healthy=%v", hasDeferred, g.healthy(), queued, healthy)
	}
}

func writeDeferredConfig(t *testing.T, f *groupingIntegrationFixture, cfg *config.Config) {
	t.Helper()
	raw, err := yaml.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f.path, raw, 0600); err != nil {
		t.Fatal(err)
	}
}

func newDeferredConfigWatcher(t *testing.T, f *groupingIntegrationFixture, callback func(*config.Config)) *watcher.Watcher {
	t.Helper()
	w, err := watcher.NewWatcher(f.path, f.authDir, callback)
	if err != nil {
		t.Fatal(err)
	}
	w.SetConfig(f.service.cfg)
	t.Cleanup(func() {
		if err := w.Stop(); err != nil {
			t.Error(err)
		}
	})
	return w
}

func canceledDeferredContext() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}

func blockDeferredFinalization(t *testing.T, f *groupingIntegrationFixture, ctx context.Context, record *coreauth.Auth) func() error {
	t.Helper()
	entered, release, finished := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	f.service.updateServerClientsContextFn = func(context.Context, *config.Config) bool {
		close(entered)
		<-release
		return true
	}
	var result error
	go func() {
		defer close(finished)
		result = f.service.grouping.finalizeOAuthRecord(ctx, record)
	}()
	t.Cleanup(func() {
		unblock()
		<-finished
		f.service.updateServerClientsContextFn = nil
	})
	select {
	case <-entered:
	case <-finished:
		t.Fatalf("finalization stopped before deferred runtime publication: %v", result)
	}
	return func() error {
		unblock()
		<-finished
		return result
	}
}
