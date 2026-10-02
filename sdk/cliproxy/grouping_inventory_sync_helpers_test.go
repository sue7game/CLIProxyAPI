package cliproxy

import (
	"context"
	"sync"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/api/handlers/management"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/config"
)

func inventoryConfigRequest(f *groupingIntegrationFixture, mutate func(*config.Config)) management.ConfigApplyRequest {
	current := f.service.cfg.CloneForRuntime()
	proposed := current.CloneForRuntime()
	mutate(proposed)
	return management.ConfigApplyRequest{Current: current, Proposed: proposed, Operation: "inventory-sync-test"}
}

func applyInventoryConfig(t *testing.T, f *groupingIntegrationFixture, mutate func(*config.Config)) {
	t.Helper()
	if err := f.service.applyGroupingConfigMutation(f.ctx, inventoryConfigRequest(f, mutate)); err != nil {
		t.Fatal(err)
	}
}

func blockInventoryRuntime(t *testing.T, f *groupingIntegrationFixture, runtimeOK bool) func() error {
	t.Helper()
	entered, release, finished := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	f.service.updateServerClientsContextFn = func(context.Context, *config.Config) bool {
		close(entered)
		<-release
		return runtimeOK
	}
	request := inventoryConfigRequest(f, func(cfg *config.Config) { cfg.OpenAICompatibility[0].Disabled = true })
	var result error
	go func() {
		defer close(finished)
		result = f.service.applyGroupingConfigMutation(f.ctx, request)
	}()
	t.Cleanup(func() {
		unblock()
		<-finished
		f.service.updateServerClientsContextFn = nil
	})
	select {
	case <-entered:
	case <-finished:
		t.Fatalf("transaction stopped before its runtime callback: %v", result)
	}
	return func() error {
		unblock()
		<-finished
		return result
	}
}
