package pluginhost

import (
	"context"
	"fmt"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
)

func TestShutdownAllCleansOwnedRuntimeOverridesBeforeClosingCallbacks(t *testing.T) {
	for _, scenario := range []string{"success", "failure", "cancel"} {
		t.Run(scenario, func(t *testing.T) { testShutdownRuntimeCleanup(t, scenario) })
	}
}

func testShutdownRuntimeCleanup(t *testing.T, scenario string) {
	t.Helper()
	client := &retryDeactivationClient{registration: validTestPlugin("alpha")}
	beta := &retryDeactivationClient{registration: validTestPlugin("beta")}
	host := NewForTest(&sequencePluginLoader{clients: []pluginClient{client, beta}})
	t.Cleanup(host.ShutdownAll)
	clearRequest, authID := deactivationRuntimeOverride(t, host)
	host.ApplyConfig(context.Background(), &config.Config{Plugins: config.PluginsConfig{
		Enabled: true, Dir: makePluginDir(t, "alpha", "beta"), Configs: enabledPluginConfigs("alpha", "beta"),
	}})
	callbackCtx, instance := markRuntimeCleanupOwner(t, host, clearRequest)
	_, operation, opened := host.httpOperations.open("alpha", instance, "", callbackCtx)
	if !opened {
		t.Fatal("failed to open HTTP operation")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cleanup := runtimeCleanupCallback(t, host, callbackCtx, instance, clearRequest, false)
	client.onDeactivate = func(call int) error {
		if call == 1 && scenario == "failure" {
			return fmt.Errorf("temporary cleanup failure")
		}
		if call == 1 && scenario == "cancel" {
			cancel()
			return context.Canceled
		}
		return cleanup(call)
	}
	host.ShutdownAllContext(ctx)
	if host.PluginLoaded("beta") || host.PluginRegistered("alpha") || host.Snapshot().enabled {
		t.Fatal("shutdown did not detach capabilities and unrelated clients")
	}
	if scenario != "success" {
		assertShutdownCleanupPending(t, host, instance, operation.ctx)
		host.ShutdownAll()
	}
	assertRuntimeCleanupComplete(t, host, authID, instance)
	if host.PluginLoaded("alpha") || host.pluginDeactivationPending("alpha") || operation.ctx.Err() != context.Canceled {
		t.Fatal("successful shutdown did not release retained runtime state")
	}
}

func assertShutdownCleanupPending(t *testing.T, host *Host, instance *hostCallbackInstance, operation context.Context) {
	t.Helper()
	if !host.PluginLoaded("alpha") || !host.pluginDeactivationPending("alpha") {
		t.Fatal("failed cleanup lost the retry target")
	}
	if instance.closed.Load() || operation.Err() != nil {
		t.Fatal("failed cleanup closed callbacks needed by the retry")
	}
}
