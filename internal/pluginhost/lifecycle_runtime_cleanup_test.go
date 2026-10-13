package pluginhost

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

func TestUnloadRuntimeOverrideOwnerCleansBeforeClosingCallbacks(t *testing.T) {
	for _, failFirst := range []bool{false, true} {
		t.Run(fmt.Sprintf("retry=%t", failFirst), func(t *testing.T) {
			client := &retryDeactivationClient{registration: validTestPlugin("alpha")}
			host := NewForTest(&countingPluginLoader{client: client})
			t.Cleanup(host.ShutdownAll)
			clearRequest, authID := deactivationRuntimeOverride(t, host)
			host.ApplyConfig(context.Background(), pluginHostConfig(makePluginDir(t, "alpha"), true, true))
			callbackCtx, instance := markRuntimeCleanupOwner(t, host, clearRequest)
			client.onDeactivate = runtimeCleanupCallback(t, host, callbackCtx, instance, clearRequest, failFirst)
			if unloaded := host.UnloadPlugin("alpha"); unloaded == failFirst {
				t.Fatalf("first unload=%t, want %t", unloaded, !failFirst)
			}
			if failFirst {
				if instance.closed.Load() || !host.pluginDeactivationPending("alpha") || host.PluginRegistered("alpha") {
					t.Fatal("failed unload cleanup lost the inactive, callable retry target")
				}
				if !host.UnloadPlugin("alpha") {
					t.Fatal("unload cleanup retry failed")
				}
			}
			assertRuntimeCleanupComplete(t, host, authID, instance)
		})
	}
}

func TestHotReloadRuntimeCleanupPreservesRollbackAndRetries(t *testing.T) {
	for _, failFirst := range []bool{false, true} {
		t.Run(fmt.Sprintf("retry=%t", failFirst), func(t *testing.T) {
			testHotReloadRuntimeCleanup(t, failFirst)
		})
	}
}

func TestRuntimeOverrideFirstUseCannotRaceRetirement(t *testing.T) {
	instance := &hostCallbackInstance{}
	if !instance.registerRuntimeOverrideUse() || !instance.needsRuntimeOverrideCleanup() {
		t.Fatal("an override started before retirement must require cleanup")
	}
	instance = &hostCallbackInstance{}
	if instance.needsRuntimeOverrideCleanup() || instance.registerRuntimeOverrideUse() {
		t.Fatal("retirement without owned overrides must reject first-use writes")
	}
}

func TestRuntimeOverrideAccessRestoredAfterReplacementRollback(t *testing.T) {
	client := &retryDeactivationClient{registration: validTestPlugin("alpha")}
	host := NewForTest(&countingPluginLoader{client: client})
	t.Cleanup(host.ShutdownAll)
	clearRequest, _ := deactivationRuntimeOverride(t, host)
	host.ApplyConfig(context.Background(), pluginHostConfig(makePluginDir(t, "alpha"), true, true))
	loaded := host.loaded["alpha"]
	if !host.cleanupRuntimeOverrideOwner(context.Background(), loaded) {
		t.Fatal("unused runtime override callback unexpectedly required cleanup")
	}
	ctx := withHostCallbackIdentity(context.Background(), "alpha", loaded.callbackInstance)
	if _, errSet := host.callFromPlugin(ctx, pluginabi.MethodHostAuthSetRuntimeOverride, clearRequest); errSet == nil {
		t.Fatal("retiring plugin accepted a first-use runtime write")
	}
	if loaded.callbackInstance.closed.Load() {
		t.Fatal("runtime write freeze closed unrelated plugin callbacks")
	}
	if _, _, ok := host.rollbackReplacement(loaded, defaultRuntimeItemConfig("alpha")); !ok {
		t.Fatal("replacement rollback failed")
	}
	markRuntimeCleanupOwner(t, host, clearRequest)
}

func testHotReloadRuntimeCleanup(t *testing.T, failFirst bool) {
	t.Helper()
	old := &retryDeactivationClient{registration: validTestPlugin("alpha")}
	newClient := func() pluginClient {
		return &retryDeactivationClient{registration: validTestPlugin("alpha")}
	}
	host := NewForTest(&sequencePluginLoader{clients: []pluginClient{old, newClient(), newClient()}})
	t.Cleanup(host.ShutdownAll)
	clearRequest, authID := deactivationRuntimeOverride(t, host)
	dir, paths := makeVersionedPluginDir(t, "alpha", "1.0.0")
	host.ApplyConfig(context.Background(), versionedPluginHostConfig(t, dir, "1.0.0"))
	callbackCtx, instance := markRuntimeCleanupOwner(t, host, clearRequest)
	_, operation, opened := host.httpOperations.open("alpha", instance, "", callbackCtx)
	if !opened {
		t.Fatal("failed to open old plugin HTTP operation")
	}
	old.onDeactivate = runtimeCleanupCallback(t, host, callbackCtx, instance, clearRequest, failFirst)
	paths["2.0.0"] = writeVersionedPluginFile(t, dir, "alpha", "2.0.0")
	host.ApplyConfig(context.Background(), versionedPluginHostConfig(t, dir, "2.0.0"))
	if failFirst {
		if !host.pluginIdentityCurrent("alpha", paths["1.0.0"], "1.0.0") || instance.closed.Load() || operation.ctx.Err() != nil {
			t.Fatal("failed runtime cleanup did not roll back to the callable old plugin")
		}
		host.ApplyConfig(context.Background(), versionedPluginHostConfig(t, dir, "2.0.0"))
	}
	if !host.pluginIdentityCurrent("alpha", paths["2.0.0"], "2.0.0") {
		t.Fatal("replacement plugin did not become active")
	}
	assertRuntimeCleanupComplete(t, host, authID, instance)
	if operation.ctx.Err() != context.Canceled {
		t.Fatal("retired plugin HTTP operation remained open after cleanup")
	}
}

func markRuntimeCleanupOwner(t *testing.T, host *Host, clearRequest []byte) (context.Context, *hostCallbackInstance) {
	t.Helper()
	instance := host.loaded["alpha"].callbackInstance
	ctx := withHostCallbackIdentity(context.Background(), "alpha", instance)
	var request pluginapi.HostAuthSetRuntimeOverrideRequest
	if errDecode := json.Unmarshal(clearRequest, &request); errDecode != nil {
		t.Fatal(errDecode)
	}
	disabled := true
	request.Clear, request.Disabled = nil, &disabled
	raw, errMarshal := json.Marshal(request)
	if errMarshal != nil {
		t.Fatal(errMarshal)
	}
	if _, errSet := host.callFromPlugin(ctx, pluginabi.MethodHostAuthSetRuntimeOverride, raw); errSet != nil {
		t.Fatal(errSet)
	}
	if instance.runtimeOverrideState.Load() != runtimeOverrideOwned {
		t.Fatal("runtime callback did not register lifecycle cleanup ownership")
	}
	return ctx, instance
}

func runtimeCleanupCallback(t *testing.T, host *Host, ctx context.Context, instance *hostCallbackInstance, request []byte, failFirst bool) func(int) error {
	t.Helper()
	return func(call int) error {
		if instance.closed.Load() || host.PluginRegistered("alpha") {
			return fmt.Errorf("cleanup must run with live callbacks and detached capabilities")
		}
		if failFirst && call == 1 {
			return fmt.Errorf("temporary cleanup failure")
		}
		_, errClear := host.callFromPlugin(ctx, pluginabi.MethodHostAuthSetRuntimeOverride, request)
		return errClear
	}
}

func assertRuntimeCleanupComplete(t *testing.T, host *Host, authID string, instance *hostCallbackInstance) {
	t.Helper()
	auth, ok := host.currentAuthManager().GetByID(authID)
	if !ok || !auth.RuntimeAuthOverride().Empty() {
		t.Fatal("plugin lifecycle left owned runtime overrides behind")
	}
	if !instance.closed.Load() {
		t.Fatal("retired plugin callbacks remained open after cleanup")
	}
}
