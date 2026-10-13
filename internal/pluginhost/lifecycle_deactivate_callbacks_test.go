package pluginhost

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

func TestHostDeactivationClearsRuntimeOverridesBeforeClosingCallbacks(t *testing.T) {
	for _, retry := range []bool{false, true} {
		t.Run(fmt.Sprintf("retry=%v", retry), func(t *testing.T) {
			client := &retryDeactivationClient{registration: validTestPlugin("alpha")}
			host := NewForTest(&countingPluginLoader{client: client})
			t.Cleanup(host.ShutdownAll)
			clearRequest, authID := deactivationRuntimeOverride(t, host)
			dir := makePluginDir(t, "alpha")
			host.ApplyConfig(context.Background(), pluginHostConfig(dir, true, true))
			instance := host.loaded["alpha"].callbackInstance
			callbackCtx := withHostCallbackIdentity(context.Background(), "alpha", instance)
			_, operation, opened := host.httpOperations.open("alpha", instance, "", callbackCtx)
			if !opened {
				t.Fatal("failed to open operation before deactivation")
			}
			client.onDeactivate = func(call int) error {
				if instance.closed.Load() || operation.ctx.Err() != nil || host.PluginRegistered("alpha") {
					return fmt.Errorf("deactivation ran with closed callbacks or active capabilities")
				}
				if retry && call == 1 {
					return fmt.Errorf("temporary cleanup failure")
				}
				_, errClear := host.callFromPlugin(callbackCtx, pluginabi.MethodHostAuthSetRuntimeOverride, clearRequest)
				return errClear
			}
			host.ApplyConfig(context.Background(), pluginHostConfig(dir, true, false))
			if retry {
				if !host.pluginDeactivationPending("alpha") || instance.closed.Load() || host.PluginRegistered("alpha") {
					t.Fatal("failed cleanup did not retain an inactive, callable pending plugin")
				}
				host.ApplyConfig(context.Background(), pluginHostConfig(dir, true, false))
			}
			auth, ok := host.currentAuthManager().GetByID(authID)
			if !ok || !auth.RuntimeAuthOverride().Empty() {
				t.Fatal("deactivation did not clear runtime cooldown and proxy overrides")
			}
			if host.PluginLoaded("alpha") || host.pluginDeactivationPending("alpha") {
				t.Fatal("successfully deactivated plugin remained loaded or pending")
			}
			if !instance.closed.Load() || operation.ctx.Err() != context.Canceled {
				t.Fatal("successful deactivation did not close callback and HTTP resources")
			}
			if _, errLate := host.callFromPlugin(callbackCtx, pluginabi.MethodHostAuthSetRuntimeOverride, clearRequest); errLate == nil {
				t.Fatal("closed plugin instance accepted a late runtime override callback")
			}
		})
	}
}

func deactivationRuntimeOverride(t *testing.T, host *Host) ([]byte, string) {
	t.Helper()
	manager := coreauth.NewManager(nil, nil, nil)
	host.SetAuthManager(manager)
	auth, errRegister := manager.Register(context.Background(), &coreauth.Auth{
		ID: "guard-runtime", Provider: "demo", Status: coreauth.StatusActive,
		Attributes: map[string]string{"runtime_only": "true"},
	})
	if errRegister != nil {
		t.Fatalf("register runtime auth: %v", errRegister)
	}
	disabled, proxy := true, "direct"
	setRequest, errMarshal := json.Marshal(pluginapi.HostAuthSetRuntimeOverrideRequest{
		AuthIndex: auth.Index, Disabled: &disabled, ProxyURL: &proxy,
	})
	if errMarshal != nil {
		t.Fatalf("marshal runtime override: %v", errMarshal)
	}
	if _, errSet := host.callFromPlugin(context.Background(), pluginabi.MethodHostAuthSetRuntimeOverride, setRequest); errSet != nil {
		t.Fatalf("set runtime override: %v", errSet)
	}
	clearRequest, errMarshal := json.Marshal(pluginapi.HostAuthSetRuntimeOverrideRequest{
		AuthIndex: auth.Index,
		Clear: []pluginapi.HostAuthRuntimeOverrideField{
			pluginapi.HostAuthRuntimeOverrideDisabled, pluginapi.HostAuthRuntimeOverrideProxyURL,
		},
	})
	if errMarshal != nil {
		t.Fatalf("marshal runtime override clear: %v", errMarshal)
	}
	return clearRequest, auth.ID
}
